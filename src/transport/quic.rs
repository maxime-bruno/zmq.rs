use quiche::{Config, ConnectionId};

use tokio::net::UdpSocket;
use tokio::sync::RwLock;

use std::sync::Mutex;

use core::pin::Pin;
use core::task::{Context, Poll};
// use futures::Future;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::ReadBuf;

// #[cfg(any(feature = "async-std-runtime", feature = "async-dispatcher-runtime"))]
// use async_std::net::{TcpListener, TcpStream};

use super::AcceptStopHandle;
use super::{make_framed, CERT_FOLDER};
use crate::async_rt;
use crate::codec::FramedIo;
use crate::endpoint::{Endpoint, Host, Port};
use crate::task_handle::TaskHandle;
use crate::ZmqResult;

use futures::{select, FutureExt};

use lazy_static::lazy_static;

lazy_static! {
    static ref SCID: RwLock<HashSet<ConnectionId<'static>>> = RwLock::new(HashSet::new());
}

static MAX_STREAM: u64 = 1_000;
static MAX_DATA_STREAM: u64 = 65_536;

pub(crate) async fn connect(host: &Host, port: Port) -> ZmqResult<(FramedIo, Endpoint)> {
    let connection = Connection::connect(host, port).await?;
    let peer = connection.peer_addr();
    log::debug!("Connection finished");
    Ok((make_framed(connection), Endpoint::from_quic_addr(peer)))
}

pub(crate) async fn begin_accept<T>(
    mut host: Host,
    port: Port,
    cback: impl Fn(ZmqResult<(FramedIo, Endpoint)>) -> T + Send + 'static,
) -> ZmqResult<(Endpoint, AcceptStopHandle)>
where
    T: std::future::Future<Output = ()> + Send + 'static,
{
    let listener = Arc::new(tokio::net::UdpSocket::bind((host.to_string().as_str(), port)).await?);
    let mut peers = HashSet::new();
    let resolved_addr = listener.local_addr()?;
    log::debug!("listenning on {}", resolved_addr);
    let (stop_channel, stop_callback) = futures::channel::oneshot::channel::<()>();
    let host_copy = host.clone();
    let task_handle = async_rt::task::spawn(async move {
        let mut stop_callback = stop_callback.fuse();
        loop {
            let mut buf = vec![0; 65_536]; //Vec::with_capacity(65_536);
            match listener.peek_sender().await {
                Ok(addr) if peers.contains(&addr) => {
                    tokio::task::yield_now().await;
                    continue;
                }
                Ok(_) => (),
                Err(e) => {
                    log::error!("Error while peeking at the connection {e}");
                    continue;
                }
            }
            select! {
                incoming = listener.recv_from(&mut buf).fuse() => {
                    let maybe_accepted: Result<_, _> = match incoming
                        {

                            Ok((size, remote_addr)) => {
                                peers.insert(remote_addr);
                                log::debug!("Received a first message of {size}bytes from {remote_addr}");
                                let connection = Connection::accept(&host_copy, Arc::clone(&listener), remote_addr, buf, size).await?;
                                let peer = connection.peer_addr();
                                log::debug!("Connection accepted");
                                Ok((make_framed(connection), Endpoint::from_quic_addr(peer)))
                        }
                            Err(err) => {
                                log::debug!("Error : {err}");
                                Err(err.into())
                            }
                    };
                    async_rt::task::spawn(cback(maybe_accepted));
                }
                _ = stop_callback => {
                    break
                }
            }
        }
        Ok(())
    });
    debug_assert_ne!(resolved_addr.port(), 0);
    let port = resolved_addr.port();
    let resolved_host: Host = resolved_addr.ip().into();
    if let Host::Ipv4(ip) = host {
        debug_assert_eq!(ip, resolved_addr.ip());
        host = resolved_host;
    } else if let Host::Ipv6(ip) = host {
        debug_assert_eq!(ip, resolved_addr.ip());
        host = resolved_host;
    }
    Ok((
        Endpoint::Tls(host, port),
        AcceptStopHandle(TaskHandle::new(stop_channel, task_handle)),
    ))
}

struct Connection {
    udp_socket: Arc<tokio::net::UdpSocket>,
    quic_socket: Arc<Mutex<quiche::Connection>>,
    next_id: u64,
    send_handle: tokio::task::JoinHandle<Result<(), std::io::Error>>,
    recv_handle: tokio::task::JoinHandle<Result<(), std::io::Error>>,
    peer: SocketAddr,
    waker: Arc<Mutex<Option<std::task::Waker>>>,
}

impl Connection {
    async fn connect(host: &Host, port: Port) -> ZmqResult<Self> {
        let udp_socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
        udp_socket
            .connect((host.to_string().as_str(), port))
            .await?;

        log::debug!("local: {}", udp_socket.local_addr()?);
        log::debug!("peer: {}", udp_socket.peer_addr()?);

        let peer = udp_socket.peer_addr()?;

        let udp_socket = Arc::new(udp_socket);

        let mut config = Config::new(quiche::PROTOCOL_VERSION).unwrap();
        config
            .load_verify_locations_from_file(
                CERT_FOLDER
                    .join("ca.pem")
                    .as_os_str()
                    .to_str()
                    .expect("Invalid certificate folder name"),
            )
            .unwrap();
        // config.verify_peer(false);
        config.set_application_protos(&[b"zeromq"]).unwrap();
        config.log_keys();
        config.set_initial_max_streams_bidi(MAX_STREAM);
        config.set_initial_max_stream_data_bidi_local(MAX_DATA_STREAM);
        config.set_initial_max_stream_data_bidi_remote(MAX_DATA_STREAM);
        config.set_initial_max_data(MAX_DATA_STREAM * MAX_STREAM);

        log::debug!("Config created");

        let mut id = ConnectionId::from_vec(rand::random_iter().take(20).collect());
        log::debug!("First scid: {id:?}");
        let existing_id = SCID.read().await;
        log::debug!("SCID lock acquired");
        while existing_id.contains(&id) {
            log::debug!("refused scid {id:?}");
            id = ConnectionId::from_vec(rand::random_iter().take(20).collect());
        }
        drop(existing_id);
        SCID.write().await.insert(id.clone());

        log::debug!("SCID: {id:?}");

        let tmp_folder = tempfile::tempdir().unwrap().into_path();
        let file = std::fs::File::create(tmp_folder.join(format!("{}.log", peer))).unwrap();

        let mut quic = quiche::connect(
            Some(host.to_string().as_str()),
            &id,
            udp_socket.local_addr()?,
            udp_socket.peer_addr()?,
            &mut config,
        )
        .unwrap();
        quic.set_keylog(Box::new(file));

        let quic_socket = Arc::new(Mutex::new(quic));

        let quic_socket_copy = Arc::clone(&quic_socket);
        let udp_socket_copy = Arc::clone(&udp_socket);
        let send_handle = tokio::task::spawn(async move {
            Self::forward_to_udp(quic_socket_copy, udp_socket_copy).await
        });
        let quic_socket_copy = Arc::clone(&quic_socket);
        let udp_socket_copy = Arc::clone(&udp_socket);
        let waker = Arc::new(Mutex::new(None));
        let waker_copy = Arc::clone(&waker);
        let recv_handle = tokio::task::spawn(async move {
            Self::forward_from_udp(quic_socket_copy, udp_socket_copy, waker_copy, peer).await
        });

        while !quic_socket.lock().unwrap().is_established()
            && !quic_socket.lock().unwrap().is_closed()
        {
            if let Some(err) = quic_socket.lock().unwrap().local_error() {
                log::error!("Error during connection establishement: {err:?}");
                panic!();
            }
            log::debug!(
                "Waiting for the establishement of the connection between {} and {}",
                udp_socket.local_addr()?,
                peer,
            );
            tokio::task::yield_now().await;
        }

        if quic_socket.lock().unwrap().is_closed() {
            panic!("Connection closed before opening")
        }

        log::debug!("Quic connection established");

        Ok(Self {
            udp_socket,
            quic_socket,
            next_id: 0,
            send_handle,
            recv_handle,
            peer,
            waker,
        })
    }

    async fn accept(
        host: &Host,
        udp_socket: Arc<tokio::net::UdpSocket>,
        peer: SocketAddr,
        mut buf: Vec<u8>,
        buf_size: usize,
    ) -> ZmqResult<Self> {
        log::debug!("local: {}", udp_socket.local_addr()?);
        log::debug!("peer: {}", peer);

        let host = host.to_string();

        let mut ca = cert_manager::CertManager::from_folder(&*CERT_FOLDER).unwrap();
        let tmp_folder = tempfile::tempdir().unwrap().into_path();
        ca.save_certificate(host.as_str(), &tmp_folder).unwrap();

        let mut config = Config::new(quiche::PROTOCOL_VERSION).unwrap();
        config
            .load_verify_locations_from_file(
                CERT_FOLDER
                    .join("ca.pem")
                    .as_os_str()
                    .to_str()
                    .expect("Invalid certificate folder name"),
            )
            .unwrap();
        config
            .load_priv_key_from_pem_file(
                tmp_folder
                    .join(format!("{}.key", &host))
                    .as_os_str()
                    .to_str()
                    .unwrap(),
            )
            .unwrap();
        config
            .load_cert_chain_from_pem_file(
                tmp_folder
                    .join(format!("{}.pem", &host))
                    .as_os_str()
                    .to_str()
                    .unwrap(),
            )
            .unwrap();
        config.set_application_protos(&[b"zeromq"]).unwrap();
        config.set_initial_max_streams_bidi(MAX_STREAM);
        config.set_initial_max_stream_data_bidi_local(MAX_DATA_STREAM);
        config.set_initial_max_stream_data_bidi_remote(MAX_DATA_STREAM);
        config.set_initial_max_data(MAX_DATA_STREAM * MAX_STREAM);

        log::debug!("Config created");

        let mut id = ConnectionId::from_vec(rand::random_iter().take(20).collect());
        log::debug!("First scid: {id:?}");
        let existing_id = SCID.read().await;
        log::debug!("SCID lock acquired");
        while existing_id.contains(&id) {
            log::debug!("refused scid {id:?}");
            id = ConnectionId::from_vec(rand::random_iter().take(20).collect());
        }
        drop(existing_id);
        SCID.write().await.insert(id.clone());

        log::debug!("SCID: {id:?}");

        let mut quic_socket =
            quiche::accept(&id, None, udp_socket.local_addr()?, peer, &mut config).unwrap();

        log::debug!("Quic socket created");

        let recv_info = quiche::RecvInfo {
            from: peer,
            to: udp_socket.local_addr()?,
        };
        match quic_socket.recv(&mut buf[..buf_size], recv_info) {
            Ok(read) => {
                log::debug!(
                    "Treated the first message ({read} bytes) from {} to the server",
                    peer
                );
            }

            Err(e) => {
                // An error occurred, handle it.
                log::error!("Error {e}");
                return Err(std::io::Error::other(e).into());
            }
        };

        log::debug!("Socket finished");

        let quic_socket = Arc::new(Mutex::new(quic_socket));

        let quic_socket_copy = Arc::clone(&quic_socket);
        let udp_socket_copy = Arc::clone(&udp_socket);
        let send_handle = tokio::task::spawn(async move {
            Self::forward_to_udp(quic_socket_copy, udp_socket_copy).await
        });
        let quic_socket_copy = Arc::clone(&quic_socket);
        let udp_socket_copy = Arc::clone(&udp_socket);
        let waker = Arc::new(Mutex::new(None));
        let waker_copy = Arc::clone(&waker);
        let recv_handle = tokio::task::spawn(async move {
            Self::forward_from_udp(quic_socket_copy, udp_socket_copy, waker_copy, peer).await
        });

        log::debug!("Handler created");

        while !quic_socket.lock().unwrap().is_established()
            && !quic_socket.lock().unwrap().is_closed()
        {
            if let Some(err) = quic_socket.lock().unwrap().local_error() {
                log::error!("Error during connection establishement: {err:?}");
                panic!();
            }
            log::debug!(
                "Waiting for the establishement of the connection between {} and {}",
                udp_socket.local_addr()?,
                peer,
            );
            tokio::task::yield_now().await;
        }

        if quic_socket.lock().unwrap().is_closed() {
            panic!("Connection closed before opening")
        }

        log::debug!("Quic connection established");

        Ok(Self {
            udp_socket,
            quic_socket,
            next_id: 1,
            send_handle,
            recv_handle,
            peer,
            waker,
        })
    }

    fn peer_addr(&self) -> SocketAddr {
        self.peer
    }

    async fn forward_to_udp(
        quic_socket: Arc<Mutex<quiche::Connection>>,
        udp_socket: Arc<UdpSocket>,
    ) -> Result<(), std::io::Error> {
        let mut buffer = [0; 65_536]; //Vec::with_capacity(65_536);
        loop {
            let next = {
                let mut quic_socket = quic_socket.lock().unwrap();
                quic_socket.send(&mut buffer)
            };
            match next {
                Ok((len, info)) => {
                    log::debug!("forwarding packet to udp");
                    udp_socket.send_to(&buffer[..len], info.to).await?;
                    log::debug!(
                        "Sent {len} bytes on the quic connection between {} and {}",
                        udp_socket.local_addr()?,
                        info.to
                    );
                    // buffer.clear()
                }
                Err(quiche::Error::Done) => {
                    log::debug!(
                        "Nothing to write on the quic connection from {}",
                        udp_socket.local_addr()?,
                    );
                    tokio::task::yield_now().await;
                }
                Err(e) => {
                    log::error!(
                        "Error on the quic connection from {}: {}",
                        udp_socket.local_addr()?,
                        e
                    );
                }
            }
        }
    }

    async fn forward_from_udp(
        quic_socket: Arc<Mutex<quiche::Connection>>,
        udp_socket: Arc<UdpSocket>,
        waker: Arc<Mutex<Option<std::task::Waker>>>,
        peer: SocketAddr,
    ) -> Result<(), std::io::Error> {
        let mut buffer = [0; 65_536]; //Vec::with_capacity(65_536);
        loop {
            match udp_socket.peek_sender().await {
                Ok(addr) if addr != peer => {
                    log::debug!("peep on a packet not from me {addr} ({peer})");
                    continue;
                }
                Ok(_) => (),
                Err(e) => {
                    log::error!("Error while peeking on the udp connection: {e}");
                    continue;
                }
            }
            match udp_socket.recv_from(&mut buffer).await {
                Ok((len, addr)) => {
                    assert_eq!(addr, peer);
                    log::debug!("forwarding packet from udp");
                    let recv_info = quiche::RecvInfo {
                        from: addr,
                        to: udp_socket.local_addr()?,
                    };
                    match quic_socket
                        .lock()
                        .unwrap()
                        .recv(&mut buffer[..len], recv_info)
                    {
                        Ok(len) => {
                            log::debug!(
                                "Received {len} bytes on the quic connection between {} and {}",
                                udp_socket.local_addr()?,
                                peer
                            );
                            let waker = waker.lock().unwrap();
                            if let Some(ref waker) = *waker {
                                waker.wake_by_ref();
                            }
                            // buffer.clear()
                        }

                        Err(e) => {
                            log::error!(
                                "Error on the quic connection between {} and {}: {}",
                                udp_socket.local_addr()?,
                                peer,
                                e
                            );
                        }
                    }
                }
                Err(e) => {
                    log::error!(
                        "Error on the quic connection between {} and {}: {}",
                        udp_socket.local_addr()?,
                        peer,
                        e
                    );
                }
            }
        }
    }
}

impl tokio::io::AsyncRead for Connection {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        log::debug!("trying to read");
        let quic_socket = Arc::clone(&self.quic_socket);
        let mut quic_socket = quic_socket
            .lock()
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "Mutex poisoned"))?;
        log::debug!("acquired lock");
        match quic_socket.stream_readable_next() {
            Some(stream_id) => {
                let mut waker = self.waker.lock().map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::Other, "Mutex poisoned")
                })?;
                *waker = None;
                log::debug!("Reading data from stream {stream_id}");
                let mut buffer = buf.initialize_unfilled();
                match quic_socket.stream_recv(stream_id, &mut buffer) {
                    Ok((len, _done)) => {
                        log::debug!("read \"{}\"", String::from_utf8_lossy(&buffer[..len]));
                        buf.advance(len);
                        Poll::Ready(Ok(()))
                    }
                    Err(e) => Poll::Ready(Err(std::io::Error::other(e))),
                }
            }
            None => {
                log::debug!("No data to read");
                let mut waker = self.waker.lock().map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::Other, "Mutex poisoned")
                })?;
                match waker.as_mut() {
                    Some(waker) => {
                        if !waker.will_wake(cx.waker()) {
                            waker.clone_from(cx.waker());
                        }
                    }
                    None => *waker = Some(cx.waker().clone()),
                }
                Poll::Pending
            }
        }
    }
}

impl tokio::io::AsyncWrite for Connection {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        log::debug!("Trying to send: \"{}\"", String::from_utf8_lossy(buf));
        let quic_socket = Arc::clone(&self.quic_socket);
        let mut quic_socket = quic_socket.lock().unwrap();
        log::debug!("Acquired lock");

        let mut stream_id = 0;
        let mut chosed = false;

        for stream in quic_socket.writable() {
            if let Ok(true) = quic_socket.stream_writable(stream, buf.len()) {
                stream_id = stream;
                chosed = true;
                break;
            }
        }

        if !chosed {
            log::debug!("No stream avalaible creating a new one");
            log::debug!(
                "We can still create {} stream",
                quic_socket.peer_streams_left_bidi()
            );
            stream_id = self.next_id;
            self.next_id += 4;
            if let Err(e) = quic_socket.stream_priority(stream_id, 127, false) {
                return Poll::Ready(Err(std::io::Error::other(e)));
            } else {
                log::debug!("Stream {stream_id} opened with priority 127");
                match quic_socket.stream_capacity(stream_id) {
                    Ok(size) => log::debug!("We can still write {size} bytes on the stream"),
                    Err(e) => log::error!("Could not retrieve the size {e}"),
                }
            }
        }
        log::debug!("Writting in stream {stream_id}");

        Poll::Ready(match quic_socket.stream_send(stream_id, buf, false) {
            Ok(v) => {
                log::debug!(
                    "Successfully send {v} bytes of the {} bytes of buffer \"{}\"",
                    buf.len(),
                    String::from_utf8_lossy(buf)
                );
                Ok(v)
            }
            Err(e) => {
                log::error!(
                    "Failled to send the {} bytes of buffer \"{}\" with error {e}",
                    buf.len(),
                    String::from_utf8_lossy(buf)
                );
                Err(std::io::Error::other(e))
            }
        })
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        todo!()
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.send_handle.abort();
        self.recv_handle.abort();
    }
}
