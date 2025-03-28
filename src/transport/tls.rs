use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::{ClientConfig, ServerConfig};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use std::sync::Arc;

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

pub(crate) async fn connect(host: &Host, port: Port) -> ZmqResult<(FramedIo, Endpoint)> {
    let raw_socket = TcpStream::connect((host.to_string().as_str(), port)).await?;
    // For some reason set_nodelay doesn't work on windows. See
    // https://github.com/zeromq/zmq.rs/issues/148 for details
    #[cfg(not(windows))]
    raw_socket.set_nodelay(true)?;
    let peer_addr = raw_socket.peer_addr()?;

    let cert_manager = cert_manager::CertManager::from_folder(&*CERT_FOLDER).unwrap();
    let ca = cert_manager.get_root_cert_store().unwrap();

    let config = ClientConfig::builder()
        .with_root_certificates(ca)
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));

    let raw_socket = connector
        .connect(host.to_string().try_into().unwrap(), raw_socket)
        .await?;

    Ok((make_framed(raw_socket), Endpoint::from_tls_addr(peer_addr)))
}

pub(crate) async fn begin_accept<T>(
    mut host: Host,
    port: Port,
    cback: impl Fn(ZmqResult<(FramedIo, Endpoint)>) -> T + Send + 'static,
) -> ZmqResult<(Endpoint, AcceptStopHandle)>
where
    T: std::future::Future<Output = ()> + Send + 'static,
{
    let listener = TcpListener::bind((host.to_string().as_str(), port)).await?;
    let resolved_addr = listener.local_addr()?;
    let (stop_channel, stop_callback) = futures::channel::oneshot::channel::<()>();
    let host_copy = host.clone();
    let task_handle = async_rt::task::spawn(async move {
        let mut stop_callback = stop_callback.fuse();
        loop {
            select! {
                incoming = listener.accept().fuse() => {
                    let maybe_accepted: Result<_, _> = match incoming
                        .and_then(|(raw_socket, remote_addr)| {
                            raw_socket
                                .set_nodelay(true)
                                .map(|_| (raw_socket, remote_addr))
                        }) {
                            Ok((raw_socket, remote_addr)) => {
                                Ok(accept(raw_socket, remote_addr, &host_copy).await)
                        }
                            Err(err) => Err(err.into()),
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

async fn accept(
    raw_socket: TcpStream,
    remote_addr: std::net::SocketAddr,
    host: &Host,
) -> (FramedIo, Endpoint) {
    let mut cert_manager = cert_manager::CertManager::from_folder(&*CERT_FOLDER).unwrap();
    let (certs, key) = cert_manager
        .create_certificate_or_get(host.to_string().as_str())
        .unwrap();
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));

    let raw_socket = acceptor.accept(raw_socket).await.unwrap();
    (
        make_framed(raw_socket),
        Endpoint::from_tcp_addr(remote_addr),
    )
}
