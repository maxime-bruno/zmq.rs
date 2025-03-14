#[cfg(all(feature = "ipc-transport", target_family = "unix"))]
mod ipc;
#[cfg(all(feature = "quic-transport", feature = "tokio-runtime"))]
mod quic;
#[cfg(feature = "tcp-transport")]
mod tcp;
#[cfg(all(feature = "tls-transport", feature = "tokio-runtime"))]
mod tls;

use crate::codec::FramedIo;
use crate::endpoint::Endpoint;
use crate::task_handle::TaskHandle;
use crate::ZmqResult;

macro_rules! do_if_enabled {
    ($feature:literal, $body:expr) => {{
        #[cfg(feature = $feature)]
        {
            $body
        }

        #[cfg(not(feature = $feature))]
        panic!("feature \"{}\" is not enabled", $feature)
    }};
}

/// Connectes to the given endpoint
///
/// # Panics
/// Panics if the requested endpoint uses a transport type that isn't enabled
pub(crate) async fn connect(endpoint: &Endpoint) -> ZmqResult<(FramedIo, Endpoint)> {
    match endpoint {
        Endpoint::Tcp(_host, _port) => {
            do_if_enabled!("tcp-transport", tcp::connect(_host, *_port).await)
        }
        Endpoint::Tls(_host, _port) => {
            do_if_enabled!("tls-transport", tls::connect(_host, *_port).await)
        }
        Endpoint::Quic(_host, _port) => {
            do_if_enabled!("quic-transport", quic::connect(_host, *_port).await)
        }
        Endpoint::Ipc(_path) => {
            #[cfg(all(feature = "ipc-transport", target_family = "unix"))]
            {
                if let Some(path) = _path {
                    ipc::connect(path).await
                } else {
                    Err(crate::error::ZmqError::Socket(
                        "Cannot connect to an unnamed ipc socket",
                    ))
                }
            }
            #[cfg(not(all(feature = "ipc-transport", target_family = "unix")))]
            panic!("IPC transport is not available on this platform")
        }
    }
}

pub struct AcceptStopHandle(pub(crate) TaskHandle<()>);

/// Spawns an async task that listens for connections at the provided endpoint.
///
/// `cback` will be invoked when a connection is accepted. If the result was
/// `Ok`, it will receive a tuple containing the framed raw socket, along with
/// the endpoint of the remote connection accepted.
///
/// Returns a `ZmqResult`, which when Ok is a tuple of the resolved bound
/// endpoint, as well as a channel to stop the async accept task
///
/// # Panics
/// Panics if the requested endpoint uses a transport type that isn't enabled
pub(crate) async fn begin_accept<T>(
    endpoint: Endpoint,
    cback: impl Fn(ZmqResult<(FramedIo, Endpoint)>) -> T + Send + 'static,
) -> ZmqResult<(Endpoint, AcceptStopHandle)>
where
    T: std::future::Future<Output = ()> + Send + 'static,
{
    let _cback = cback;
    match endpoint {
        Endpoint::Tcp(_host, _port) => do_if_enabled!(
            "tcp-transport",
            tcp::begin_accept(_host, _port, _cback).await
        ),
        Endpoint::Tls(_host, _port) => do_if_enabled!(
            "tls-transport",
            tls::begin_accept(_host, _port, _cback).await
        ),
        Endpoint::Quic(_host, _port) => do_if_enabled!(
            "quic-transport",
            quic::begin_accept(_host, _port, _cback).await
        ),
        Endpoint::Ipc(_path) => {
            #[cfg(all(feature = "ipc-transport", target_family = "unix"))]
            {
                if let Some(path) = _path {
                    ipc::begin_accept(&path, _cback).await
                } else {
                    Err(crate::error::ZmqError::Socket(
                        "Cannot begin accepting peers at an unnamed ipc socket",
                    ))
                }
            }
            #[cfg(not(all(feature = "ipc-transport", target_family = "unix")))]
            panic!("IPC transport is not available on this platform")
        }
    }
}

#[allow(unused)]
#[cfg(feature = "tokio-runtime")]
fn make_framed<T>(stream: T) -> FramedIo
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Sync + 'static,
{
    use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};
    let (read, write) = tokio::io::split(stream);
    FramedIo::new(Box::new(read.compat()), Box::new(write.compat_write()))
}

#[allow(unused)]
#[cfg(any(feature = "async-std-runtime", feature = "async-dispatcher-runtime"))]
fn make_framed<T>(stream: T) -> FramedIo
where
    T: futures::AsyncRead + futures::AsyncWrite + Send + Sync + 'static,
{
    use futures::AsyncReadExt;
    let (read, write) = stream.split();
    FramedIo::new(Box::new(read), Box::new(write))
}

#[cfg(any(feature = "quic-transport", feature = "tls-transport"))]
static CERT_FOLDER: CertFolder = CertFolder::new();

#[cfg(any(feature = "quic-transport", feature = "tls-transport"))]
pub(crate) fn set_cert_folder<P: AsRef<std::path::Path>>(
    folder: P,
) -> Result<(), std::path::PathBuf> {
    CERT_FOLDER.init(folder)
}

#[cfg(any(feature = "quic-transport", feature = "tls-transport"))]
struct CertFolder {
    folder: std::sync::OnceLock<std::path::PathBuf>,
}
#[cfg(any(feature = "quic-transport", feature = "tls-transport"))]
impl CertFolder {
    pub const fn new() -> Self {
        Self {
            folder: std::sync::OnceLock::new(),
        }
    }

    fn init_ca<P: AsRef<std::path::Path>>(folder: P) -> std::path::PathBuf {
        match cert_manager::CertManager::from_folder(&folder) {
            Err(cert_manager::Error::IoError(error)) => {
                log::warn!(
                    "Error while opening the cert folder ({}):{error}",
                    folder.as_ref().display()
                );
                cert_manager::CertManager::new_in(&folder).unwrap();
            }
            Err(e) => panic!("{}", e),
            Ok(_) => (),
        }
        let folder = folder.as_ref();
        folder.to_path_buf()
    }

    pub fn init<P: AsRef<std::path::Path>>(&self, folder: P) -> Result<(), std::path::PathBuf> {
        self.folder.set(Self::init_ca(folder))
    }
}
#[cfg(any(feature = "quic-transport", feature = "tls-transport"))]
impl std::ops::Deref for CertFolder {
    type Target = std::path::PathBuf;

    fn deref(&self) -> &Self::Target {
        self.folder.get_or_init(|| Self::init_ca("examples/certs"))
    }
}
