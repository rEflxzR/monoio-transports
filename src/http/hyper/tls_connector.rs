use std::fmt::Debug;

use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use crate::connectors::Connector;

#[cfg(not(feature = "hyper-native-tls"))]
use tokio_rustls::{TlsConnector, client::TlsStream};
#[cfg(feature = "hyper-native-tls")]
use tokio_native_tls::{TlsConnector, TlsStream};

#[cfg(not(feature = "hyper-native-tls"))]
pub type ServerName<'a> = rustls::pki_types::ServerName<'a>;

#[cfg(feature = "hyper-native-tls")]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TlsServerName(pub smol_str::SmolStr);
#[cfg(feature = "hyper-native-tls")]
pub type ServerName<'a> = TlsServerName;

#[cfg(feature = "hyper-native-tls")]
impl<T: Into<smol_str::SmolStr>> From<T> for ServerName<'static> {
    #[inline]
    fn from(value: T) -> Self {
        Self(value.into())
    }
}

#[derive(Error, Debug)]
pub enum TlsError {
    #[error("io error")]
    Io(#[from] std::io::Error),
    #[cfg(not(feature = "hyper-native-tls"))]
    #[error("rustls error")]
    Rustls(#[from] rustls::Error),
    #[cfg(feature = "hyper-native-tls")]
    #[error("native-tls error")]
    NativeTls(#[from] tokio_native_tls::native_tls::Error),
}

impl From<TlsError> for std::io::Error {
    fn from(e: TlsError) -> Self {
        match e {
            TlsError::Io(e) => e,
            #[cfg(not(feature = "hyper-native-tls"))]
            TlsError::Rustls(e) => std::io::Error::new(std::io::ErrorKind::Other, e),
            #[cfg(feature = "hyper-native-tls")]
            TlsError::NativeTls(e) => std::io::Error::new(std::io::ErrorKind::Other, e),
        }
    }
}

/// A connector for establishing TLS connections over an inner connector.
///
/// This connector wraps another connector (TCP in this case)
/// and adds TLS encryption to the connection. The underlying TLS implementation
/// can be either `rustls` or `native-tls` depending on the feature flags.
/// Set the `hyper-native-tls` feature to use the `native-tls` implementation. Default is 'rustls'
#[derive(Clone)]
pub struct HyperTlsConnector<C> {
    inner_connector: C,
    tls_connector: TlsConnector,
}

impl<C: Debug> Debug for HyperTlsConnector<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TlsConnector, inner: {:?}", self.inner_connector)
    }
}

impl<C> HyperTlsConnector<C> {
    pub const fn new(inner_connector: C, tls_connector: TlsConnector) -> Self {
        Self {
            inner_connector,
            tls_connector,
        }
    }

    // Create a new `TlsConnector` with custom ALPN protocols.
    #[cfg(not(feature = "hyper-native-tls"))]
    #[inline]
    pub fn new_with_tls_default(inner_connector: C, alpn: Option<Vec<&str>>) -> Self {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let mut cfg = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        // Set ALPN from client side
        match alpn {
            Some(alpn) => {
                let alpn: Vec<Vec<u8>> = alpn.iter().map(|a| a.as_bytes().to_vec()).collect();
                cfg.alpn_protocols = alpn;
            },
            None => {}
        }

        HyperTlsConnector::new(inner_connector, std::sync::Arc::new(cfg).into())
    }

    // Create a new `TlsConnector` with custom ALPN protocols.
    #[cfg(feature = "hyper-native-tls")]
    #[inline]
    pub fn new_with_tls_default(inner_connector: C, alpn: Option<Vec<&str>>) -> Self {
        let mut tls_connector = tokio_native_tls::native_tls::TlsConnector::builder();
        if let Some(alpn) = alpn {
            tls_connector.request_alpns(&alpn);
        }
        HyperTlsConnector::new(inner_connector, tls_connector.build().unwrap().into())
    }

    #[allow(unused)]
    #[inline]
    pub fn inner_connector(&self) -> &C {
        &self.inner_connector
    }

    #[allow(unused)]
    #[inline]
    pub fn tls_connector(&self) -> &TlsConnector {
        &self.tls_connector
    }
}

impl<C: Default> Default for HyperTlsConnector<C> {
    /// Create a new `TlsConnector` with the default inner connector.
    /// Additionally, the default ALPN protocols are set to `h2` and `http/1.1`.
    #[inline]
    fn default() -> Self {
        let alpn = Some(vec!["h2", "http/1.1"]);
        HyperTlsConnector::new_with_tls_default(Default::default(), alpn)
    }
}

impl<C, T, CN> Connector<T> for HyperTlsConnector<C>
    where
        T: AsRef<ServerName<'static>>,
        for<'a> C: Connector<&'a T, Error= std::io::Error, Connection= CN>,
        CN: AsyncRead + AsyncWrite + Unpin,
{
    type Connection = TlsStream<CN>;
    type Error = TlsError;

    async fn connect(&self, key: T) -> Result<Self::Connection, Self::Error> {
        let stream = self.inner_connector.connect(&key).await?;
        let server_name = key.as_ref();
        #[cfg(not(feature = "hyper-native-tls"))]
        let tls_stream = self
            .tls_connector
            .connect(server_name.clone(), stream)
            .await?;
        #[cfg(feature = "hyper-native-tls")]
        let tls_stream = self.tls_connector.connect(&server_name.0.as_str(), stream).await?;
        Ok(tls_stream)
    }
}