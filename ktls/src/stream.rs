//! See [`KtlsStream`].

pub mod context;
pub mod error;
pub mod impl_std;

use std::os::fd::AsFd;
use std::pin::Pin;

use rustls::client::UnbufferedClientConnection;
use rustls::server::UnbufferedServerConnection;

use crate::error::Error;
use crate::stream::context::{Context, StreamState, TlsConnData};

const DEFAULT_SCRATCH_CAPACITY: usize = 64;

#[pin_project::pin_project(project = KTlsStreamProject, PinnedDrop)]
/// A thin wrapper around an inner socket with kernel TLS (kTLS) offload
/// configured.
///
/// This implements traits [`Read`](std::io::Read) and
/// [`Write`](std::io::Write), [`AsyncRead`](tokio::io::AsyncRead) and
/// [`AsyncWrite`](tokio::io::AsyncWrite) (when feature `async-io-tokio` is
/// enabled).
///
/// For those who may need low-level access to the inner socket, feature
/// `raw-api` provides an unsafe method [`as_raw`](Self::as_raw) to get a
/// mutable reference to the inner socket.
///
/// ## Behaviours
///
/// Once a TLS `close_notify` alert from the peer is received, all subsequent
/// read operations will return EOF.
///
/// Once the caller explicitly calls `(poll_)shutdown` on the stream, all
/// subsequent write operations will return 0 bytes, indicating that the
/// stream is closed for writing.
///
/// Once the stream is being dropped, a `close_notify` alert would be sent to
/// the peer automatically before shutting down the inner socket, according to
/// [RFC 8446, section 6.1].
///
/// The caller may call `(poll_)shutdown` on the stream to shutdown explicitly
/// both sides of the stream. Currently, there's no way provided by this crate
/// to shutdown the TLS stream write side only. For TLS 1.2, this is ideal since
/// once one party sends a `close_notify` alert, *the other party MUST respond
/// with a `close_notify` alert of its own and close down the connection
/// immediately*, according to [RFC 5246, section 7.2.1]; for TLS 1.3, *both
/// parties need not wait to receive a "`close_notify`" alert before
/// closing their read side of the connection*, according to [RFC 8446, section
/// 6.1].
///
/// [RFC 5246, section 7.2.1]: https://tools.ietf.org/html/rfc5246#section-7.2.1
/// [RFC 8446, section 6.1]: https://tools.ietf.org/html/rfc8446#section-6.1
pub struct KtlsStream<S>
where
    S: AsFd,
{
    #[pin]
    inner: S,

    /// The context of the kTLS stream.
    ctx: Context,
}

#[pin_project::pinned_drop]
impl<S: AsFd> PinnedDrop for KtlsStream<S> {
    fn drop(self: Pin<&mut Self>) {
        let this = self.project();

        // TODO: No need to flush? It's a no-op anyway for TcpStream / UnixStream.
        this.ctx.shutdown(&*this.inner);
    }
}

impl<S> KtlsStream<S>
where
    S: AsFd,
{
    /// Attempts to construct a new [`KtlsStream`] from the provided socket and
    /// [`UnbufferedClientConnection`].
    ///
    /// ## Prerequisites
    ///
    /// - The provided [`UnbufferedClientConnection`] must meet the following
    ///   requirements:
    ///
    ///   - TLS handshake must be completed
    ///   - [`enable_extract_secrets`](rustls::ClientConfig::enable_secret_extraction) must be set to `true`
    ///
    ///   For detailed information about these prerequisites, see the
    ///   [`rustls::kernel`] module documentation.
    ///
    /// - The socket provided must have ULP configured with
    ///   [`setup_ktls_ulp`](crate::setup::setup_ulp) in advance.
    ///
    /// ## Errors
    ///
    /// Returns an error if the connection does not meet the prerequisites or if
    /// the underlying kernel TLS setup fails.
    pub fn from_unbuffered_client_connnection(
        socket: S,
        conn: UnbufferedClientConnection,
    ) -> Result<Self, Error> {
        let (secrets, conn) = conn
            .dangerous_into_kernel_connection()
            .map_err(Error::ExtractSecrets)?;

        let supported_cipher_suite = conn.negotiated_cipher_suite();

        let mut this = Self {
            inner: socket,
            ctx: Context::new(StreamState::empty(), Vec::new(), TlsConnData::Client(conn)),
        };

        let ret = crate::setup::setup_tls_params(&this.inner, supported_cipher_suite, secrets);

        if ret.is_err() {
            this.ctx.shutdown(&this.inner);

            ret?;
        }

        Ok(this)
    }

    /// Attempts to construct a new [`KtlsStream`] from the provided socket and
    /// [`UnbufferedServerConnection`].
    ///
    /// ## Prerequisites
    ///
    /// - The provided [`UnbufferedServerConnection`] must meet the following
    ///   requirements:
    ///
    ///   - TLS handshake must be completed
    ///   - [`enable_extract_secrets`](rustls::ServerConfig::enable_secret_extraction) must be set to `true`
    ///
    ///   For detailed information about these prerequisites, see the
    ///   [`rustls::kernel`] module documentation.
    ///
    /// - The socket provided must have ULP configured with
    ///   [`setup_ktls_ulp`](crate::setup::setup_ulp) in advance.
    ///
    /// ## Errors
    ///
    /// Returns an error if the connection does not meet the prerequisites or if
    /// the underlying kernel TLS setup fails.
    pub fn from_unbuffered_server_connnection(
        socket: S,
        conn: UnbufferedServerConnection,
        early_data_received: Option<Vec<u8>>,
    ) -> Result<Self, Error> {
        let (secrets, conn) = conn
            .dangerous_into_kernel_connection()
            .map_err(Error::ExtractSecrets)?;

        // From here, the connection is considered established and handshake is
        // completed

        let supported_cipher_suite = conn.negotiated_cipher_suite();
        let (state, buffer) = match early_data_received {
            Some(early_data_received) if !early_data_received.is_empty() => {
                (StreamState::HAS_BUFFERED_DATA, early_data_received)
            }
            _ => (
                StreamState::empty(),
                Vec::with_capacity(DEFAULT_SCRATCH_CAPACITY),
            ),
        };

        let mut this = Self {
            inner: socket,
            ctx: Context::new(state, buffer, TlsConnData::Server(conn)),
        };

        let ret = crate::setup::setup_tls_params(&this.inner, supported_cipher_suite, secrets);

        if ret.is_err() {
            this.ctx.shutdown(&this.inner);

            ret?;
        }

        Ok(this)
    }
}
