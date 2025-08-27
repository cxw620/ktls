//! Error type of `KtlsStream` and related operations.

use std::io;

use rustls::{AlertDescription, InvalidMessage, PeerMisbehaved};

#[non_exhaustive]
#[derive(Debug)]
#[derive(thiserror::Error)]
/// The error type for `KtlsStream` and related operations.
pub enum KtlsStreamError {
    #[error("Received corrupt message of type {0:?}")]
    /// A corrupt message was received from the peer.
    InvalidMessage(InvalidMessage),

    #[error("Peer misbehaved: {0:?}")]
    /// The peer misbehaved in some way.
    PeerMisbehaved(PeerMisbehaved),

    #[error("Key update failed: {0}")]
    /// Failed to handle a key update request.
    KeyUpdateFailed(#[source] rustls::Error),

    #[error("Failed to handle a provided session ticket: {0}")]
    /// Failed to handle a provided session ticket.
    SessionTicketFailed(#[source] rustls::Error),

    #[error("the connection has been closed by the peer")]
    /// The connection has been closed by the peer.
    Closed,

    #[error("cannot handle control messages while there is buffered data to read")]
    /// Cannot handle control messages while there is buffered data to read.
    ControlMessageWithBufferedData,

    #[error("Connection peer closed the connection with an alert: {0:?}")]
    /// The connection peer closed the connection with an alert.
    Alert(AlertDescription),
}

impl From<InvalidMessage> for KtlsStreamError {
    fn from(error: InvalidMessage) -> Self {
        Self::InvalidMessage(error)
    }
}

impl From<PeerMisbehaved> for KtlsStreamError {
    fn from(error: PeerMisbehaved) -> Self {
        Self::PeerMisbehaved(error)
    }
}

impl From<KtlsStreamError> for io::Error {
    fn from(value: KtlsStreamError) -> Self {
        Self::other(value)
    }
}
