//! Message exchange over an established connection.
//!
//! Every application message travels on its own bidirectional QUIC stream:
//!
//! 1. the sender opens a stream, writes the UTF-8 JSON message and finishes its half;
//! 2. the receiver reads the whole stream (up to the size limit), hands the message
//!    to the application and answers with a single status byte, then finishes;
//! 3. the sender's `send` completes when that status byte arrives.
//!
//! QUIC already gives reliability, ordering within a stream, flow control and
//! encryption, so the 11-15 KB chunking and the hashes of the WebRTC transport are
//! not needed. The status byte keeps the "received by the peer" confirmation the
//! extension's request queues rely on.

use std::time::Duration;

use iroh::endpoint::{Connection, ReadToEndError, RecvStream, SendStream, VarInt};
use n0_future::time;

use crate::SendError;

/// ALPN of version 1 of this protocol.
pub const ALPN: &[u8] = b"radix-connect/iroh/1";

/// Status byte: the message was received and handed to the application.
const STATUS_RECEIVED: u8 = 0x00;
/// Status byte: the message was refused (too large or not valid UTF-8).
const STATUS_REJECTED: u8 = 0x01;

/// Application error codes used when closing a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CloseCode {
    /// The session was closed by its owner.
    Normal = 0,
    /// The remote endpoint is not the peer of this link.
    Unauthorized = 1,
    /// A newer connection from the same peer replaced this one.
    Replaced = 2,
}

impl From<CloseCode> for VarInt {
    fn from(code: CloseCode) -> Self {
        VarInt::from_u32(code as u32)
    }
}

/// Stream error code sent when an incoming message exceeds the size limit.
const STREAM_MESSAGE_TOO_LARGE: u32 = 1;

/// Sends `message` on a new stream and waits for the peer's status byte.
pub(crate) async fn send_message(
    conn: &Connection,
    message: &str,
    max_message_size: usize,
    ack_timeout: Duration,
) -> Result<(), SendError> {
    if message.len() > max_message_size {
        return Err(SendError::MessageTooLarge {
            size: message.len(),
            max: max_message_size,
        });
    }
    let exchange = async {
        let (mut send, mut recv) = conn.open_bi().await.map_err(lost)?;
        send.write_all(message.as_bytes()).await.map_err(lost)?;
        send.finish().map_err(lost)?;
        // The answer is exactly one byte; anything longer is a protocol violation.
        let status = recv.read_to_end(1).await.map_err(|error| match error {
            ReadToEndError::TooLong => SendError::Rejected,
            ReadToEndError::Read(error) => lost(error),
        })?;
        match status.as_slice() {
            [STATUS_RECEIVED] => Ok(()),
            _ => Err(SendError::Rejected),
        }
    };
    time::timeout(ack_timeout, exchange)
        .await
        .unwrap_or(Err(SendError::Timeout))
}

/// Outcome of reading one incoming stream.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Incoming {
    /// A complete message, still to be acknowledged with [`acknowledge`].
    Message(String),
    /// The stream was refused and answered; nothing to deliver.
    Refused,
}

/// Reads one message from a stream the peer opened.
///
/// Oversized or non-UTF-8 messages are answered with a rejection here and reported
/// as [`Incoming::Refused`]. A valid message must be acknowledged by the caller with
/// [`acknowledge`] once it has been handed to the application.
pub(crate) async fn read_message(
    send: &mut SendStream,
    recv: &mut RecvStream,
    max_message_size: usize,
) -> Result<Incoming, ReadToEndError> {
    let bytes = match recv.read_to_end(max_message_size).await {
        Ok(bytes) => bytes,
        Err(ReadToEndError::TooLong) => {
            tracing::warn!(
                max_message_size,
                "refusing an incoming message over the size limit"
            );
            // Ask the peer to stop sending the rest, then tell it why.
            let _ = recv.stop(VarInt::from_u32(STREAM_MESSAGE_TOO_LARGE));
            answer(send, STATUS_REJECTED).await;
            return Ok(Incoming::Refused);
        }
        Err(error) => return Err(error),
    };
    match String::from_utf8(bytes) {
        Ok(message) => Ok(Incoming::Message(message)),
        Err(_) => {
            tracing::warn!("refusing an incoming message that is not UTF-8");
            answer(send, STATUS_REJECTED).await;
            Ok(Incoming::Refused)
        }
    }
}

/// Confirms to the peer that its message reached the application.
pub(crate) async fn acknowledge(send: &mut SendStream) {
    answer(send, STATUS_RECEIVED).await;
}

async fn answer(send: &mut SendStream, status: u8) {
    // If the peer is gone it will not wait for the answer either: nothing to do.
    if send.write_all(&[status]).await.is_ok() {
        let _ = send.finish();
    }
}

fn lost(error: impl std::fmt::Display) -> SendError {
    SendError::ConnectionLost(error.to_string())
}
