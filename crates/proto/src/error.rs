#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Invalid message type: {0}")]
    InvalidMessageType(u8),
    #[error("Buffer too short")]
    BufferTooShort,
    #[error(transparent)]
    StdIo(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
