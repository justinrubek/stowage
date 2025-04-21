#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Invalid message type: {0}")]
    InvalidMessageType(u8),
    #[error("Invalid utf8")]
    InvalidUtf8,
    #[error("Buffer too short")]
    BufferTooShort,
    #[error(transparent)]
    StdIo(#[from] std::io::Error),
    #[error(transparent)]
    TryFromInt(#[from] std::num::TryFromIntError),
}

pub type Result<T> = std::result::Result<T, Error>;
