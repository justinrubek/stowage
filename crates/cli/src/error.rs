#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    StdIo(#[from] std::io::Error),
    #[error(transparent)]
    StowageProto(#[from] stowage_proto::error::Error),
    #[error("Hello {0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, Error>;
