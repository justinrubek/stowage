use std::path::PathBuf;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    StdIo(#[from] std::io::Error),
    #[error("{0}: path doesn't exist or is inaccessible")]
    Path(PathBuf),
    #[error("{0}: not writable")]
    NotWritable(PathBuf),
    #[error("{0}: refusing to bind over sticky directory")]
    StickyDirectory(PathBuf),
    #[error("Mount failed with code: {0}")]
    Mount(nix::errno::Errno),
}

pub type Result<T> = std::result::Result<T, Error>;
