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
    #[error("Could not look up current user")]
    UserLookup,
    #[error("{0}: Invalid path")]
    InvalidPath(String),
    #[error("Could not access /proc/mounts")]
    MountsAccess,
    #[error("{0}: Not mounted")]
    NotMounted(PathBuf),
    #[error("{0}: Refusing to unmount non-9p filesystem")]
    NonNinePFilesystem(PathBuf),
    #[error("{0}: Not mounted by you")]
    NotMountedByUser(PathBuf),
    #[error("{0}: Unmount failed: {1}")]
    Unmount(PathBuf, String),
    #[error(transparent)]
    Nix(#[from] nix::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
