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
    #[error("Empty dial string")]
    EmptyDialString,
    #[error("{0}: unknown network (expecting unix, tcp, or virtio)")]
    UnknownNetwork(String),
    #[error("Missing dial address")]
    MissingDialAddress,
    #[error("{0}: cannot access socket")]
    SocketAccess(String),
    #[error("{0}: invalid port")]
    InvalidPort(String),
    #[error("{0}: could not resolve hostname")]
    HostResolution(String),
    #[error("{0}: username contains commas")]
    InvalidUsername(String),
    #[error("{0}: spec contains commas")]
    InvalidAname(String),
    #[error("{0}: msize must be a positive integer")]
    InvalidMsize(u32),
    #[error("Mount error: {0}")]
    Mount(String),
    #[error(transparent)]
    Nul(#[from] std::ffi::NulError),
}

pub type Result<T> = std::result::Result<T, Error>;
