use std::path::PathBuf;

#[derive(clap::Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub(crate) struct Args {
    #[clap(subcommand)]
    pub command: Commands,
}

#[derive(clap::Subcommand, Debug)]
pub(crate) enum Commands {
    Bind(BindCommand),
    Mount(MountCommand),
    Unmount(UnmountCommand),
}

#[derive(clap::Args, Debug)]
pub(crate) struct MountCommand {
    /// plan9 dial string
    pub dial: String,
    /// the directory to mount the filesystem at. must be writable by the mounter.
    ///
    /// EXAMPLE:
    /// - `tcp!host!port`
    /// - `unix!socket`
    pub mount_point: String,

    #[arg(long, short)]
    /// tree to mount when attaching to a server that exports multiple trees
    pub aname: Option<String>,

    #[arg(long, short)]
    /// do not perform any points and only print the underlying mount command
    pub dry_run: bool,

    #[arg(long, short = 'x')]
    /// mount exclusively so that other users cannot access the mount
    pub exclusive: bool,

    #[arg(long, short)]
    /// mount the filesystem using the mounter's uid/gid
    pub inherit_user: bool,

    #[arg(long, short)]
    /// maximum length of a single 9p message, in bytes
    pub msize: Option<u32>,

    #[arg(long, short)]
    /// makes all users share the same filesystem rather than having individual attaches
    pub single_attach: bool,

    #[arg(long, short)]
    /// the user name to provide the server
    pub uname: Option<String>,
}

#[derive(clap::Args, Debug)]
pub(crate) struct BindCommand {
    pub source: String,
    pub destination: String,
}

#[derive(clap::Args, Debug)]
pub(crate) struct UnmountCommand {
    pub target: String,
}
