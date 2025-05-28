use std::path::PathBuf;

#[derive(clap::Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub(crate) struct Args {
    #[clap(subcommand)]
    pub command: Commands,
}

#[derive(clap::Subcommand, Debug)]
pub(crate) enum Commands {
    Debug(DebugCommand),
    Fs(FileCommand),
    Server(ServerCommand),
}

#[derive(clap::Args, Debug)]
pub(crate) struct ServerCommand {
    #[clap(subcommand)]
    pub command: ServerCommands,

    #[arg(default_value = "0.0.0.0:3000", long, short)]
    pub addr: std::net::SocketAddr,

    #[arg(default_value = "data", long, short)]
    pub path: PathBuf,
}

/// A command for running the API server
#[derive(clap::Subcommand, Debug)]
pub(crate) enum ServerCommands {
    /// start the http server
    Start,
}

#[derive(clap::Args, Debug)]
pub(crate) struct FileCommand {
    #[clap(subcommand)]
    pub command: FileCommands,

    #[arg(default_value = "0.0.0.0:3000", long, short)]
    pub addr: std::net::SocketAddr,
}

#[derive(clap::Subcommand, Debug)]
pub(crate) enum FileCommands {
    Ls {
        path: Option<String>,
    },
    Mkdir {
        path: String,
        /// create parent directories
        #[arg(long, short)]
        parents: bool,
    },
    Touch {
        path: String,
    },
    Write {
        path: String,
        /// Data to write (if omitted, read from stdin)
        data: Option<String>,
        /// Append to file instead of truncating
        #[arg(long, short)]
        append: bool,
    },
    Cat {
        path: String,
    },
}

#[derive(clap::Args, Debug)]
pub(crate) struct DebugCommand {
    #[clap(subcommand)]
    pub command: DebugCommands,
}

#[derive(clap::Subcommand, Debug)]
pub(crate) enum DebugCommands {
    /// Display the 9p messages contained in a binary file
    DumpMessages { path: PathBuf },
}
