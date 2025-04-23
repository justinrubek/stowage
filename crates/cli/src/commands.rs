use std::path::PathBuf;

#[derive(clap::Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub(crate) struct Args {
    #[clap(subcommand)]
    pub command: Commands,
}

#[derive(clap::Subcommand, Debug)]
pub(crate) enum Commands {
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
