use crate::{
    commands::Commands,
    error::{Error, Result},
};
use clap::Parser;
use tracing::{error, info};

mod commands;
mod error;

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let args = commands::Args::parse();
    match args.command {
        Commands::Bind(bind) => {
            todo!()
        }
        Commands::Mount(mount) => {
            todo!()
        }
        Commands::Unmount(mount) => {
            todo!()
        }
    }
}
