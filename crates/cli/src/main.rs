use crate::{
    commands::{Commands, ServerCommands},
    error::Result,
};
use clap::Parser;
use std::sync::Arc;
use stowage_filesystems::disk::Handler;
use stowage_service::Plan9;
use tokio::net::TcpListener;
use tracing::{error, info};

mod commands;
mod error;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let args = commands::Args::parse();
    match args.command {
        Commands::Server(server) => {
            let cmd = server.command;
            match cmd {
                ServerCommands::Start => {
                    let listener = TcpListener::bind(server.addr).await?;
                    info!(?server.addr, ?server.path, "listening");

                    let handler = Arc::new(Handler::new(server.path));

                    loop {
                        let (socket, addr) = listener.accept().await?;
                        info!("new connection from: {addr}");

                        let fs_clone = handler.clone();
                        tokio::spawn(async move {
                            let service = Plan9::new(socket, fs_clone);
                            if let Err(err) = service.run().await {
                                error!("Connection error from {addr}: {err}");
                            }
                        });
                    }
                }
            }
        }
    }
}
