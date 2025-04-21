use crate::{
    commands::{Commands, ServerCommands},
    error::Result,
    handlers::Memory,
};
use clap::Parser;
use std::sync::Arc;
use stowage_service::Plan9;
use tokio::net::TcpListener;
use tracing::info;

mod commands;
mod error;
mod handlers;

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
                    info!("listening on: {}", server.addr);

                    let fs = Arc::new(Memory::new());

                    loop {
                        let (socket, addr) = listener.accept().await?;
                        info!("new connection from: {addr}");

                        let fs_clone = fs.clone();
                        tokio::spawn(async move {
                            let service = Plan9::new(socket, fs_clone);
                            service.run().await.expect("server failed");
                        });
                    }
                }
            }
        }
    }
}
