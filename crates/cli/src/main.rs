use crate::{
    commands::{Commands, HelloCommands},
    error::Result,
};
use clap::Parser;
use futures::{SinkExt, StreamExt};
use std::sync::Arc;
use stowage_9p::{codec::Plan9, fs::Filesystem};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::Framed;

mod commands;
mod error;

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let args = commands::Args::parse();
    match args.command {
        Commands::Hello(hello) => {
            let cmd = hello.command;
            match cmd {
                HelloCommands::World => {
                    println!("Hello, world!");
                }
                HelloCommands::Name { name } => {
                    println!("Hello, {name}!");
                }
                HelloCommands::Error => {
                    Err(crate::error::Error::Other("error".into()))?;
                }
            }
        }
    }

    Ok(())
}

pub struct Plan9Service<T, F>
where
    T: AsyncRead + AsyncWrite + Unpin,
    F: Filesystem,
{
    connection: Framed<T, Plan9>,
    filesystem: Arc<F>,
}

impl<T, F> Plan9Service<T, F>
where
    T: AsyncRead + AsyncWrite + Unpin,
    F: Filesystem,
{
    pub fn new(connection: T, filesystem: Arc<F>) -> Self {
        Self {
            connection: Framed::new(connection, Plan9),
            filesystem,
        }
    }

    pub async fn run(mut self) {
        while let Some(message_result) = self.connection.next().await {
            match message_result {
                Ok(request) => {
                    let response = self.filesystem.handle_message(request).await;
                    if let Err(e) = self.connection.send(response).await {
                        eprintln!("error sending response: {:?}", e);
                        break;
                    }
                }
                Err(e) => {
                    eprintln!("error receiving message: {:?}", e);
                    break;
                }
            }
        }
    }
}
