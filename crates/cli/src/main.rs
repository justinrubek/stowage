use crate::{
    commands::{Commands, HelloCommands},
    error::Result,
};
use clap::Parser;
use futures::{SinkExt, StreamExt};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use stowage_proto::{Codec, Message, Qid};
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
    connection: Framed<T, Codec>,
    filesystem: Arc<F>,
}

impl<T, F> Plan9Service<T, F>
where
    T: AsyncRead + AsyncWrite + Unpin,
    F: Filesystem,
{
    pub fn new(connection: T, filesystem: Arc<F>) -> Self {
        Self {
            connection: Framed::new(connection, Codec),
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

pub trait Filesystem {
    async fn handle_message(&self, message: Message) -> Message;
}

/// Simple in-memory file-system implementation
pub struct BasicFilesystem {
    files: Mutex<HashMap<u32, Vec<u8>>>,
    next_fid: Mutex<u32>,
}

impl BasicFilesystem {
    pub fn new() -> Self {
        Self {
            files: Mutex::new(HashMap::new()),
            next_fid: Mutex::new(1),
        }
    }
}

impl Filesystem for BasicFilesystem {
    async fn handle_message(&self, message: Message) -> Message {
        match message {
            Message::Tversion { tag, msize, .. } => Message::Rversion {
                tag,
                msize: msize.min(8192),
                version: "9P2000".to_string(),
            },
            Message::Tattach { tag, .. } => {
                Message::Rattach {
                    tag,
                    qid: Qid {
                        qtype: 0x80, // QTDIR
                        version: 0,
                        path: 0,
                    },
                }
            }
            // TODO: implement other message handlers
            _ => {
                // default error response for unimplemented messages
                Message::Rerror {
                    tag: 0, // TODO: use appropriate tag
                    ename: "not implemented".to_string(),
                }
            }
        }
    }
}
