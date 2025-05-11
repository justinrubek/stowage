use crate::{
    commands::{Commands, ServerCommands},
    error::Result,
};
use bytes::BytesMut;
use clap::Parser;
use error::Error;
use futures::{SinkExt, StreamExt};
use std::sync::Arc;
use stowage_filesystems::disk::Handler;
use stowage_proto::{Codec, Message, Tattach, Tauth, Tclunk, Tlopen, Treaddir, Tversion};
use stowage_service::Plan9;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::Framed;
use tracing::{error, info};

mod commands;
mod error;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let args = commands::Args::parse();
    match args.command {
        Commands::Fs(fs) => {
            let cmd = fs.command;

            let stream = TcpStream::connect(fs.addr).await?;
            let tag: u16 = 1;

            let mut conn = Framed::new(stream, Codec);

            let version_tag = 0xFFFF;
            let msize = 8192;

            // version negotiation
            let version_msg = Message::Tversion(Tversion {
                tag: version_tag,
                msize: msize,
                version: String::from("9P2000.L"),
            });
            conn.send(version_msg).await?;

            if let Some(Ok(msg)) = conn.next().await {
                match msg {
                    Message::Rversion(rversion) => {
                        if rversion.version != "9P.2000L" {
                            return Err(Error::Other(format!(
                                "server doesn't support 9P2000.L, got {}",
                                rversion.version
                            )));
                        }
                        let max_size = std::cmp::min(msize, rversion.msize);
                        println!(
                            "negotiation version: {} with msize: {}",
                            rversion.version, msize
                        );
                    }
                    Message::Rlerror(err) => {
                        return Err(Error::Other(format!(
                            "version negotiation failed: {}",
                            err.ecode
                        )));
                    }
                    _ => return Err(Error::Other("unexpected response to Tversion".into())),
                }
            } else {
                return Err(Error::Other("no response to version negotiation".into()));
            }

            let afid = 1;
            let auth_msg = Tauth {
                tag,
                afid,
                uname: String::from("nobody"),
                aname: String::from(""),
            };
            conn.send(Message::Tauth(auth_msg)).await?;

            let used_afid: u32;
            if let Some(Ok(msg)) = conn.next().await {
                match msg {
                    Message::Rauth(_) => {
                        return Err(Error::Other(
                            "authentication required but not supported by this client".into(),
                        ));
                    }
                    Message::Rlerror(_) => {
                        // expected when auth is not required
                        used_afid = 0xFFFFFFFF; // P9_NOFID
                    }
                    _ => return Err(Error::Other("unexpected response to Tauth".into())),
                }
            } else {
                return Err(Error::Other("no response to authentication".into()));
            }

            match cmd {
                commands::FileCommands::Ls { path } => {
                    let path = path.or(Some("/".into())).unwrap();
                    println!("{path}");

                    // 1. Attach to filesystem
                    let root_fid = 2;
                    let attach_msg = Tattach {
                        tag,
                        fid: root_fid,
                        afid: used_afid,
                        uname: String::from("nobody"),
                        aname: String::from(""),
                    };

                    conn.send(Message::Tattach(attach_msg)).await?;

                    // Handle attach response
                    if let Some(Ok(msg)) = conn.next().await {
                        match msg {
                            Message::Rattach(_) => {
                                // Successfully attached
                            }
                            Message::Rlerror(err) => {
                                return Err(Error::Other(format!(
                                    "Failed to attach to filesystem: error {}",
                                    err.ecode
                                )));
                            }
                            _ => return Err(Error::Other("Unexpected response to Tattach".into())),
                        }
                    } else {
                        return Err(Error::Other("No response to attach".into()));
                    }

                    // 2. Open directory
                    let lopen_msg = Tlopen {
                        tag,
                        fid: root_fid,
                        flags: 0, // P9_RDONLY
                    };

                    conn.send(Message::Tlopen(lopen_msg)).await?;

                    // Handle lopen response
                    if let Some(Ok(msg)) = conn.next().await {
                        match msg {
                            Message::Rlopen(_) => {
                                // Directory opened successfully
                            }
                            Message::Rlerror(err) => {
                                return Err(Error::Other(format!(
                                    "Failed to open directory: error {}",
                                    err.ecode
                                )));
                            }
                            _ => return Err(Error::Other("Unexpected response to Tlopen".into())),
                        }
                    } else {
                        return Err(Error::Other("No response to lopen".into()));
                    }

                    // 3. Read directory contents
                    let mut offset: u64 = 0;
                    let mut entries = Vec::new();
                    let max_count = 8192; // P9_MAX_BUF

                    loop {
                        let readdir_msg = Treaddir {
                            tag,
                            fid: root_fid,
                            offset,
                            count: max_count,
                        };

                        conn.send(Message::Treaddir(readdir_msg)).await?;

                        // Handle readdir response
                        if let Some(Ok(msg)) = conn.next().await {
                            match msg {
                                Message::Rreaddir(rreaddir) => {
                                    if rreaddir.data.is_empty() {
                                        break; // No more entries
                                    }

                                    // Process entries and update offset for next read
                                    for entry in &rreaddir.data {
                                        entries.push(entry.clone());
                                        offset = entry.offset;
                                    }

                                    if rreaddir.data.len() < (max_count as usize) {
                                        break; // Reached end of directory
                                    }
                                }
                                Message::Rlerror(err) => {
                                    return Err(Error::Other(format!(
                                        "Failed to read directory: error {}",
                                        err.ecode
                                    )));
                                }
                                _ => {
                                    return Err(Error::Other(
                                        "Unexpected response to Treaddir".into(),
                                    ))
                                }
                            }
                        } else {
                            return Err(Error::Other("No response to readdir".into()));
                        }
                    }

                    // 4. Clunk the fid
                    let clunk_msg = Tclunk { tag, fid: root_fid };

                    conn.send(Message::Tclunk(clunk_msg)).await?;

                    // Handle clunk response (optional, but good practice)
                    if let Some(Ok(msg)) = conn.next().await {
                        match msg {
                            Message::Rclunk(_) => {
                                // Successfully closed directory
                            }
                            Message::Rlerror(err) => {
                                // Non-fatal error
                                eprintln!("Warning: Failed to clunk fid: error {}", err.ecode);
                            }
                            _ => {
                                // Non-fatal error
                                eprintln!("Warning: Unexpected response to Tclunk");
                            }
                        }
                    }

                    // Display results
                    println!("Directory listing for {path}:");
                    for entry in entries {
                        let type_char = if entry.dtype & 0x80 != 0 { 'd' } else { '-' };
                        println!("{}{}", type_char, entry.name);
                    }

                    Ok(())
                }
            }
        }
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
