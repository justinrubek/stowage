use crate::{
    commands::{Commands, ServerCommands},
    error::Result,
};
use clap::Parser;
use commands::DebugCommands;
use error::Error;
use futures::{SinkExt, StreamExt};
use std::{io::Cursor, path::PathBuf, sync::Arc};
use stowage_filesystems::disk::Handler;
use stowage_proto::{
    consts::P9_NOFID, Decodable, Message, MessageCodec, Stat, TaggedMessage, Tattach, Tauth,
    Tclunk, Tcreate, Topen, Tread, Tstat, Tversion, Twalk, Twrite, Twstat,
};
use stowage_service::Plan9;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::{Decoder, Framed};
use tracing::{error, info};

mod commands;
mod error;

type Connection = Framed<TcpStream, MessageCodec>;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let args = commands::Args::parse();
    match args.command {
        Commands::Debug(debug) => match debug.command {
            DebugCommands::DumpMessages { path } => dump_messages_command(&path),
        },
        Commands::Fs(fs) => {
            let cmd = fs.command;

            let stream = TcpStream::connect(fs.addr).await?;
            let mut conn = Framed::new(stream, MessageCodec::new());
            let tag: u16 = 1;

            let msize = perform_handshake(&mut conn, tag).await?;

            match cmd {
                commands::FileCommands::Ls { path } => {
                    ls_command(&mut conn, tag, path, msize).await
                }
                commands::FileCommands::Mkdir { path, parents } => {
                    mkdir_command(&mut conn, tag, path, parents).await
                }
                commands::FileCommands::Touch { path } => touch_command(&mut conn, tag, path).await,
                commands::FileCommands::Write { path, data, append } => {
                    write_command(&mut conn, tag, path, data, append, msize).await
                }
                commands::FileCommands::Cat { path } => {
                    cat_command(&mut conn, tag, path, msize).await
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

async fn perform_handshake(conn: &mut Connection, tag: u16) -> Result<u32> {
    let msize = perform_version_negotiation(conn).await?;
    perform_authentication(conn, tag).await?;
    attach_to_filesystem(conn, tag).await?;
    Ok(msize)
}

async fn perform_version_negotiation(conn: &mut Connection) -> Result<u32> {
    let version_tag = 0xFFFF;
    let mut msize = 8192;

    let version_msg = Message::Tversion(Tversion {
        msize,
        version: String::from("9P2000"),
    });
    let tagged = TaggedMessage {
        message: version_msg,
        tag: version_tag,
    };

    send_message(conn, tagged).await?;

    let response = receive_message(conn).await?;
    match response.message {
        Message::Rversion(rversion) => {
            if rversion.version != "9P2000" {
                return Err(Error::Other(format!(
                    "server doesn't support 9P2000, got {}",
                    rversion.version
                )));
            }
            msize = std::cmp::min(msize, rversion.msize);
            println!(
                "negotiated version: {} with msize: {}",
                rversion.version, msize
            );
            Ok(msize)
        }
        Message::Rerror(err) => Err(Error::Other(format!(
            "version negotiation failed: {}",
            err.ename
        ))),
        _ => Err(Error::Other("unexpected response to Tversion".into())),
    }
}

async fn perform_authentication(conn: &mut Connection, tag: u16) -> Result<()> {
    let afid = 1;
    let auth_msg = Tauth {
        afid,
        uname: String::from("nobody"),
        aname: String::new(),
    };
    let tagged = TaggedMessage {
        message: Message::Tauth(auth_msg),
        tag,
    };

    send_message(conn, tagged).await?;

    let response = receive_message(conn).await?;
    match response.message {
        Message::Rauth(_) => Err(Error::Other(
            "authentication required but not supported by this client".into(),
        )),
        Message::Rerror(_) => {
            // expected when auth is not required
            Ok(())
        }
        _ => Err(Error::Other("unexpected response to Tauth".into())),
    }
}

async fn attach_to_filesystem(conn: &mut Connection, tag: u16) -> Result<()> {
    let root_fid = 2;
    let attach_msg = Tattach {
        fid: root_fid,
        afid: P9_NOFID,
        uname: String::from("nobody"),
        aname: String::new(),
    };
    let tagged = TaggedMessage {
        message: Message::Tattach(attach_msg),
        tag,
    };

    send_message(conn, tagged).await?;

    let response = receive_message(conn).await?;
    match response.message {
        Message::Rattach(_) => Ok(()),
        Message::Rerror(err) => Err(Error::Other(format!(
            "Failed to attach to filesystem: {}",
            err.ename
        ))),
        _ => Err(Error::Other("Unexpected response to Tattach".into())),
    }
}

async fn send_message(conn: &mut Connection, message: TaggedMessage) -> Result<()> {
    conn.send(message).await.map_err(Error::from)
}

async fn receive_message(conn: &mut Connection) -> Result<TaggedMessage> {
    match conn.next().await {
        Some(Ok(msg)) => Ok(msg),
        Some(Err(e)) => Err(Error::from(e)),
        None => Err(Error::Other("Connection closed".into())),
    }
}

fn parse_path_components(path: &str) -> Vec<String> {
    path.split('/')
        .filter(|s| !s.is_empty())
        .map(std::string::ToString::to_string)
        .collect()
}

async fn walk_to_path(
    conn: &mut Connection,
    tag: u16,
    base_fid: u32,
    new_fid: u32,
    path: &str,
) -> Result<bool> {
    let components = parse_path_components(path);

    if components.is_empty() {
        return Ok(true); // root path
    }

    let walk_msg = Twalk {
        fid: base_fid,
        newfid: new_fid,
        wnames: components.clone(),
    };
    let tagged = TaggedMessage {
        message: Message::Twalk(walk_msg),
        tag,
    };

    send_message(conn, tagged).await?;

    let response = receive_message(conn).await?;
    match response.message {
        Message::Rwalk(rwalk) => Ok(rwalk.wqids.len() == components.len()),
        Message::Rerror(_) => Ok(false),
        _ => Err(Error::Other("Unexpected response to Twalk".into())),
    }
}

async fn cleanup_fid(conn: &mut Connection, tag: u16, fid: u32) -> Result<()> {
    let clunk_msg = Tclunk { fid };
    let tagged = TaggedMessage {
        message: Message::Tclunk(clunk_msg),
        tag,
    };

    send_message(conn, tagged).await?;

    // handle response but don't fail on clunk errors
    if let Ok(response) = receive_message(conn).await {
        match response.message {
            Message::Rclunk(_) => {}
            Message::Rerror(err) => {
                eprintln!("warning: Failed to clunk fid {}: {}", fid, err.ename);
            }
            _ => {
                eprintln!("warning: Unexpected response to Tclunk for fid {fid}");
            }
        }
    }

    Ok(())
}

async fn ls_command(
    conn: &mut Connection,
    tag: u16,
    path: Option<String>,
    msize: u32,
) -> Result<()> {
    let path = path.unwrap_or_else(|| "/".to_string());
    info!("running: ls {path}");

    let mut root_fid = 2;

    // walk to target path if not root
    if path != "/" {
        let components = parse_path_components(&path);
        if !components.is_empty() {
            let walk_success = walk_to_path(conn, tag, root_fid, root_fid + 1, &path).await?;
            if !walk_success {
                return Err(Error::Other(format!("path not found: {path}")));
            }
            root_fid += 1;
        }
    }

    let open_msg = Topen {
        fid: root_fid,
        mode: 0, // OREAD
    };
    send_message(
        conn,
        TaggedMessage {
            message: Message::Topen(open_msg),
            tag,
        },
    )
    .await?;

    let response = receive_message(conn).await?;
    match response.message {
        Message::Ropen(_) => {}
        Message::Rerror(err) => {
            return Err(Error::Other(format!(
                "failed to open directory: {}",
                err.ename
            )));
        }
        _ => return Err(Error::Other("unexpected response to Topen".into())),
    }

    read_directory_contents(conn, tag, root_fid, msize).await?;

    cleanup_fid(conn, tag, root_fid).await?;

    Ok(())
}

async fn read_directory_contents(
    conn: &mut Connection,
    tag: u16,
    fid: u32,
    msize: u32,
) -> Result<()> {
    let protocol_overhead = 100;
    let max_count = if msize > protocol_overhead {
        msize - protocol_overhead
    } else {
        4096
    };

    let mut offset = 0u64;

    loop {
        let tread = TaggedMessage::new(
            tag,
            Message::Tread(Tread {
                fid,
                offset,
                count: max_count,
            }),
        );

        send_message(conn, tread).await?;
        let response = receive_message(conn).await?;

        match response.message {
            Message::Rread(rread) => {
                if rread.data.is_empty() {
                    break; // end of directory
                }

                let data_len = rread.data.len();
                let mut data_slice = &rread.data[..];

                // process each stat entry in the directory read response
                while !data_slice.is_empty() {
                    if data_slice.len() < 2 {
                        break;
                    }

                    let stat_size = u16::from_le_bytes([data_slice[0], data_slice[1]]) as usize;
                    if data_slice.len() < stat_size + 2 {
                        break;
                    }

                    let mut cursor = Cursor::new(&data_slice[0..stat_size + 2]);

                    match Stat::decode(&mut cursor) {
                        Ok(stat) => {
                            println!(
                                "{:>8} {} {}",
                                stat.length,
                                stat.name,
                                if stat.mode & 0x8000_0000 != 0 {
                                    "/"
                                } else {
                                    ""
                                }
                            );

                            // move to the next stat entry
                            data_slice = &data_slice[stat_size + 2..];
                        }
                        Err(e) => {
                            eprintln!("Warning: Failed to parse stat: {e}");
                            break;
                        }
                    }
                }

                offset += data_len as u64;
            }
            Message::Rerror(err) => {
                return Err(Error::Other(format!(
                    "Failed to read directory: {}",
                    err.ename
                )));
            }
            _ => return Err(Error::Other("Unexpected response to Tread".into())),
        }
    }

    Ok(())
}

async fn mkdir_command(conn: &mut Connection, tag: u16, path: String, parents: bool) -> Result<()> {
    info!("running: mkdir {path}");

    let path = path.trim_end_matches('/');
    let components = parse_path_components(path);

    if components.is_empty() {
        return Err(Error::Other("Cannot create root directory".into()));
    }

    // find existing depth
    let mut existing_depth = 0;
    let root_fid = 2;

    for i in 1..=components.len() {
        let partial_components = components[0..i].to_vec();
        let walk_success = walk_to_path(
            conn,
            tag,
            root_fid,
            root_fid + 1,
            &partial_components.join("/"),
        )
        .await?;

        if walk_success {
            existing_depth = i;
            if i == components.len() {
                return Err(Error::Other(format!(
                    "mkdir: cannot create directory '{path}': File exists"
                )));
            }
            cleanup_fid(conn, tag, root_fid + 1).await?;
        } else {
            cleanup_fid(conn, tag, root_fid + 1).await?;
            break;
        }
    }

    // check if we need -p flag
    if existing_depth < components.len() - 1 && !parents {
        return Err(Error::Other(format!(
            "mkdir: cannot create directory '{path}': No such file or directory"
        )));
    }

    // create missing directories
    for i in existing_depth..components.len() {
        create_directory(conn, tag, &components, i).await?;
    }

    println!("Directory created: {path}");
    Ok(())
}

async fn create_directory(
    conn: &mut Connection,
    tag: u16,
    components: &[String],
    index: usize,
) -> Result<()> {
    let root_fid = 2;
    let parent_components = if index == 0 {
        vec![]
    } else {
        components[0..index].to_vec()
    };

    if parent_components.is_empty() {
        // creating in root
        let create_msg = Tcreate {
            fid: root_fid,
            name: components[index].clone(),
            perm: 0o755 | 0x8000_0000, // directory permissions with DMDIR bit
            mode: 0,                   // OREAD
        };
        send_message(
            conn,
            TaggedMessage {
                message: Message::Tcreate(create_msg),
                tag,
            },
        )
        .await?;

        let response = receive_message(conn).await?;
        match response.message {
            Message::Rcreate(_) => {
                if index < components.len() - 1 {
                    cleanup_fid(conn, tag, root_fid).await?;
                }
                Ok(())
            }
            Message::Rerror(err) => Err(Error::Other(format!(
                "failed to create directory '{}': {}",
                components[index], err.ename
            ))),
            _ => Err(Error::Other("unexpected response to Tcreate".into())),
        }
    } else {
        // walk to parent and create there
        let parent_fid = root_fid + 2;
        let walk_success = walk_to_path(
            conn,
            tag,
            root_fid,
            parent_fid,
            &parent_components.join("/"),
        )
        .await?;

        if !walk_success {
            return Err(Error::Other("failed to walk to parent directory".into()));
        }

        let create_msg = Tcreate {
            fid: parent_fid,
            name: components[index].clone(),
            perm: 0o755 | 0x8000_0000,
            mode: 0,
        };
        send_message(
            conn,
            TaggedMessage {
                message: Message::Tcreate(create_msg),
                tag,
            },
        )
        .await?;

        let response = receive_message(conn).await?;
        match response.message {
            Message::Rcreate(_) => {
                cleanup_fid(conn, tag, parent_fid).await?;
                Ok(())
            }
            Message::Rerror(err) => {
                cleanup_fid(conn, tag, parent_fid).await?;
                Err(Error::Other(format!(
                    "failed to create directory '{}': {}",
                    components[index], err.ename
                )))
            }
            _ => {
                cleanup_fid(conn, tag, parent_fid).await?;
                Err(Error::Other("unexpected response to Tcreate".into()))
            }
        }
    }
}

async fn touch_command(conn: &mut Connection, tag: u16, path: String) -> Result<()> {
    info!("running: touch {path}");

    let components = parse_path_components(&path);
    if components.is_empty() {
        return Err(Error::Other("cannot touch root directory".into()));
    }

    let root_fid = 2;
    let file_fid = root_fid + 1;

    let file_exists = walk_to_path(conn, tag, root_fid, file_fid, &path).await?;

    if file_exists {
        handle_existing_file_touch(conn, tag, file_fid, &path).await?;
    } else {
        create_new_file(conn, tag, &components, &path).await?;
    }

    Ok(())
}

async fn handle_existing_file_touch(
    conn: &mut Connection,
    tag: u16,
    file_fid: u32,
    path: &str,
) -> Result<()> {
    // check if it's a directory
    let stat_msg = Message::Tstat(Tstat { fid: file_fid });
    send_message(
        conn,
        TaggedMessage {
            message: stat_msg,
            tag,
        },
    )
    .await?;

    let response = receive_message(conn).await?;
    match response.message {
        Message::Rstat(rstat) => {
            if rstat.stat.mode & 0x8000_0000 != 0 {
                cleanup_fid(conn, tag, file_fid).await?;
                return Err(Error::Other(format!("touch: {path}: Is a directory")));
            }

            let current_time = u32::try_from(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            )
            .unwrap();

            if let Ok(updated_stat) = create_updated_stat(&rstat.stat, current_time, current_time) {
                let wstat_msg = Message::Twstat(Twstat {
                    fid: file_fid,
                    stat: updated_stat,
                });
                send_message(
                    conn,
                    TaggedMessage {
                        message: wstat_msg,
                        tag,
                    },
                )
                .await?;

                if let Ok(response) = receive_message(conn).await {
                    match response.message {
                        Message::Rwstat(_) => {
                            println!("updated access and modification times for: {path}");
                        }
                        Message::Rerror(err) => {
                            eprintln!("warning: Could not update file times: {}", err.ename);
                            println!("file exists: {path}");
                        }
                        _ => {
                            eprintln!("warning: Unexpected response to Twstat");
                            println!("file exists: {path}");
                        }
                    }
                }
            } else {
                println!("file exists: {path}");
            }
        }
        Message::Rerror(err) => {
            return Err(Error::Other(format!(
                "failed to get file stat: {}",
                err.ename
            )));
        }
        _ => return Err(Error::Other("unexpected response to Tstat".into())),
    }

    cleanup_fid(conn, tag, file_fid).await?;
    Ok(())
}

async fn create_new_file(
    conn: &mut Connection,
    tag: u16,
    components: &[String],
    path: &str,
) -> Result<()> {
    let root_fid = 2;
    let (parent_components, filename) = if components.len() > 1 {
        (
            components[0..components.len() - 1].to_vec(),
            components.last().unwrap().clone(),
        )
    } else {
        (vec![], components[0].clone())
    };

    if parent_components.is_empty() {
        // creating in root directory
        let create_msg = Tcreate {
            fid: root_fid,
            name: filename,
            perm: 0o644,
            mode: 2, // OWRITE to create and immediately close
        };
        send_message(
            conn,
            TaggedMessage {
                message: Message::Tcreate(create_msg),
                tag,
            },
        )
        .await?;

        let response = receive_message(conn).await?;
        match response.message {
            Message::Rcreate(_) => {
                cleanup_fid(conn, tag, root_fid).await?;
                println!("file created: {path}");
                Ok(())
            }
            Message::Rerror(err) => Err(Error::Other(format!(
                "failed to create file '{}': {}",
                path, err.ename
            ))),
            _ => Err(Error::Other("unexpected response to Tcreate".into())),
        }
    } else {
        // walk to parent directory first
        let parent_fid = root_fid + 2;
        let walk_success = walk_to_path(
            conn,
            tag,
            root_fid,
            parent_fid,
            &parent_components.join("/"),
        )
        .await?;

        if !walk_success {
            cleanup_fid(conn, tag, parent_fid).await?;
            return Err(Error::Other(format!(
                "parent directory not found for: {path}"
            )));
        }

        let create_msg = Tcreate {
            fid: parent_fid,
            name: filename,
            perm: 0o644,
            mode: 2,
        };
        send_message(
            conn,
            TaggedMessage {
                message: Message::Tcreate(create_msg),
                tag,
            },
        )
        .await?;

        let response = receive_message(conn).await?;
        match response.message {
            Message::Rcreate(_) => {
                cleanup_fid(conn, tag, parent_fid).await?;
                println!("file created: {path}");
                Ok(())
            }
            Message::Rerror(err) => {
                cleanup_fid(conn, tag, parent_fid).await?;
                Err(Error::Other(format!(
                    "failed to create file '{path}': {}",
                    err.ename
                )))
            }
            _ => {
                cleanup_fid(conn, tag, parent_fid).await?;
                Err(Error::Other("unexpected response to Tcreate".into()))
            }
        }
    }
}

async fn write_command(
    conn: &mut Connection,
    tag: u16,
    path: String,
    data: Option<String>,
    append: bool,
    msize: u32,
) -> Result<()> {
    info!("running: write {path} (append: {append})");

    // get data from command line or stdin
    let write_data = if let Some(data) = data {
        data.into_bytes()
    } else {
        use std::io::Read;
        let mut buffer = Vec::new();
        std::io::stdin().read_to_end(&mut buffer)?;
        buffer
    };

    let root_fid = 2;
    let components = parse_path_components(&path);

    if components.is_empty() {
        return Err(Error::Other("cannot write to root directory".into()));
    }

    // try to walk to the file
    let file_fid = root_fid + 1;
    let file_exists = walk_to_path(conn, tag, root_fid, file_fid, &path).await?;

    let (write_fid, start_offset) = if file_exists {
        // file exists - open for writing
        open_file_for_writing(conn, tag, file_fid, append).await?
    } else {
        // file doesn't exist - create it
        cleanup_fid(conn, tag, file_fid).await?;
        create_file_for_writing(conn, tag, &components, &path).await?
    };

    write_data_to_file(conn, tag, write_fid, &write_data, start_offset, msize).await?;

    cleanup_fid(conn, tag, write_fid).await?;

    let mode_str = if append { "appended" } else { "wrote" };
    println!("{} {} bytes to {}", mode_str, write_data.len(), path);
    Ok(())
}

async fn open_file_for_writing(
    conn: &mut Connection,
    tag: u16,
    file_fid: u32,
    append: bool,
) -> Result<(u32, u64)> {
    let open_msg = Topen {
        fid: file_fid,
        mode: 1, // OWRITE
    };
    send_message(
        conn,
        TaggedMessage {
            message: Message::Topen(open_msg),
            tag,
        },
    )
    .await?;

    let response = receive_message(conn).await?;
    match response.message {
        Message::Ropen(_) => {
            let offset = if append {
                get_file_size(conn, tag, file_fid).await.unwrap_or(0)
            } else {
                0
            };
            Ok((file_fid, offset))
        }
        Message::Rerror(err) => Err(Error::Other(format!(
            "failed to open file for writing: {}",
            err.ename
        ))),
        _ => Err(Error::Other("unexpected response to Topen".into())),
    }
}

async fn get_file_size(conn: &mut Connection, tag: u16, fid: u32) -> Result<u64> {
    let stat_msg = Message::Tstat(Tstat { fid });
    send_message(
        conn,
        TaggedMessage {
            message: stat_msg,
            tag,
        },
    )
    .await?;

    let response = receive_message(conn).await?;
    match response.message {
        Message::Rstat(rstat) => Ok(rstat.stat.length),
        Message::Rerror(err) => {
            eprintln!(
                "warning: Could not stat file: {}, starting at offset 0",
                err.ename
            );
            Ok(0)
        }
        _ => {
            eprintln!("warning: Unexpected response to Tstat, starting at offset 0");
            Ok(0)
        }
    }
}

async fn create_file_for_writing(
    conn: &mut Connection,
    tag: u16,
    components: &[String],
    path: &str,
) -> Result<(u32, u64)> {
    let root_fid = 2;
    let (parent_components, filename) = if components.len() > 1 {
        (
            components[0..components.len() - 1].to_vec(),
            components.last().unwrap().clone(),
        )
    } else {
        (vec![], components[0].clone())
    };

    if parent_components.is_empty() {
        // creating in root directory
        let create_msg = Tcreate {
            fid: root_fid,
            name: filename,
            perm: 0o644,
            mode: 1, // OWRITE
        };
        send_message(
            conn,
            TaggedMessage {
                message: Message::Tcreate(create_msg),
                tag,
            },
        )
        .await?;

        let response = receive_message(conn).await?;
        match response.message {
            Message::Rcreate(_) => Ok((root_fid, 0)),
            Message::Rerror(err) => Err(Error::Other(format!(
                "failed to create file '{}': {}",
                path, err.ename
            ))),
            _ => Err(Error::Other("unexpected response to Tcreate".into())),
        }
    } else {
        // walk to parent directory first
        let parent_fid = root_fid + 2;
        let walk_success = walk_to_path(
            conn,
            tag,
            root_fid,
            parent_fid,
            &parent_components.join("/"),
        )
        .await?;

        if !walk_success {
            cleanup_fid(conn, tag, parent_fid).await?;
            return Err(Error::Other(format!(
                "parent directory not found for: {path}",
            )));
        }

        let create_msg = Tcreate {
            fid: parent_fid,
            name: filename,
            perm: 0o644,
            mode: 1, // OWRITE
        };
        send_message(
            conn,
            TaggedMessage {
                message: Message::Tcreate(create_msg),
                tag,
            },
        )
        .await?;

        let response = receive_message(conn).await?;
        match response.message {
            Message::Rcreate(_) => Ok((parent_fid, 0)),
            Message::Rerror(err) => Err(Error::Other(format!(
                "failed to create file '{}': {}",
                path, err.ename
            ))),
            _ => Err(Error::Other("unexpected response to Tcreate".into())),
        }
    }
}

async fn write_data_to_file(
    conn: &mut Connection,
    tag: u16,
    fid: u32,
    data: &[u8],
    start_offset: u64,
    msize: u32,
) -> Result<()> {
    let protocol_overhead = 100;
    let max_count = if msize > protocol_overhead {
        (msize - protocol_overhead) as usize
    } else {
        4096
    };

    let mut offset = start_offset;
    let mut bytes_written = 0;

    while bytes_written < data.len() {
        let chunk_size = std::cmp::min(max_count, data.len() - bytes_written);
        let chunk = data[bytes_written..bytes_written + chunk_size].to_vec();

        let write_msg = Message::Twrite(Twrite {
            fid,
            offset,
            data: bytes::Bytes::from(chunk),
        });
        send_message(
            conn,
            TaggedMessage {
                message: write_msg,
                tag,
            },
        )
        .await?;

        let response = receive_message(conn).await?;
        match response.message {
            Message::Rwrite(rwrite) => {
                if rwrite.count == 0 {
                    return Err(Error::Other("write failed: server wrote 0 bytes".into()));
                }
                bytes_written += rwrite.count as usize;
                offset += u64::from(rwrite.count);
            }
            Message::Rerror(err) => {
                return Err(Error::Other(format!(
                    "failed to write to file: {}",
                    err.ename
                )));
            }
            _ => return Err(Error::Other("unexpected response to Twrite".into())),
        }
    }

    Ok(())
}

async fn cat_command(conn: &mut Connection, tag: u16, path: String, msize: u32) -> Result<()> {
    info!("running: cat {path}");

    let mut root_fid = 2;
    let components = parse_path_components(&path);

    if components.is_empty() {
        return Err(Error::Other(format!("cat: {path}: Is a directory")));
    }

    let walk_success = walk_to_path(conn, tag, root_fid, root_fid + 1, &path).await?;
    if !walk_success {
        return Err(Error::Other(format!("file not found: {path}")));
    }
    root_fid += 1;

    // open file for reading
    let open_msg = Topen {
        fid: root_fid,
        mode: 0, // OREAD
    };
    send_message(
        conn,
        TaggedMessage {
            message: Message::Topen(open_msg),
            tag,
        },
    )
    .await?;

    let response = receive_message(conn).await?;
    match response.message {
        Message::Ropen(ropen) => {
            if ropen.qid.qtype & 0x80 != 0 {
                return Err(Error::Other(format!("cat: {path}: Is a directory")));
            }
        }
        Message::Rerror(err) => {
            return Err(Error::Other(format!("failed to open file: {}", err.ename)));
        }
        _ => return Err(Error::Other("unexpected response to Topen".into())),
    }

    read_and_output_file(conn, tag, root_fid, msize).await?;

    cleanup_fid(conn, tag, root_fid).await?;

    Ok(())
}

async fn read_and_output_file(conn: &mut Connection, tag: u16, fid: u32, msize: u32) -> Result<()> {
    let protocol_overhead = 100;
    let max_count = if msize > protocol_overhead {
        msize - protocol_overhead
    } else {
        4096
    };

    let mut offset: u64 = 0;

    loop {
        let tread = TaggedMessage::new(
            tag,
            Message::Tread(Tread {
                fid,
                offset,
                count: max_count,
            }),
        );

        send_message(conn, tread).await?;
        let response = receive_message(conn).await?;

        match response.message {
            Message::Rread(rread) => {
                if rread.data.is_empty() {
                    break; // end of file
                }

                print!("{}", String::from_utf8_lossy(&rread.data));
                offset += rread.data.len() as u64;
            }
            Message::Rerror(err) => {
                return Err(Error::Other(format!("Failed to read file: {}", err.ename)));
            }
            _ => return Err(Error::Other("Unexpected response to Tread".into())),
        }
    }

    Ok(())
}

fn create_updated_stat(_current_stat: &Stat, _atime: u32, _mtime: u32) -> Result<Stat> {
    unimplemented!("stat writing");
}

fn dump_messages_command(path: &PathBuf) -> Result<()> {
    use bytes::BytesMut;
    use std::fs;

    info!("reading 9p messages from: {}", path.display());

    let data = fs::read(path)
        .map_err(|e| Error::Other(format!("failed to read file {}: {}", path.display(), e)))?;

    if data.is_empty() {
        println!("file is empty");
        return Ok(());
    }

    // create decoder and buffer
    let mut codec = MessageCodec::new();
    let mut buf = BytesMut::from(&data[..]);
    let mut message_count = 0;

    // decode messages one by one
    while !buf.is_empty() {
        match codec.decode(&mut buf) {
            Ok(Some(message)) => {
                message_count += 1;

                let direction = match message.message_type().to_u8() {
                    100 | 102 | 104 | 108 | 110 | 112 | 114 | 116 | 118 | 120 | 122 | 124 | 126 => {
                        "<-"
                    }
                    _ => "->",
                };

                println!("{direction} {message}");
                if let Message::Rstat(rstat) = &message.message {
                    println!("{:?}", rstat.stat);
                }
            }
            Ok(None) => {
                // no complete message available
                if !buf.is_empty() {
                    println!("incomplete message data: {} bytes", buf.len());
                }
                break;
            }
            Err(e) => {
                println!("error decoding message: {e}");
                println!("remaining buffer: {} bytes", buf.len());
                break;
            }
        }
    }

    println!("\ntotal messages: {message_count}");
    Ok(())
}
