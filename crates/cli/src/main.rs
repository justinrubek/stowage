use crate::{
    commands::{Commands, ServerCommands},
    error::Result,
};
use bytes::{Buf, BytesMut};
use clap::Parser;
use error::Error;
use futures::{SinkExt, StreamExt};
use std::sync::Arc;
use stowage_filesystems::disk::Handler;
use stowage_proto::{
    consts::P9_NOFID, Message, MessageCodec, ParsedStat, Protocol, TaggedMessage, Tattach, Tauth,
    Tclunk, Tcreate, Topen, Tread, Tversion, Twalk,
};
use stowage_service::Plan9;
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

            let mut conn = Framed::new(stream, MessageCodec::new());

            let version_tag = 0xFFFF;
            let mut msize = 8192;

            // version negotiation
            let version_msg = Message::Tversion(Tversion {
                msize,
                version: String::from("9P2000"),
            });
            let tagged = TaggedMessage {
                message: version_msg,
                tag: version_tag,
            };
            conn.send(tagged).await?;

            if let Some(Ok(msg)) = conn.next().await {
                match msg.message {
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
                    }
                    Message::Rerror(err) => {
                        return Err(Error::Other(format!(
                            "version negotiation failed: {}",
                            err.ename,
                        )));
                    }
                    _ => return Err(Error::Other("unexpected response to Tversion".into())),
                }
            } else {
                return Err(Error::Other("no response to version negotiation".into()));
            }

            let afid = 1;
            let auth_msg = Tauth {
                afid,
                uname: String::from("nobody"),
                aname: String::from(""),
            };
            let tagged = TaggedMessage {
                message: Message::Tauth(auth_msg),
                tag,
            };
            conn.send(tagged).await?;

            let used_afid: u32;
            if let Some(Ok(msg)) = conn.next().await {
                match msg.message {
                    Message::Rauth(_) => {
                        return Err(Error::Other(
                            "authentication required but not supported by this client".into(),
                        ));
                    }
                    Message::Rerror(_) => {
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
                    info!("running: ls {path}");

                    // 1. Attach to filesystem
                    let mut root_fid = 2;
                    let attach_msg = Tattach {
                        fid: root_fid,
                        afid: P9_NOFID, // No authentication
                        uname: String::from("nobody"),
                        aname: String::from(""),
                    };
                    let tagged = TaggedMessage {
                        message: Message::Tattach(attach_msg),
                        tag,
                    };
                    conn.send(tagged).await?;

                    // Handle attach response
                    if let Some(Ok(msg)) = conn.next().await {
                        match msg.message {
                            Message::Rattach(_) => {
                                // Successfully attached
                            }
                            Message::Rerror(err) => {
                                return Err(Error::Other(format!(
                                    "Failed to attach to filesystem: {}",
                                    err.ename
                                )));
                            }
                            _ => return Err(Error::Other("Unexpected response to Tattach".into())),
                        }
                    } else {
                        return Err(Error::Other("No response to attach".into()));
                    }

                    // If we're not at root directory, we need to walk to the target path
                    if path != "/" {
                        let components: Vec<String> = path
                            .split('/')
                            .filter(|s| !s.is_empty())
                            .map(|s| s.to_string())
                            .collect();

                        if !components.is_empty() {
                            let walk_msg = Twalk {
                                fid: root_fid,
                                newfid: root_fid + 1, // Use a new fid for the walked path
                                wnames: components.clone(),
                            };
                            let tagged = TaggedMessage {
                                message: Message::Twalk(walk_msg),
                                tag,
                            };
                            conn.send(tagged).await?;

                            if let Some(Ok(msg)) = conn.next().await {
                                match msg.message {
                                    Message::Rwalk(rwalk) => {
                                        if rwalk.wqids.len() != components.len() {
                                            return Err(Error::Other(format!(
                                                "Path not found: {}",
                                                path
                                            )));
                                        }
                                        // Update the root_fid to our walked fid
                                        root_fid = root_fid + 1;
                                    }
                                    Message::Rerror(err) => {
                                        return Err(Error::Other(format!(
                                            "Failed to walk to path: {}",
                                            err.ename
                                        )));
                                    }
                                    _ => {
                                        return Err(Error::Other(
                                            "Unexpected response to Twalk".into(),
                                        ))
                                    }
                                }
                            } else {
                                return Err(Error::Other("No response to walk".into()));
                            }
                        }
                    }

                    // 2. Open directory
                    let open_msg = Topen {
                        fid: root_fid,
                        mode: 0, // OREAD
                    };
                    let tagged = TaggedMessage {
                        message: Message::Topen(open_msg),
                        tag,
                    };
                    conn.send(tagged).await?;

                    // Handle open response
                    if let Some(Ok(msg)) = conn.next().await {
                        match msg.message {
                            Message::Ropen(_) => {
                                // Directory opened successfully
                            }
                            Message::Rerror(err) => {
                                return Err(Error::Other(format!(
                                    "Failed to open directory: {}",
                                    err.ename
                                )));
                            }
                            _ => return Err(Error::Other("Unexpected response to Topen".into())),
                        }
                    } else {
                        return Err(Error::Other("No response to open".into()));
                    }

                    // 3. Read directory contents
                    // In 9p2000, reading a directory returns a stream of Stat structures
                    let mut offset: u64 = 0;
                    let protocol_overhead = 100;
                    let max_count = if msize > protocol_overhead {
                        msize - protocol_overhead
                    } else {
                        4096
                    };

                    let all_stats: Vec<ParsedStat> = Vec::new();

                    let mut offset = 0u64;

                    loop {
                        // Send Tread request with current offset
                        let tread = TaggedMessage::new(
                            tag,
                            Message::Tread(Tread {
                                fid: root_fid,
                                offset,
                                count: max_count,
                            }),
                        );

                        conn.send(tread).await?;

                        if let Some(Ok(msg)) = conn.next().await {
                            match msg.message {
                                Message::Rread(rread) => {
                                    match rread.data.len() {
                                        0 => break, // no more data - END OF DIRECTORY
                                        _ => {
                                            let data_len = rread.data.len();

                                            // parse each stat entry from the raw bytes
                                            let mut bytes = BytesMut::from(&rread.data[..]);

                                            while !bytes.is_empty() {
                                                if bytes.len() < 2 {
                                                    break;
                                                }

                                                let stat_size =
                                                    u16::from_le_bytes([bytes[0], bytes[1]])
                                                        as usize;
                                                if bytes.len() < stat_size + 2 {
                                                    break;
                                                }

                                                let stat_bytes = bytes.split_to(stat_size + 2);

                                                match ParsedStat::from_bytes(&stat_bytes.freeze()) {
                                                    Ok(stat) => {
                                                        println!(
                                                            "{:>8} {} {}",
                                                            stat.length,
                                                            stat.name,
                                                            if stat.mode & 0x80000000 != 0 {
                                                                "/"
                                                            } else {
                                                                ""
                                                            }
                                                        );
                                                    }
                                                    Err(e) => {
                                                        eprintln!(
                                                            "Warning: Failed to parse stat: {}",
                                                            e
                                                        );
                                                        break;
                                                    }
                                                }
                                            }

                                            // critical: Advance the offset for the next read
                                            offset += data_len as u64;
                                        }
                                    }
                                }
                                Message::Rerror(err) => {
                                    return Err(Error::Other(format!(
                                        "Failed to read directory: {}",
                                        err.ename
                                    )));
                                }
                                _ => {
                                    return Err(Error::Other("Unexpected response to Tread".into()))
                                }
                            }
                        } else {
                            return Err(Error::Other("Connection closed".into()));
                        }
                    }

                    // 4. clunk the fid
                    let clunk_msg = Tclunk { fid: root_fid };
                    let tagged = TaggedMessage {
                        message: Message::Tclunk(clunk_msg),
                        tag,
                    };
                    conn.send(tagged).await?;

                    // handle clunk response (optional, but good practice)
                    if let Some(Ok(msg)) = conn.next().await {
                        match msg.message {
                            Message::Rclunk(_) => {
                                // successfully closed directory
                            }
                            Message::Rerror(err) => {
                                // non-fatal error
                                eprintln!("Warning: Failed to clunk fid: {}", err.ename);
                            }
                            _ => {
                                // non-fatal error
                                eprintln!("Warning: Unexpected response to Tclunk");
                            }
                        }
                    }

                    // Display results
                    println!("Directory listing for {path}:");
                    for stat in all_stats {
                        // FIX 6: Use stat.qid.qtype instead of stat.qtype
                        let type_char = if stat.qid.qtype & 0x80 != 0 { 'd' } else { '-' };
                        println!("{}{} {} bytes", type_char, stat.name, stat.length);
                    }

                    Ok(())
                }

                commands::FileCommands::Mkdir { path, parents } => {
                    info!("running: mkdir {path}");

                    // 1. attach to filesystem
                    let root_fid = 2;
                    let attach_msg = Tattach {
                        fid: root_fid,
                        afid: P9_NOFID,
                        uname: String::from("nobody"),
                        aname: String::from(""),
                    };
                    let tagged = TaggedMessage {
                        message: Message::Tattach(attach_msg),
                        tag,
                    };
                    conn.send(tagged).await?;

                    // handle attach response
                    if let Some(Ok(msg)) = conn.next().await {
                        match msg.message {
                            Message::Rattach(_) => {}
                            Message::Rerror(err) => {
                                return Err(Error::Other(format!(
                                    "Failed to attach to filesystem: {}",
                                    err.ename
                                )));
                            }
                            _ => return Err(Error::Other("Unexpected response to Tattach".into())),
                        }
                    } else {
                        return Err(Error::Other("No response to attach".into()));
                    }

                    // 2. parse the full path into components
                    let path = path.trim_end_matches('/');
                    let components: Vec<String> = path
                        .split('/')
                        .filter(|s| !s.is_empty())
                        .map(|s| s.to_string())
                        .collect();

                    if components.is_empty() {
                        return Err(Error::Other("Cannot create root directory".into()));
                    }

                    // 3. find how far we can walk, then create what's missing
                    let mut existing_depth = 0;

                    // try to walk the full path to see how much exists
                    for i in 1..=components.len() {
                        let partial_components = components[0..i].to_vec();

                        let walk_msg = Twalk {
                            fid: root_fid,
                            newfid: root_fid + 1,
                            wnames: partial_components.clone(),
                        };
                        let tagged = TaggedMessage {
                            message: Message::Twalk(walk_msg),
                            tag,
                        };
                        conn.send(tagged).await?;

                        if let Some(Ok(msg)) = conn.next().await {
                            match msg.message {
                                Message::Rwalk(rwalk) => {
                                    if rwalk.wqids.len() == partial_components.len() {
                                        // this path exists
                                        existing_depth = i;

                                        // if this is the full path, it already exists
                                        if i == components.len() {
                                            return Err(Error::Other(format!(
                                                "mkdir: cannot create directory '{}': File exists",
                                                path
                                            )));
                                        }

                                        // clunk the temporary fid
                                        let clunk_msg = Tclunk { fid: root_fid + 1 };
                                        let tagged = TaggedMessage {
                                            message: Message::Tclunk(clunk_msg),
                                            tag,
                                        };
                                        conn.send(tagged).await?;
                                        if let Some(Ok(_)) = conn.next().await {}
                                    } else {
                                        // this path doesn't fully exist
                                        // clunk the temporary fid
                                        let clunk_msg = Tclunk { fid: root_fid + 1 };
                                        let tagged = TaggedMessage {
                                            message: Message::Tclunk(clunk_msg),
                                            tag,
                                        };
                                        conn.send(tagged).await?;
                                        if let Some(Ok(_)) = conn.next().await {}
                                        break;
                                    }
                                }
                                Message::Rerror(_) => {
                                    // path doesn't exist at all
                                    break;
                                }
                                _ => {
                                    return Err(Error::Other("Unexpected response to Twalk".into()))
                                }
                            }
                        } else {
                            return Err(Error::Other("No response to walk".into()));
                        }
                    }

                    // check if we need -p flag
                    if existing_depth < components.len() - 1 && !parents {
                        return Err(Error::Other(format!(
                            "mkdir: cannot create directory '{}': No such file or directory",
                            path
                        )));
                    }

                    // 4. create missing directories one by one
                    for i in existing_depth..components.len() {
                        // walk to the parent directory
                        let parent_components = if i == 0 {
                            vec![]
                        } else {
                            components[0..i].to_vec()
                        };

                        let parent_fid = root_fid + 2;

                        if parent_components.is_empty() {
                            // creating in root - use root_fid directly
                            let create_msg = Tcreate {
                                fid: root_fid,
                                name: components[i].clone(),
                                perm: 0o755 | 0x80000000, // directory permissions with DMDIR bit
                                mode: 0,                  // OREAD
                            };
                            let tagged = TaggedMessage {
                                message: Message::Tcreate(create_msg),
                                tag,
                            };
                            conn.send(tagged).await?;

                            if let Some(Ok(msg)) = conn.next().await {
                                match msg.message {
                                    Message::Rcreate(_) => {
                                        // success - but we need to clunk this opened fid if we're not done
                                        if i < components.len() - 1 {
                                            let clunk_msg = Tclunk { fid: root_fid };
                                            let tagged = TaggedMessage {
                                                message: Message::Tclunk(clunk_msg),
                                                tag,
                                            };
                                            conn.send(tagged).await?;
                                            if let Some(Ok(_)) = conn.next().await {}
                                        }
                                    }
                                    Message::Rerror(err) => {
                                        return Err(Error::Other(format!(
                                            "Failed to create directory '{}': {}",
                                            components[i], err.ename
                                        )));
                                    }
                                    _ => {
                                        return Err(Error::Other(
                                            "Unexpected response to Tcreate".into(),
                                        ))
                                    }
                                }
                            } else {
                                return Err(Error::Other("No response to create".into()));
                            }
                        } else {
                            // walk to parent directory
                            let walk_msg = Twalk {
                                fid: root_fid,
                                newfid: parent_fid,
                                wnames: parent_components,
                            };
                            let tagged = TaggedMessage {
                                message: Message::Twalk(walk_msg),
                                tag,
                            };
                            conn.send(tagged).await?;

                            if let Some(Ok(msg)) = conn.next().await {
                                match msg.message {
                                    Message::Rwalk(_) => {
                                        // now create the directory in the parent
                                        let create_msg = Tcreate {
                                            fid: parent_fid,
                                            name: components[i].clone(),
                                            perm: 0o755 | 0x80000000, // directory permissions with DMDIR bit
                                            mode: 0,                  // OREAD
                                        };
                                        let tagged = TaggedMessage {
                                            message: Message::Tcreate(create_msg),
                                            tag,
                                        };
                                        conn.send(tagged).await?;

                                        if let Some(Ok(msg)) = conn.next().await {
                                            match msg.message {
                                                Message::Rcreate(_) => {
                                                    // success - clunk the opened fid
                                                    let clunk_msg = Tclunk { fid: parent_fid };
                                                    let tagged = TaggedMessage {
                                                        message: Message::Tclunk(clunk_msg),
                                                        tag,
                                                    };
                                                    conn.send(tagged).await?;
                                                    if let Some(Ok(_)) = conn.next().await {}
                                                }
                                                Message::Rerror(err) => {
                                                    return Err(Error::Other(format!(
                                                        "Failed to create directory '{}': {}",
                                                        components[i], err.ename
                                                    )));
                                                }
                                                _ => {
                                                    return Err(Error::Other(
                                                        "Unexpected response to Tcreate".into(),
                                                    ))
                                                }
                                            }
                                        } else {
                                            return Err(Error::Other(
                                                "No response to create".into(),
                                            ));
                                        }
                                    }
                                    Message::Rerror(err) => {
                                        return Err(Error::Other(format!(
                                            "Failed to walk to parent directory: {}",
                                            err.ename
                                        )));
                                    }
                                    _ => {
                                        return Err(Error::Other(
                                            "Unexpected response to Twalk".into(),
                                        ))
                                    }
                                }
                            } else {
                                return Err(Error::Other("No response to walk".into()));
                            }
                        }
                    }

                    println!("Directory created: {}", path);
                    Ok(())
                }

                commands::FileCommands::Cat { path } => {
                    info!("running: cat {path}");

                    // 1. attach to filesystem
                    let mut root_fid = 2;
                    let attach_msg = Tattach {
                        fid: root_fid,
                        afid: P9_NOFID,
                        uname: String::from("nobody"),
                        aname: String::from(""),
                    };
                    let tagged = TaggedMessage {
                        message: Message::Tattach(attach_msg),
                        tag,
                    };
                    conn.send(tagged).await?;

                    // handle attach response
                    if let Some(Ok(msg)) = conn.next().await {
                        match msg.message {
                            Message::Rattach(_) => {
                                // successfully attached
                            }
                            Message::Rerror(err) => {
                                return Err(Error::Other(format!(
                                    "Failed to attach to filesystem: {}",
                                    err.ename
                                )));
                            }
                            _ => return Err(Error::Other("Unexpected response to Tattach".into())),
                        }
                    } else {
                        return Err(Error::Other("No response to attach".into()));
                    }

                    // 2. walk to the target file path
                    let components: Vec<String> = path
                        .split('/')
                        .filter(|s| !s.is_empty())
                        .map(|s| s.to_string())
                        .collect();

                    if !components.is_empty() {
                        let walk_msg = Twalk {
                            fid: root_fid,
                            newfid: root_fid + 1,
                            wnames: components.clone(),
                        };
                        let tagged = TaggedMessage {
                            message: Message::Twalk(walk_msg),
                            tag,
                        };
                        conn.send(tagged).await?;

                        if let Some(Ok(msg)) = conn.next().await {
                            match msg.message {
                                Message::Rwalk(rwalk) => {
                                    if rwalk.wqids.len() != components.len() {
                                        return Err(Error::Other(format!(
                                            "File not found: {}",
                                            path
                                        )));
                                    }
                                    // check if the target is a directory by examining the last qid
                                    if let Some(last_qid) = rwalk.wqids.last() {
                                        if last_qid.qtype & 0x80 != 0 {
                                            // QTDIR bit
                                            return Err(Error::Other(format!(
                                                "cat: {}: Is a directory",
                                                path
                                            )));
                                        }
                                    }
                                    // update the root_fid to our walked fid
                                    root_fid = root_fid + 1;
                                }
                                Message::Rerror(err) => {
                                    return Err(Error::Other(format!(
                                        "Failed to walk to file: {}",
                                        err.ename
                                    )));
                                }
                                _ => {
                                    return Err(Error::Other("Unexpected response to Twalk".into()))
                                }
                            }
                        } else {
                            return Err(Error::Other("No response to walk".into()));
                        }
                    } else {
                        // root directory case
                        return Err(Error::Other(format!("cat: {}: Is a directory", path)));
                    }

                    // 3. open file for reading
                    let open_msg = Topen {
                        fid: root_fid,
                        mode: 0, // OREAD
                    };
                    let tagged = TaggedMessage {
                        message: Message::Topen(open_msg),
                        tag,
                    };
                    conn.send(tagged).await?;

                    // handle open response and double-check if it's a directory
                    if let Some(Ok(msg)) = conn.next().await {
                        match msg.message {
                            Message::Ropen(ropen) => {
                                // double-check: if qid indicates directory, return error
                                if ropen.qid.qtype & 0x80 != 0 {
                                    // QTDIR bit
                                    return Err(Error::Other(format!(
                                        "cat: {}: Is a directory",
                                        path
                                    )));
                                }
                                // File opened successfully
                            }
                            Message::Rerror(err) => {
                                return Err(Error::Other(format!(
                                    "Failed to open file: {}",
                                    err.ename
                                )));
                            }
                            _ => return Err(Error::Other("Unexpected response to Topen".into())),
                        }
                    } else {
                        return Err(Error::Other("No response to open".into()));
                    }

                    // 4. read file contents
                    let mut offset: u64 = 0;
                    let protocol_overhead = 100;
                    let max_count = if msize > protocol_overhead {
                        msize - protocol_overhead
                    } else {
                        4096
                    };

                    loop {
                        // send Tread request with current offset
                        let tread = TaggedMessage::new(
                            tag,
                            Message::Tread(Tread {
                                fid: root_fid,
                                offset,
                                count: max_count,
                            }),
                        );

                        conn.send(tread).await?;

                        if let Some(Ok(msg)) = conn.next().await {
                            match msg.message {
                                Message::Rread(rread) => {
                                    match rread.data.len() {
                                        0 => break, // end of file
                                        _ => {
                                            // print the raw file content to stdout
                                            print!("{}", String::from_utf8_lossy(&rread.data));

                                            // advance offset for next read
                                            offset += rread.data.len() as u64;
                                        }
                                    }
                                }
                                Message::Rerror(err) => {
                                    return Err(Error::Other(format!(
                                        "Failed to read file: {}",
                                        err.ename
                                    )));
                                }
                                _ => {
                                    return Err(Error::Other("Unexpected response to Tread".into()))
                                }
                            }
                        } else {
                            return Err(Error::Other("Connection closed".into()));
                        }
                    }

                    // 5. clunk the fid
                    let clunk_msg = Tclunk { fid: root_fid };
                    let tagged = TaggedMessage {
                        message: Message::Tclunk(clunk_msg),
                        tag,
                    };
                    conn.send(tagged).await?;

                    // handle clunk response (optional, but good practice)
                    if let Some(Ok(msg)) = conn.next().await {
                        match msg.message {
                            Message::Rclunk(_) => {
                                // successfully closed file
                            }
                            Message::Rerror(err) => {
                                // non-fatal error
                                eprintln!("Warning: Failed to clunk fid: {}", err.ename);
                            }
                            _ => {
                                // non-fatal error
                                eprintln!("Warning: Unexpected response to Tclunk");
                            }
                        }
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
