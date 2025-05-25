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
    Tclunk, Tcreate, Topen, Tread, Tstat, Tversion, Twalk, Twrite, Twstat,
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

                commands::FileCommands::Touch { path } => {
                    info!("running: touch {path}");

                    // 1. Attach to filesystem
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

                    // Handle attach response
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

                    // 2. Parse the path into components
                    let components: Vec<String> = path
                        .split('/')
                        .filter(|s| !s.is_empty())
                        .map(|s| s.to_string())
                        .collect();

                    if components.is_empty() {
                        return Err(Error::Other("Cannot touch root directory".into()));
                    }

                    // 3. Try to walk to the full path to see if file exists
                    let file_fid = root_fid + 1;
                    let walk_msg = Twalk {
                        fid: root_fid,
                        newfid: file_fid,
                        wnames: components.clone(),
                    };
                    let tagged = TaggedMessage {
                        message: Message::Twalk(walk_msg),
                        tag,
                    };
                    conn.send(tagged).await?;

                    let file_exists = if let Some(Ok(msg)) = conn.next().await {
                        match msg.message {
                            Message::Rwalk(rwalk) => {
                                if rwalk.wqids.len() == components.len() {
                                    // File exists - check if it's a directory
                                    if let Some(last_qid) = rwalk.wqids.last() {
                                        if last_qid.qtype & 0x80 != 0 {
                                            // QTDIR bit - it's a directory
                                            // Clean up the fid before returning error
                                            let clunk_msg = Tclunk { fid: file_fid };
                                            let tagged = TaggedMessage {
                                                message: Message::Tclunk(clunk_msg),
                                                tag,
                                            };
                                            conn.send(tagged).await?;
                                            if let Some(Ok(_)) = conn.next().await {}

                                            return Err(Error::Other(format!(
                                                "touch: {}: Is a directory",
                                                path
                                            )));
                                        }
                                    }
                                    true
                                } else {
                                    // Partial walk - file doesn't exist, but we may have walked partway
                                    // Clean up the partial fid
                                    let clunk_msg = Tclunk { fid: file_fid };
                                    let tagged = TaggedMessage {
                                        message: Message::Tclunk(clunk_msg),
                                        tag,
                                    };
                                    conn.send(tagged).await?;
                                    if let Some(Ok(_)) = conn.next().await {}
                                    false
                                }
                            }
                            Message::Rerror(_) => false, // File doesn't exist
                            _ => return Err(Error::Other("Unexpected response to Twalk".into())),
                        }
                    } else {
                        return Err(Error::Other("No response to walk".into()));
                    };

                    if file_exists {
                        // File exists - update access and modification times using Twstat

                        // Get current stat to preserve other fields
                        let stat_msg = Message::Tstat(Tstat { fid: file_fid });
                        let tagged = TaggedMessage {
                            message: stat_msg,
                            tag,
                        };
                        conn.send(tagged).await?;

                        let update_result = if let Some(Ok(msg)) = conn.next().await {
                            match msg.message {
                                Message::Rstat(rstat) => {
                                    // Parse the current stat
                                    match ParsedStat::from_bytes(&rstat.stat) {
                                        Ok(current_stat) => {
                                            // Get current time (Unix timestamp)
                                            let current_time = std::time::SystemTime::now()
                                                .duration_since(std::time::UNIX_EPOCH)
                                                .unwrap()
                                                .as_secs()
                                                as u32;

                                            // Create updated stat with new times
                                            match create_updated_stat_bytes(
                                                &current_stat,
                                                current_time,
                                                current_time,
                                            ) {
                                                Ok(updated_stat) => {
                                                    // Send Twstat to update the file metadata
                                                    let wstat_msg = Message::Twstat(Twstat {
                                                        fid: file_fid,
                                                        stat: updated_stat,
                                                    });
                                                    let tagged = TaggedMessage {
                                                        message: wstat_msg,
                                                        tag,
                                                    };
                                                    conn.send(tagged).await?;

                                                    if let Some(Ok(msg)) = conn.next().await {
                                                        match msg.message {
                                                            Message::Rwstat(_) => Ok(()),
                                                            Message::Rerror(err) => Err(format!(
                                                                "Server rejected stat update: {}",
                                                                err.ename
                                                            )),
                                                            _ => {
                                                                Err("Unexpected response to Twstat"
                                                                    .into())
                                                            }
                                                        }
                                                    } else {
                                                        Err("No response to wstat".into())
                                                    }
                                                }
                                                Err(e) => Err(format!(
                                                    "Failed to create updated stat: {}",
                                                    e
                                                )),
                                            }
                                        }
                                        Err(e) => {
                                            Err(format!("Failed to parse current stat: {}", e))
                                        }
                                    }
                                }
                                Message::Rerror(err) => {
                                    Err(format!("Failed to get file stat: {}", err.ename))
                                }
                                _ => Err("Unexpected response to Tstat".into()),
                            }
                        } else {
                            Err("No response to stat".into())
                        };

                        // Clean up the fid
                        let clunk_msg = Tclunk { fid: file_fid };
                        let tagged = TaggedMessage {
                            message: Message::Tclunk(clunk_msg),
                            tag,
                        };
                        conn.send(tagged).await?;
                        if let Some(Ok(_)) = conn.next().await {}

                        // Handle the update result
                        match update_result {
                            Ok(()) => {
                                println!("Updated access and modification times for: {}", path);
                            }
                            Err(err_msg) => {
                                // Some servers don't support Twstat or time updates - fall back gracefully
                                eprintln!("Warning: Could not update file times: {}", err_msg);
                                println!("File exists: {}", path);
                            }
                        }
                    } else {
                        // File doesn't exist - create it

                        // Parse parent directory and filename
                        let (parent_components, filename) = if components.len() > 1 {
                            (
                                components[0..components.len() - 1].to_vec(),
                                components.last().unwrap().clone(),
                            )
                        } else {
                            (vec![], components[0].clone())
                        };

                        if parent_components.is_empty() {
                            // Creating in root directory - use root_fid directly
                            let create_msg = Tcreate {
                                fid: root_fid,
                                name: filename,
                                perm: 0o644, // Regular file permissions
                                mode: 2,     // OWRITE to create and immediately close
                            };
                            let tagged = TaggedMessage {
                                message: Message::Tcreate(create_msg),
                                tag,
                            };
                            conn.send(tagged).await?;

                            if let Some(Ok(msg)) = conn.next().await {
                                match msg.message {
                                    Message::Rcreate(_) => {
                                        // Success - immediately clunk the opened file
                                        let clunk_msg = Tclunk { fid: root_fid };
                                        let tagged = TaggedMessage {
                                            message: Message::Tclunk(clunk_msg),
                                            tag,
                                        };
                                        conn.send(tagged).await?;
                                        if let Some(Ok(_)) = conn.next().await {}

                                        println!("File created: {}", path);
                                    }
                                    Message::Rerror(err) => {
                                        return Err(Error::Other(format!(
                                            "Failed to create file '{}': {}",
                                            path, err.ename
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
                            // Walk to parent directory first
                            let parent_fid = root_fid + 2;
                            let walk_msg = Twalk {
                                fid: root_fid,
                                newfid: parent_fid,
                                wnames: parent_components.clone(),
                            };
                            let tagged = TaggedMessage {
                                message: Message::Twalk(walk_msg),
                                tag,
                            };
                            conn.send(tagged).await?;

                            if let Some(Ok(msg)) = conn.next().await {
                                match msg.message {
                                    Message::Rwalk(rwalk) => {
                                        if rwalk.wqids.len() != parent_components.len() {
                                            // Clean up the partial fid
                                            let clunk_msg = Tclunk { fid: parent_fid };
                                            let tagged = TaggedMessage {
                                                message: Message::Tclunk(clunk_msg),
                                                tag,
                                            };
                                            conn.send(tagged).await?;
                                            if let Some(Ok(_)) = conn.next().await {}

                                            return Err(Error::Other(format!(
                                                "Parent directory not found for: {}",
                                                path
                                            )));
                                        }

                                        // Now create the file in the parent directory
                                        let create_msg = Tcreate {
                                            fid: parent_fid,
                                            name: filename,
                                            perm: 0o644, // Regular file permissions
                                            mode: 2,     // OWRITE to create and immediately close
                                        };
                                        let tagged = TaggedMessage {
                                            message: Message::Tcreate(create_msg),
                                            tag,
                                        };
                                        conn.send(tagged).await?;

                                        let create_result = if let Some(Ok(msg)) = conn.next().await
                                        {
                                            match msg.message {
                                                Message::Rcreate(_) => Ok(()),
                                                Message::Rerror(err) => Err(format!(
                                                    "Failed to create file '{}': {}",
                                                    path, err.ename
                                                )),
                                                _ => Err("Unexpected response to Tcreate".into()),
                                            }
                                        } else {
                                            Err("No response to create".into())
                                        };

                                        // Always clean up the parent fid
                                        let clunk_msg = Tclunk { fid: parent_fid };
                                        let tagged = TaggedMessage {
                                            message: Message::Tclunk(clunk_msg),
                                            tag,
                                        };
                                        conn.send(tagged).await?;
                                        if let Some(Ok(_)) = conn.next().await {}

                                        // Check create result
                                        match create_result {
                                            Ok(()) => println!("File created: {}", path),
                                            Err(err_msg) => {
                                                return Err(Error::Other(err_msg));
                                            }
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

                    Ok(())
                }

                commands::FileCommands::Write { path, data, append } => {
                    info!("running: write {path} (append: {append})");

                    // 1. get data from command line or stdin
                    let write_data = if let Some(data) = data {
                        data.into_bytes()
                    } else {
                        use std::io::Read;
                        let mut buffer = Vec::new();
                        std::io::stdin().read_to_end(&mut buffer)?;
                        buffer
                    };

                    // 2. attach to filesystem
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

                    // 3. parse path components
                    let components: Vec<String> = path
                        .split('/')
                        .filter(|s| !s.is_empty())
                        .map(|s| s.to_string())
                        .collect();

                    if components.is_empty() {
                        return Err(Error::Other("Cannot write to root directory".into()));
                    }

                    // 4. try to walk to the file
                    let file_fid = root_fid + 1;
                    let walk_msg = Twalk {
                        fid: root_fid,
                        newfid: file_fid,
                        wnames: components.clone(),
                    };
                    let tagged = TaggedMessage {
                        message: Message::Twalk(walk_msg),
                        tag,
                    };
                    conn.send(tagged).await?;

                    let file_exists = if let Some(Ok(msg)) = conn.next().await {
                        match msg.message {
                            Message::Rwalk(rwalk) => {
                                if rwalk.wqids.len() == components.len() {
                                    // check if it's a directory
                                    if let Some(last_qid) = rwalk.wqids.last() {
                                        if last_qid.qtype & 0x80 != 0 {
                                            // clean up fid
                                            let clunk_msg = Tclunk { fid: file_fid };
                                            let tagged = TaggedMessage {
                                                message: Message::Tclunk(clunk_msg),
                                                tag,
                                            };
                                            conn.send(tagged).await?;
                                            if let Some(Ok(_)) = conn.next().await {}

                                            return Err(Error::Other(format!(
                                                "write: {}: Is a directory",
                                                path
                                            )));
                                        }
                                    }
                                    true
                                } else {
                                    // clean up partial fid
                                    let clunk_msg = Tclunk { fid: file_fid };
                                    let tagged = TaggedMessage {
                                        message: Message::Tclunk(clunk_msg),
                                        tag,
                                    };
                                    conn.send(tagged).await?;
                                    if let Some(Ok(_)) = conn.next().await {}
                                    false
                                }
                            }
                            Message::Rerror(_) => false,
                            _ => return Err(Error::Other("Unexpected response to Twalk".into())),
                        }
                    } else {
                        return Err(Error::Other("No response to walk".into()));
                    };

                    let (write_fid, start_offset) = if file_exists {
                        // 5a. file exists - open for writing
                        let open_msg = Topen {
                            fid: file_fid,
                            mode: 1, // OWRITE (always just write mode - we'll handle append manually)
                        };
                        let tagged = TaggedMessage {
                            message: Message::Topen(open_msg),
                            tag,
                        };
                        conn.send(tagged).await?;

                        if let Some(Ok(msg)) = conn.next().await {
                            match msg.message {
                                Message::Ropen(_) => {
                                    // if append mode, get file size to determine where to start writing
                                    let offset = if append {
                                        let stat_msg = Message::Tstat(Tstat { fid: file_fid });
                                        let tagged = TaggedMessage {
                                            message: stat_msg,
                                            tag,
                                        };
                                        conn.send(tagged).await?;

                                        if let Some(Ok(msg)) = conn.next().await {
                                            match msg.message {
                                                Message::Rstat(rstat) => {
                                                    match get_file_length_from_stat(&rstat.stat) {
                                                        Ok(length) => {
                                                            println!(
                                                                "DEBUG: File size for append: {}",
                                                                length
                                                            );
                                                            length
                                                        }
                                                        Err(e) => {
                                                            eprintln!("Warning: Could not parse file length: {}, starting at offset 0", e);
                                                            0
                                                        }
                                                    }
                                                }
                                                Message::Rerror(err) => {
                                                    eprintln!("Warning: Could not stat file for append: {}, starting at offset 0", err.ename);
                                                    0
                                                }
                                                _ => {
                                                    eprintln!("Warning: Unexpected response to Tstat, starting at offset 0");
                                                    0
                                                }
                                            }
                                        } else {
                                            eprintln!("Warning: No response to stat, starting at offset 0");
                                            0
                                        }
                                    } else {
                                        0
                                    };

                                    (file_fid, offset)
                                }
                                Message::Rerror(err) => {
                                    return Err(Error::Other(format!(
                                        "Failed to open file for writing: {}",
                                        err.ename
                                    )));
                                }
                                _ => {
                                    return Err(Error::Other("Unexpected response to Topen".into()))
                                }
                            }
                        } else {
                            return Err(Error::Other("No response to open".into()));
                        }
                    } else {
                        // 5b. file doesn't exist - create it
                        let (parent_components, filename) = if components.len() > 1 {
                            (
                                components[0..components.len() - 1].to_vec(),
                                components.last().unwrap().clone(),
                            )
                        } else {
                            (vec![], components[0].clone())
                        };

                        let created_fid = if parent_components.is_empty() {
                            // creating in root directory
                            let create_msg = Tcreate {
                                fid: root_fid,
                                name: filename,
                                perm: 0o644, // regular file permissions
                                mode: 1,     // OWRITE
                            };
                            let tagged = TaggedMessage {
                                message: Message::Tcreate(create_msg),
                                tag,
                            };
                            conn.send(tagged).await?;

                            if let Some(Ok(msg)) = conn.next().await {
                                match msg.message {
                                    Message::Rcreate(_) => root_fid,
                                    Message::Rerror(err) => {
                                        return Err(Error::Other(format!(
                                            "Failed to create file '{}': {}",
                                            path, err.ename
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
                            // walk to parent directory first
                            let parent_fid = root_fid + 2;
                            let walk_msg = Twalk {
                                fid: root_fid,
                                newfid: parent_fid,
                                wnames: parent_components.clone(),
                            };
                            let tagged = TaggedMessage {
                                message: Message::Twalk(walk_msg),
                                tag,
                            };
                            conn.send(tagged).await?;

                            if let Some(Ok(msg)) = conn.next().await {
                                match msg.message {
                                    Message::Rwalk(rwalk) => {
                                        if rwalk.wqids.len() != parent_components.len() {
                                            // Clean up partial fid
                                            let clunk_msg = Tclunk { fid: parent_fid };
                                            let tagged = TaggedMessage {
                                                message: Message::Tclunk(clunk_msg),
                                                tag,
                                            };
                                            conn.send(tagged).await?;
                                            if let Some(Ok(_)) = conn.next().await {}

                                            return Err(Error::Other(format!(
                                                "Parent directory not found for: {}",
                                                path
                                            )));
                                        }

                                        // Create file in parent directory
                                        let create_msg = Tcreate {
                                            fid: parent_fid,
                                            name: filename,
                                            perm: 0o644,
                                            mode: 1, // OWRITE
                                        };
                                        let tagged = TaggedMessage {
                                            message: Message::Tcreate(create_msg),
                                            tag,
                                        };
                                        conn.send(tagged).await?;

                                        if let Some(Ok(msg)) = conn.next().await {
                                            match msg.message {
                                                Message::Rcreate(_) => parent_fid,
                                                Message::Rerror(err) => {
                                                    return Err(Error::Other(format!(
                                                        "Failed to create file '{}': {}",
                                                        path, err.ename
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
                        };

                        (created_fid, 0u64) // new file starts at offset 0
                    };

                    // 6. write data in chunks
                    let protocol_overhead = 100;
                    let max_count = if msize > protocol_overhead {
                        (msize - protocol_overhead) as usize
                    } else {
                        4096
                    };

                    let mut offset = start_offset;
                    let mut bytes_written = 0;

                    while bytes_written < write_data.len() {
                        let chunk_size = std::cmp::min(max_count, write_data.len() - bytes_written);
                        let chunk = write_data[bytes_written..bytes_written + chunk_size].to_vec();

                        let write_msg = Message::Twrite(Twrite {
                            fid: write_fid,
                            offset: offset,
                            data: bytes::Bytes::from(chunk),
                        });
                        let tagged = TaggedMessage {
                            message: write_msg,
                            tag,
                        };
                        conn.send(tagged).await?;

                        if let Some(Ok(msg)) = conn.next().await {
                            match msg.message {
                                Message::Rwrite(rwrite) => {
                                    if rwrite.count == 0 {
                                        return Err(Error::Other(
                                            "Write failed: server wrote 0 bytes".into(),
                                        ));
                                    }
                                    bytes_written += rwrite.count as usize;
                                    offset += rwrite.count as u64;
                                }
                                Message::Rerror(err) => {
                                    return Err(Error::Other(format!(
                                        "Failed to write to file: {}",
                                        err.ename
                                    )));
                                }
                                _ => {
                                    return Err(Error::Other(
                                        "Unexpected response to Twrite".into(),
                                    ))
                                }
                            }
                        } else {
                            return Err(Error::Other("No response to write".into()));
                        }
                    }

                    // 7. clunk the fid
                    let clunk_msg = Tclunk { fid: write_fid };
                    let tagged = TaggedMessage {
                        message: Message::Tclunk(clunk_msg),
                        tag,
                    };
                    conn.send(tagged).await?;

                    if let Some(Ok(msg)) = conn.next().await {
                        match msg.message {
                            Message::Rclunk(_) => {}
                            Message::Rerror(err) => {
                                eprintln!("Warning: Failed to clunk fid: {}", err.ename);
                            }
                            _ => {
                                eprintln!("Warning: Unexpected response to Tclunk");
                            }
                        }
                    }

                    let mode_str = if append { "appended" } else { "wrote" };
                    println!("{} {} bytes to {}", mode_str, bytes_written, path);
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

fn create_updated_stat_bytes(
    current_stat: &ParsedStat,
    atime: u32,
    mtime: u32,
) -> Result<bytes::Bytes> {
    unimplemented!("stat writing");
}

fn get_file_length_from_stat(
    stat_bytes: &[u8],
) -> std::result::Result<u64, Box<dyn std::error::Error>> {
    // 9P stat structure layout (after size prefix):
    // type[2] + dev[4] + qid[13] + mode[4] + atime[4] + mtime[4] + length[8] + ...
    // Length field starts at byte offset 35 (2+4+13+4+4+4+4 = 35)
    const LENGTH_OFFSET: usize = 35;

    if stat_bytes.len() < LENGTH_OFFSET + 8 {
        return Err("Stat bytes too short to contain length field".into());
    }

    let length_bytes = &stat_bytes[LENGTH_OFFSET..LENGTH_OFFSET + 8];
    let length = u64::from_le_bytes([
        length_bytes[0],
        length_bytes[1],
        length_bytes[2],
        length_bytes[3],
        length_bytes[4],
        length_bytes[5],
        length_bytes[6],
        length_bytes[7],
    ]);

    Ok(length)
}
