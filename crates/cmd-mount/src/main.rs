use crate::{
    commands::Commands,
    error::{Error, Result},
};
use clap::Parser;
use nix::{
    libc,
    mount::{mount, umount, MsFlags},
    sys::stat::{stat, Mode},
    unistd::{access, getgid, getuid, AccessFlags, User},
};
use std::{
    ffi::CString,
    fs::File,
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
};
use tracing::info;

mod commands;
mod error;

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let args = commands::Args::parse();
    match args.command {
        Commands::Bind(bind) => {
            let Ok(stat_result) = stat(&bind.target) else {
                return Err(Error::Path(bind.target.clone()));
            };

            if access(&bind.target, AccessFlags::W_OK).is_err() {
                return Err(Error::NotWritable(bind.target));
            }

            if stat_result.st_mode & Mode::S_ISVTX.bits() != 0 {
                return Err(Error::StickyDirectory(bind.target));
            }

            mount(
                Some(&bind.source),
                &bind.target,
                None::<&str>,
                MsFlags::MS_BIND,
                None::<&str>,
            )?;

            Ok(())
        }
        Commands::Mount(mount) => do_mount(&mount),
        Commands::Umount(unmount) => {
            let Some(user) = User::from_uid(getuid())? else {
                return Err(Error::UserLookup);
            };

            let home_dir = user.dir;
            let username = user.name;

            let Ok(canonical_path) = std::fs::canonicalize(&unmount.target) else {
                return Err(Error::InvalidPath(unmount.target));
            };

            let Ok(file) = File::open("/proc/mounts") else {
                return Err(Error::MountsAccess);
            };

            let reader = BufReader::new(file);

            for line in reader.lines() {
                let line = line?;
                let fields: Vec<&str> = line.split_whitespace().collect();

                if fields.len() < 4 {
                    continue; // invalid line format
                }

                let _mount_source = fields[0];
                let mount_point = fields[1];
                let mount_type = fields[2];
                let mount_options = fields[3];

                // unescape the mount point
                let mount_point = mount_point.replace("\\040", " ");
                let mount_path = PathBuf::from(&mount_point);

                if canonical_path == mount_path {
                    let in_home_dir = mount_point.starts_with(&*home_dir.to_string_lossy());

                    // check filesystem type and mount ownership
                    if !in_home_dir && mount_type != "9p" {
                        return Err(Error::NonNinePFilesystem(canonical_path));
                    }

                    if !in_home_dir && !is_mounted_by_user(mount_options, &username) {
                        return Err(Error::NotMountedByUser(canonical_path));
                    }

                    // perform unmount
                    match umount(&canonical_path) {
                        Ok(()) => {
                            info!("Successfully unmounted {}", canonical_path.display());
                            return Ok(());
                        }
                        Err(e) => return Err(Error::Unmount(canonical_path, e.to_string())),
                    }
                }
            }

            // if we got here, we didn't find the mount point
            Err(Error::NotMounted(canonical_path))
        }
    }
}

fn is_mounted_by_user(options: &str, username: &str) -> bool {
    for option in options.split(',') {
        if let Some(option) = option.strip_prefix("name=") {
            return option == username;
        }
    }
    false
}

fn do_mount(mount: &commands::MountCommand) -> Result<()> {
    // validate mount point
    let Ok(stat_result) = stat(&mount.mount_point) else {
        return Err(Error::Path(mount.mount_point.clone()));
    };

    // check write permission
    if access(&mount.mount_point, AccessFlags::W_OK).is_err() {
        return Err(Error::NotWritable(mount.mount_point.clone()));
    }

    // check sticky bit
    if stat_result.st_mode & Mode::S_ISVTX.bits() != 0 {
        return Err(Error::StickyDirectory(mount.mount_point.clone()));
    }

    let parts: Vec<&str> = mount.dial.split('!').collect();
    if parts.is_empty() {
        return Err(Error::EmptyDialString);
    }

    let proto = parts[0];
    if proto != "unix" && proto != "tcp" && proto != "virtio" && proto != "-" {
        return Err(Error::UnknownNetwork(proto.to_string()));
    }

    let transport = parse_dial_string(&mount.dial)?;
    let mut options = transport.options;

    let Some(user) = User::from_uid(getuid())? else {
        return Err(Error::UserLookup);
    };

    options.push(format!("name={}", user.name));

    // add uname
    let uname = match &mount.uname {
        Some(name) => name.clone(),
        None => user.name,
    };

    if uname.contains(',') {
        return Err(Error::InvalidUsername(uname));
    }
    options.push(format!("uname={uname}"));

    // add other options based on command flags
    if mount.single_attach {
        options.push("access=any".to_string());
    }

    if mount.exclusive {
        options.push(format!("access={}", getuid()));
    }

    if let Some(aname) = &mount.aname {
        if aname.contains(',') {
            return Err(Error::InvalidAname(aname.clone()));
        }
        options.push(format!("aname={aname}"));
    }

    if let Some(msize) = mount.msize {
        if msize > 0 {
            options.push(format!("msize={msize}"));
        } else {
            return Err(Error::InvalidMsize(msize));
        }
    }

    if mount.inherit_user {
        options.push(format!("uid={},gid={}", getuid(), getgid()));
        options.push(format!("dfltuid={},dfltgid={}", getuid(), getgid()));
    }

    // add standard security options
    if user.uid != 0.into() {
        options.push("nosuid".to_string());
    }

    if !mount.device_mapping {
        options.push("nodev".to_string());
    }

    if !mount.extensions {
        options.push("noextend".to_string());
    }

    // assemble final options string
    let options_str = options.join(",");

    // handle dry run
    if mount.dry_run {
        info!(
            "would execute: mount -t 9p -o {} {} {}",
            options_str,
            transport.addr,
            mount.mount_point.display()
        );
        return Ok(());
    }

    // Perform mount operation
    let c_addr = CString::new(transport.addr)?;
    let mount_path_str = mount.mount_point.to_string_lossy();
    let c_mountpoint = CString::new(mount_path_str.as_bytes())?;
    let c_options = CString::new(options_str)?;

    match unsafe {
        // Using libc::mount directly as nix doesn't fully support all options we need
        libc::mount(
            c_addr.as_ptr(),
            c_mountpoint.as_ptr(),
            CString::new("9p").unwrap().as_ptr(),
            0,
            c_options.as_ptr().cast::<libc::c_void>(),
        )
    } {
        0 => {
            info!(
                "Successfully mounted {} at {}",
                mount.dial,
                mount.mount_point.display()
            );
            Ok(())
        }
        _ => Err(Error::Mount(std::io::Error::last_os_error().to_string())),
    }
}

/// Parse a 9P dial string and return (transport, address)
fn parse_dial_string(dial: &str) -> Result<TransportContext> {
    let parts: Vec<&str> = dial.split('!').collect();
    if parts.is_empty() {
        return Err(Error::EmptyDialString);
    }

    let proto = parts[0];
    if proto != "unix" && proto != "tcp" && proto != "virtio" && proto != "-" {
        return Err(Error::UnknownNetwork(proto.to_string()));
    }

    let mut context = if proto == "-" {
        return Ok(TransportContext {
            addr: "nodev".to_string(),
            options: vec!["rfdno=0".to_string(), "wfdno=1".to_string()],
            trans: "fd".to_string(),
        });
    } else {
        // need address part for all other protocols
        if parts.len() < 2 {
            return Err(Error::MissingDialAddress);
        }

        let addr = parts[1];
        let mut options = Vec::new();

        // for unix sockets, check accessibility
        if proto == "unix"
            && access(Path::new(addr), AccessFlags::R_OK | AccessFlags::W_OK).is_err()
        {
            return Err(Error::SocketAccess(addr.to_string()));
        }

        // for TCP, resolve hostname and port
        let address = if proto == "tcp" {
            let port = if parts.len() > 2 {
                match parts[2].parse::<u16>() {
                    Ok(p) => p,
                    Err(_) => return Err(Error::InvalidPort(parts[2].to_string())),
                }
            } else {
                564 // default 9P port
            };

            let ip = resolve_to_ipv4(addr, port)?;

            options.push(format!("port={port}"));

            ip
        } else {
            // for unix and virtio, use address as is
            addr.to_string()
        };

        TransportContext {
            addr: address,
            options,
            trans: proto.to_string(),
        }
    };

    context.options.push(format!("trans={}", context.trans));
    Ok(context)
}

struct TransportContext {
    addr: String,
    options: Vec<String>,
    trans: String,
}

fn resolve_to_ipv4(hostname: &str, port: u16) -> Result<String> {
    use std::net::{IpAddr, ToSocketAddrs};

    // First try direct IPv4 parsing - if it's already an IP address
    if let Ok(ip) = hostname.parse::<std::net::IpAddr>() {
        if let IpAddr::V4(ipv4) = ip {
            return Ok(ipv4.to_string());
        }

        return Err(Error::IPv6NotSupported(hostname.to_string()));
    }

    // Otherwise, use DNS resolution with IPv4 preference
    let socket_addrs = (hostname, port)
        .to_socket_addrs()
        .map_err(|_| Error::HostResolution(hostname.to_string()))?;

    // Find the first IPv4 address
    for addr in socket_addrs {
        if let IpAddr::V4(ipv4) = addr.ip() {
            return Ok(ipv4.to_string());
        }
    }

    // No IPv4 addresses found
    Err(Error::NoIPv4Address(hostname.to_string()))
}
