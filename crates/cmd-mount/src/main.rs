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
    net::ToSocketAddrs,
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
            let stat_result = match stat(&bind.target) {
                Ok(result) => result,
                Err(_) => return Err(Error::Path(bind.target.clone())),
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
        Commands::Mount(mount) => {
            // validate mount point
            let stat_result = match stat(&mount.mount_point) {
                Ok(result) => result,
                Err(_) => return Err(Error::Path(mount.mount_point.clone())),
            };

            // check write permission
            if access(&mount.mount_point, AccessFlags::W_OK).is_err() {
                return Err(Error::NotWritable(mount.mount_point.clone().into()));
            }

            // check sticky bit
            if stat_result.st_mode & Mode::S_ISVTX.bits() != 0 {
                return Err(Error::StickyDirectory(mount.mount_point.clone().into()));
            }

            let parts: Vec<&str> = mount.dial.split('!').collect();
            if parts.is_empty() {
                return Err(Error::EmptyDialString);
            }

            let proto = parts[0];
            if proto != "unix" && proto != "tcp" && proto != "virtio" && proto != "-" {
                return Err(Error::UnknownNetwork(proto.to_string()));
            }

            let (trans, addr) = match proto {
                "-" => ("fd".to_string(), "nodev".to_string()),
                _ => {
                    if parts.len() < 2 {
                        return Err(Error::MissingDialAddress);
                    }

                    let addr = parts[1];

                    // for unix sockets, check accessibility
                    if proto == "unix" {
                        if access(Path::new(addr), AccessFlags::R_OK | AccessFlags::W_OK).is_err() {
                            return Err(Error::SocketAccess(addr.to_string()));
                        }
                    }

                    // for tcp, resolve hostname and port
                    let mut address = addr.to_string();
                    if proto == "tcp" {
                        let port = if parts.len() > 2 {
                            match parts[2].parse::<u16>() {
                                Ok(p) => p,
                                Err(_) => return Err(Error::InvalidPort(parts[2].to_string())),
                            }
                        } else {
                            564 // default 9p port
                        };

                        // resolve hostname to IP
                        match (addr, port).to_socket_addrs() {
                            Ok(mut addrs) => {
                                if let Some(socket_addr) = addrs.next() {
                                    address = socket_addr.ip().to_string();
                                } else {
                                    return Err(Error::HostResolution(addr.to_string()));
                                }
                            }
                            Err(_) => return Err(Error::HostResolution(addr.to_string())),
                        }
                    }

                    (proto.to_string(), address)
                }
            };

            // build mount options
            let mut options = vec![];

            // base options
            options.push(format!("trans={}", trans));

            // user identification
            let user = match User::from_uid(getuid())? {
                Some(user) => user,
                None => return Err(Error::UserLookup),
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
            options.push(format!("uname={}", uname));

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
                options.push(format!("aname={}", aname));
            }

            if let Some(msize) = mount.msize {
                if msize > 0 {
                    options.push(format!("msize={}", msize));
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

            // special case for fd transport
            if trans == "fd" {
                options.push("rfdno=0,wfdno=1".to_string());
            }

            // assemble final options string
            let options_str = options.join(",");

            // handle dry run
            if mount.dry_run {
                info!(
                    "would execute: mount -t 9p -o {} {} {}",
                    options_str,
                    addr,
                    mount.mount_point.display()
                );
                return Ok(());
            }

            // Perform mount operation
            let c_addr = CString::new(addr)?;
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
                    c_options.as_ptr() as *const libc::c_void,
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
        Commands::Unmount(unmount) => {
            let user = match User::from_uid(getuid())? {
                Some(user) => user,
                None => return Err(Error::UserLookup),
            };

            let home_dir = user.dir;
            let username = user.name;

            let canonical_path = match std::fs::canonicalize(&unmount.target) {
                Ok(path) => path,
                Err(_) => return Err(Error::InvalidPath(unmount.target)),
            };

            let file = match File::open("/proc/mounts") {
                Ok(file) => file,
                Err(_) => return Err(Error::MountsAccess),
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

                    if !in_home_dir && !is_mounted_by_user(&mount_options, &username) {
                        return Err(Error::NotMountedByUser(canonical_path));
                    }

                    // perform unmount
                    match umount(&canonical_path) {
                        Ok(_) => {
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
