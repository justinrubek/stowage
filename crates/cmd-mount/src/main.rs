use crate::{
    commands::Commands,
    error::{Error, Result},
};
use clap::Parser;
use nix::{
    mount::{mount, umount, MsFlags},
    sys::stat::{stat, Mode},
    unistd::{access, getuid, AccessFlags, User},
};
use std::{
    fs::File,
    io::{BufRead, BufReader},
    path::PathBuf,
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
            )
            .map_err(Error::Mount)?;

            Ok(())
        }
        Commands::Mount(mount) => {
            todo!()
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
