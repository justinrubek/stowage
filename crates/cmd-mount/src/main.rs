use crate::{
    commands::Commands,
    error::{Error, Result},
};
use clap::Parser;
use nix::{
    mount::{mount, MsFlags},
    sys::stat::{stat, Mode},
    unistd::{access, AccessFlags},
};

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
            .map_err(|e| Error::Mount(e))?;

            Ok(())
        }
        Commands::Mount(mount) => {
            todo!()
        }
        Commands::Unmount(mount) => {
            todo!()
        }
    }
}
