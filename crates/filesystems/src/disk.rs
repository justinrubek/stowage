use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use stowage_proto::consts::{EIO, ENOTDIR, EOPNOTSUPP};
use stowage_proto::{
    consts::{
        O_APPEND, O_CREAT, O_EXCL, O_NONBLOCK, O_RDONLY, O_RDWR, O_TRUNC, O_WRONLY, P9_GETATTR_ALL,
        P9_GETATTR_BASIC, P9_NOFID, P9_SETATTR_ATIME, P9_SETATTR_ATIME_SET, P9_SETATTR_GID,
        P9_SETATTR_MODE, P9_SETATTR_MTIME, P9_SETATTR_MTIME_SET, P9_SETATTR_SIZE, P9_SETATTR_UID,
        QID_TYPE_DIR, QID_TYPE_FILE, QID_TYPE_SYMLINK,
    },
    Dirent, Lock, Message, Qid, Stat, StatFs,
};
use stowage_service::MessageHandler;

pub struct Handler {
    dir: PathBuf,
    fids: Arc<Mutex<HashMap<u32, FidEntry>>>,
}

struct FidEntry {
    path: PathBuf,
    opened: bool,
    is_dir: bool,
    file: Option<File>,
}

impl Handler {
    // accept a path to use as the root directory
    pub fn new<P: Into<PathBuf>>(dir: P) -> Self {
        Self {
            dir: dir.into(),
            fids: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    // helper methods
    fn path_for_fid(&self, fid: u32) -> Result<PathBuf, io::Error> {
        let fids = self.fids.lock().unwrap();
        match fids.get(&fid) {
            Some(entry) => Ok(entry.path.clone()),
            None => Err(io::Error::new(io::ErrorKind::NotFound, "fid not found")),
        }
    }

    fn create_qid_from_metadata(&self, metadata: &fs::Metadata) -> Qid {
        let qtype = if metadata.is_dir() {
            QID_TYPE_DIR
        } else if metadata.is_symlink() {
            QID_TYPE_SYMLINK
        } else {
            QID_TYPE_FILE
        };

        Qid {
            qtype,
            version: 0, // version is not tracked in this implementation
            path: metadata.ino(),
        }
    }

    fn stat_from_metadata(&self, metadata: &fs::Metadata, path: &Path) -> Stat {
        let qid = self.create_qid_from_metadata(metadata);
        Stat {
            dev: 0, // not needed for this implementation
            qtype: qid.qtype as u16,
            qid: qid,
            mode: metadata.mode(),
            atime: metadata.atime() as u32,
            mtime: metadata.mtime() as u32,
            length: metadata.len(),
            name: path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string(),
            uid: metadata.uid().to_string(),
            gid: metadata.gid().to_string(),
            muid: "".to_string(), // not tracked in this implementation
        }
    }
}

impl MessageHandler for Handler {
    async fn handle_message(&self, message: Message) -> Message {
        match message {
            Message::Tversion {
                tag,
                msize,
                version,
            } => {
                // protocol requires version to be 9P2000.L
                let version_str = if version == "9P2000.L" {
                    "9P2000.L".to_string()
                } else {
                    "unknown".to_string()
                };

                // use client's msize or cap it if needed
                let msize = std::cmp::min(msize, 65536); // reasonable maximum

                Message::Rversion {
                    tag,
                    msize,
                    version: version_str,
                }
            }

            Message::Tauth {
                tag,
                afid,
                uname,
                aname,
            } => {
                // authentication is not implemented/required in this handler
                // return an error indicating operation not supported
                Message::Rlerror {
                    tag,
                    ecode: EOPNOTSUPP as u32,
                }
            }

            Message::Tattach {
                tag,
                fid,
                afid,
                uname,
                aname,
            } => {
                // establish a new fid that points to the root directory
                let root_path = self.dir.clone();

                // verify the root directory exists
                match fs::metadata(&root_path) {
                    Ok(metadata) => {
                        if !metadata.is_dir() {
                            return Message::Rlerror {
                                tag,
                                ecode: ENOTDIR as u32,
                            };
                        }

                        // create a qid for the root directory
                        let qid = self.create_qid_from_metadata(&metadata);

                        // store this fid in our mapping
                        let mut fids = self.fids.lock().unwrap();
                        fids.insert(
                            fid,
                            FidEntry {
                                path: root_path,
                                opened: false,
                                is_dir: true,
                                file: None,
                            },
                        );

                        Message::Rattach { tag, qid }
                    }
                    Err(e) => Message::Rlerror {
                        tag,
                        ecode: e.raw_os_error().unwrap_or(EIO as i32) as u32,
                    },
                }
            }
            Message::Tflush { tag, oldtag } => {
                // flush doesn't need special file operations for this implementation
                // it simply acknowledges the flush request
                Message::Rflush { tag }
            }

            Message::Twalk {
                tag,
                fid,
                newfid,
                wnames,
            } => {
                // get the source path
                let source_path = match self.path_for_fid(fid) {
                    Ok(path) => path,
                    Err(_) => {
                        return Message::Rlerror {
                            tag,
                            ecode: ENOTDIR as u32,
                        }
                    }
                };

                // if newfid differs from fid, clone the fid
                if fid != newfid {
                    let mut fids = self.fids.lock().unwrap();
                    // clone the path and check if source exists before attempting to insert
                    let entry_opt = fids.get(&fid);
                    if let Some(entry) = entry_opt {
                        // clone the needed values outside the borrow
                        let path_clone = entry.path.clone();
                        let is_dir = entry.is_dir;

                        // now insert without borrowing entry
                        fids.insert(
                            newfid,
                            FidEntry {
                                path: path_clone,
                                opened: false,
                                is_dir,
                                file: None,
                            },
                        );
                    } else {
                        return Message::Rlerror {
                            tag,
                            ecode: ENOTDIR as u32,
                        };
                    }
                }

                // empty walk is just a fid clone
                if wnames.is_empty() {
                    return Message::Rwalk { tag, wqids: vec![] };
                }

                // walk through each path component
                let mut wqids = Vec::with_capacity(wnames.len());
                let mut current_path = source_path;

                for wname in &wnames {
                    current_path = current_path.join(wname);

                    match fs::metadata(&current_path) {
                        Ok(metadata) => {
                            let qid = self.create_qid_from_metadata(&metadata);
                            wqids.push(qid);
                        }
                        Err(_) => {
                            // path component not found, return what we have
                            if wqids.is_empty() {
                                return Message::Rlerror {
                                    tag,
                                    ecode: ENOTDIR as u32,
                                };
                            }
                            break;
                        }
                    }
                }

                // if we successfully walked all components, update the newfid's path
                if wqids.len() == wnames.len() {
                    let mut fids = self.fids.lock().unwrap();
                    if let Some(entry) = fids.get_mut(&newfid) {
                        entry.path = current_path.clone();
                        entry.is_dir = fs::metadata(&current_path)
                            .map(|m| m.is_dir())
                            .unwrap_or(false);
                    }
                }

                Message::Rwalk { tag, wqids }
            }

            Message::Topen { tag, fid, mode } => {
                let path = match self.path_for_fid(fid) {
                    Ok(path) => path,
                    Err(_) => {
                        return Message::Rlerror {
                            tag,
                            ecode: EIO as u32,
                        }
                    }
                };

                // convert 9P mode to rust file open options
                let mut options = OpenOptions::new();

                // translate 9P mode flags to Rust OpenOptions
                match (mode & 0x3) as u32 {
                    O_RDONLY => {
                        options.read(true);
                    }
                    O_WRONLY => {
                        options.write(true);
                    }
                    O_RDWR => {
                        options.read(true).write(true);
                    }
                    _ => {
                        return Message::Rlerror {
                            tag,
                            ecode: EIO as u32,
                        }
                    }
                }

                // handle additional flags
                if (mode as u32 & O_TRUNC) != 0 {
                    options.truncate(true);
                }
                if (mode as u32 & O_APPEND) != 0 {
                    options.append(true);
                }

                // attempt to open the file
                match options.open(&path) {
                    Ok(file) => {
                        match fs::metadata(&path) {
                            Ok(metadata) => {
                                let qid = self.create_qid_from_metadata(&metadata);
                                let is_dir = metadata.is_dir();

                                // update the fid entry
                                let mut fids = self.fids.lock().unwrap();
                                if let Some(entry) = fids.get_mut(&fid) {
                                    entry.opened = true;
                                    entry.file = Some(file);
                                }

                                // reasonable iounit size
                                let iounit = 4096;

                                Message::Ropen { tag, qid, iounit }
                            }
                            Err(e) => Message::Rlerror {
                                tag,
                                ecode: e.raw_os_error().unwrap_or(EIO as i32) as u32,
                            },
                        }
                    }
                    Err(e) => Message::Rlerror {
                        tag,
                        ecode: e.raw_os_error().unwrap_or(EIO as i32) as u32,
                    },
                }
            }

            // New handler for Tcreate
            Message::Tcreate {
                tag,
                fid,
                name,
                perm,
                mode,
            } => {
                let dir_path = match self.path_for_fid(fid) {
                    Ok(path) => path,
                    Err(_) => {
                        return Message::Rlerror {
                            tag,
                            ecode: EIO as u32,
                        }
                    }
                };

                // check if the parent is a directory
                match fs::metadata(&dir_path) {
                    Ok(metadata) => {
                        if !metadata.is_dir() {
                            return Message::Rlerror {
                                tag,
                                ecode: ENOTDIR as u32,
                            };
                        }
                    }
                    Err(e) => {
                        return Message::Rlerror {
                            tag,
                            ecode: e.raw_os_error().unwrap_or(EIO as i32) as u32,
                        }
                    }
                }

                // prepare the new file path
                let file_path = dir_path.join(&name);

                // convert 9P mode to rust file open options
                let mut options = OpenOptions::new();
                options.create(true);

                // translate 9P mode flags to Rust OpenOptions
                match (mode & 0x3) as u32 {
                    O_RDONLY => {
                        options.read(true);
                    }
                    O_WRONLY => {
                        options.write(true);
                    }
                    O_RDWR => {
                        options.read(true).write(true);
                    }
                    _ => {
                        return Message::Rlerror {
                            tag,
                            ecode: EIO as u32,
                        }
                    }
                }

                // handle additional flags
                if (mode as u32 & O_EXCL) != 0 {
                    options.create_new(true);
                }
                if (mode as u32 & O_TRUNC) != 0 {
                    options.truncate(true);
                }

                // attempt to create the file
                match options.open(&file_path) {
                    Ok(file) => {
                        // set file permissions
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::PermissionsExt;
                            if let Ok(mut perms) = fs::metadata(&file_path).map(|m| m.permissions())
                            {
                                perms.set_mode(perm & 0o777);
                                let _ = fs::set_permissions(&file_path, perms);
                            }
                        }

                        match fs::metadata(&file_path) {
                            Ok(metadata) => {
                                let qid = self.create_qid_from_metadata(&metadata);

                                // update the fid entry to point to the new file
                                let mut fids = self.fids.lock().unwrap();
                                if let Some(entry) = fids.get_mut(&fid) {
                                    entry.path = file_path;
                                    entry.opened = true;
                                    entry.is_dir = false;
                                    entry.file = Some(file);
                                }

                                // reasonable iounit size
                                let iounit = 4096;

                                Message::Rcreate { tag, qid, iounit }
                            }
                            Err(e) => Message::Rlerror {
                                tag,
                                ecode: e.raw_os_error().unwrap_or(EIO as i32) as u32,
                            },
                        }
                    }
                    Err(e) => Message::Rlerror {
                        tag,
                        ecode: e.raw_os_error().unwrap_or(EIO as i32) as u32,
                    },
                }
            }

            Message::Tread {
                tag,
                fid,
                offset,
                count,
            } => {
                // get the fid entry
                let mut fids = self.fids.lock().unwrap();
                let entry = match fids.get_mut(&fid) {
                    Some(entry) => entry,
                    None => {
                        return Message::Rlerror {
                            tag,
                            ecode: EIO as u32,
                        }
                    }
                };

                // ensure the file is opened
                if !entry.opened {
                    return Message::Rlerror {
                        tag,
                        ecode: EIO as u32,
                    };
                }

                // handle different types of reads
                if entry.is_dir {
                    // directories should not be read with Tread in 9P2000.L
                    // they should use Treaddir instead
                    return Message::Rlerror {
                        tag,
                        ecode: EOPNOTSUPP as u32,
                    };
                } else {
                    // read from regular file
                    let file = match &mut entry.file {
                        Some(file) => file,
                        None => {
                            return Message::Rlerror {
                                tag,
                                ecode: EIO as u32,
                            }
                        }
                    };

                    // seek to the offset
                    if let Err(e) = file.seek(SeekFrom::Start(offset)) {
                        return Message::Rlerror {
                            tag,
                            ecode: e.raw_os_error().unwrap_or(EIO as i32) as u32,
                        };
                    }

                    // allocate buffer and read data
                    let mut buffer = vec![0; count as usize];
                    match file.read(&mut buffer) {
                        Ok(n) => {
                            buffer.truncate(n);
                            Message::Rread { tag, data: buffer }
                        }
                        Err(e) => Message::Rlerror {
                            tag,
                            ecode: e.raw_os_error().unwrap_or(EIO as i32) as u32,
                        },
                    }
                }
            }

            Message::Twrite {
                tag,
                fid,
                offset,
                data,
            } => {
                // get the fid entry
                let mut fids = self.fids.lock().unwrap();
                let entry = match fids.get_mut(&fid) {
                    Some(entry) => entry,
                    None => {
                        return Message::Rlerror {
                            tag,
                            ecode: EIO as u32,
                        }
                    }
                };

                // ensure the file is opened
                if !entry.opened {
                    return Message::Rlerror {
                        tag,
                        ecode: EIO as u32,
                    };
                }

                // get the file handle
                let file = match &mut entry.file {
                    Some(file) => file,
                    None => {
                        return Message::Rlerror {
                            tag,
                            ecode: EIO as u32,
                        }
                    }
                };

                // seek to the offset
                if let Err(e) = file.seek(SeekFrom::Start(offset)) {
                    return Message::Rlerror {
                        tag,
                        ecode: e.raw_os_error().unwrap_or(EIO as i32) as u32,
                    };
                }

                // write the data
                match file.write(&data) {
                    Ok(count) => Message::Rwrite {
                        tag,
                        count: count as u32,
                    },
                    Err(e) => Message::Rlerror {
                        tag,
                        ecode: e.raw_os_error().unwrap_or(EIO as i32) as u32,
                    },
                }
            }

            Message::Tclunk { tag, fid } => {
                // remove the fid from the map
                let mut fids = self.fids.lock().unwrap();

                // close any open file handle before removing
                if let Some(entry) = fids.remove(&fid) {
                    // file will be closed when dropped by remove
                    // we don't need to do anything special with it
                }

                // return success
                Message::Rclunk { tag }
            }

            Message::Tremove { tag, fid } => {
                // get the path
                let path = match self.path_for_fid(fid) {
                    Ok(path) => path,
                    Err(_) => {
                        return Message::Rlerror {
                            tag,
                            ecode: EIO as u32,
                        }
                    }
                };

                // remove the fid from the map first (similar to clunk)
                let mut fids = self.fids.lock().unwrap();
                fids.remove(&fid);

                // attempt to remove the file or directory
                let result = if path.is_dir() {
                    fs::remove_dir_all(&path)
                } else {
                    fs::remove_file(&path)
                };

                match result {
                    Ok(_) => Message::Rremove { tag },
                    Err(e) => Message::Rlerror {
                        tag,
                        ecode: e.raw_os_error().unwrap_or(EIO as i32) as u32,
                    },
                }
            }
            Message::Tstat { tag, fid } => {
                // get the path and metadata for this fid
                let path = match self.path_for_fid(fid) {
                    Ok(path) => path,
                    Err(_) => {
                        return Message::Rlerror {
                            tag,
                            ecode: EIO as u32,
                        }
                    }
                };

                match fs::metadata(&path) {
                    Ok(metadata) => {
                        let stat = self.stat_from_metadata(&metadata, &path);
                        Message::Rstat { tag, stat }
                    }
                    Err(e) => Message::Rlerror {
                        tag,
                        ecode: e.raw_os_error().unwrap_or(EIO as i32) as u32,
                    },
                }
            }

            Message::Twstat { tag, fid, stat } => {
                // handle the wstat operation - deprecated in 9P2000.L
                // clients should use setattr instead
                Message::Rlerror {
                    tag,
                    ecode: EOPNOTSUPP as u32,
                }
            }

            Message::Topenfd { tag, fid, mode } => {
                // openfd not supported in this implementation
                // clients should use lopen instead
                Message::Rlerror {
                    tag,
                    ecode: EOPNOTSUPP as u32,
                }
            }

            Message::Tlopen { tag, fid, flags } => {
                let path = match self.path_for_fid(fid) {
                    Ok(path) => path,
                    Err(_) => {
                        return Message::Rlerror {
                            tag,
                            ecode: EIO as u32,
                        }
                    }
                };

                // convert Linux open flags to rust file open options
                let mut options = OpenOptions::new();

                // translate Linux open flags to Rust OpenOptions
                if (flags & O_RDWR) == O_RDWR {
                    options.read(true).write(true);
                } else if (flags & O_WRONLY) == O_WRONLY {
                    options.write(true);
                } else {
                    // O_RDONLY is 0, so default to read
                    options.read(true);
                }

                if (flags & O_TRUNC) != 0 {
                    options.truncate(true);
                }
                if (flags & O_APPEND) != 0 {
                    options.append(true);
                }
                if (flags & O_CREAT) != 0 {
                    options.create(true);
                }
                if (flags & O_EXCL) != 0 {
                    options.create_new(true);
                }

                // attempt to open the file
                let result = if fs::metadata(&path).map_or(false, |m| m.is_dir()) {
                    // for directories, just get metadata and don't actually open a file
                    Ok(None)
                } else {
                    options.open(&path).map(Some)
                };

                match result {
                    Ok(file_opt) => {
                        match fs::metadata(&path) {
                            Ok(metadata) => {
                                let qid = self.create_qid_from_metadata(&metadata);
                                let is_dir = metadata.is_dir();

                                // update the fid entry
                                let mut fids = self.fids.lock().unwrap();
                                if let Some(entry) = fids.get_mut(&fid) {
                                    entry.opened = true;
                                    entry.is_dir = is_dir;
                                    entry.file = file_opt;
                                }

                                // reasonable iounit size
                                let iounit = 4096;

                                Message::Rlopen { tag, qid, iounit }
                            }
                            Err(e) => Message::Rlerror {
                                tag,
                                ecode: e.raw_os_error().unwrap_or(EIO as i32) as u32,
                            },
                        }
                    }
                    Err(e) => Message::Rlerror {
                        tag,
                        ecode: e.raw_os_error().unwrap_or(EIO as i32) as u32,
                    },
                }
            }

            Message::Tgetattr {
                tag,
                fid,
                request_mask,
            } => {
                let path = match self.path_for_fid(fid) {
                    Ok(path) => path,
                    Err(_) => {
                        return Message::Rlerror {
                            tag,
                            ecode: EIO as u32,
                        }
                    }
                };

                match fs::metadata(&path) {
                    Ok(metadata) => {
                        let qid = self.create_qid_from_metadata(&metadata);

                        // determine valid fields based on request_mask
                        let valid = request_mask & P9_GETATTR_ALL;

                        // get unix timestamps
                        let atime = metadata.atime();
                        let mtime = metadata.mtime();
                        let ctime = metadata.ctime();

                        // convert to seconds and nanoseconds
                        let atime_sec = atime as u64;
                        let atime_nsec = 0; // not available in standard metadata
                        let mtime_sec = mtime as u64;
                        let mtime_nsec = 0; // not available in standard metadata
                        let ctime_sec = ctime as u64;
                        let ctime_nsec = 0; // not available in standard metadata

                        // birth time and other extended attributes not supported
                        let btime_sec = 0;
                        let btime_nsec = 0;
                        let gen = 0;
                        let data_version = 0;

                        Message::Rgetattr {
                            tag,
                            valid,
                            qid,
                            mode: metadata.mode(),
                            uid: metadata.uid(),
                            gid: metadata.gid(),
                            nlink: metadata.nlink() as u64,
                            rdev: metadata.rdev() as u64,
                            size: metadata.len(),
                            blksize: metadata.blksize() as u64,
                            blocks: metadata.blocks() as u64,
                            atime_sec,
                            atime_nsec,
                            mtime_sec,
                            mtime_nsec,
                            ctime_sec,
                            ctime_nsec,
                            btime_sec,
                            btime_nsec,
                            gen,
                            data_version,
                        }
                    }
                    Err(e) => Message::Rlerror {
                        tag,
                        ecode: e.raw_os_error().unwrap_or(EIO as i32) as u32,
                    },
                }
            }

            Message::Tsetattr {
                tag,
                fid,
                valid,
                mode,
                uid,
                gid,
                size,
                atime_sec,
                atime_nsec,
                mtime_sec,
                mtime_nsec,
            } => {
                let path = match self.path_for_fid(fid) {
                    Ok(path) => path,
                    Err(_) => {
                        return Message::Rlerror {
                            tag,
                            ecode: EIO as u32,
                        }
                    }
                };

                // handle each attribute based on valid flags
                let mut error = None;

                // set mode if requested
                if (valid & P9_SETATTR_MODE) != 0 {
                    #[cfg(unix)]
                    {
                        if let Ok(mut perms) = fs::metadata(&path).map(|m| m.permissions()) {
                            perms.set_mode(mode);
                            if let Err(e) = fs::set_permissions(&path, perms) {
                                error = Some(e);
                            }
                        } else {
                            error = Some(io::Error::new(
                                io::ErrorKind::Other,
                                "Failed to get permissions",
                            ));
                        }
                    }
                }

                // set size if requested
                if error.is_none() && (valid & P9_SETATTR_SIZE) != 0 {
                    if let Err(e) = fs::OpenOptions::new()
                        .write(true)
                        .open(&path)
                        .and_then(|mut file| file.set_len(size))
                    {
                        error = Some(e);
                    }
                }

                // uid/gid setting usually requires root privileges
                // this implementation does not fully handle these cases

                // set atime if requested
                #[cfg(unix)]
                if error.is_none()
                    && ((valid & P9_SETATTR_ATIME) != 0 || (valid & P9_SETATTR_ATIME_SET) != 0)
                {
                    // not fully implemented - would require utimes syscall
                }

                // set mtime if requested
                #[cfg(unix)]
                if error.is_none()
                    && ((valid & P9_SETATTR_MTIME) != 0 || (valid & P9_SETATTR_MTIME_SET) != 0)
                {
                    // not fully implemented - would require utimes syscall
                }

                match error {
                    Some(e) => Message::Rlerror {
                        tag,
                        ecode: e.raw_os_error().unwrap_or(EIO as i32) as u32,
                    },
                    None => Message::Rsetattr { tag },
                }
            }

            Message::Treaddir {
                tag,
                fid,
                offset,
                count,
            } => {
                // get the fid entry
                let mut fids = self.fids.lock().unwrap();
                let entry = match fids.get_mut(&fid) {
                    Some(entry) => entry,
                    None => {
                        return Message::Rlerror {
                            tag,
                            ecode: EIO as u32,
                        }
                    }
                };

                // ensure the fid is a directory and is opened
                if !entry.is_dir || !entry.opened {
                    return Message::Rlerror {
                        tag,
                        ecode: ENOTDIR as u32,
                    };
                }

                // read directory entries
                let path = entry.path.clone();
                drop(fids); // release lock before filesystem operations

                let mut entries: Vec<Dirent> = Vec::new();

                match fs::read_dir(&path) {
                    Ok(read_dir) => {
                        let mut entries_collection: Vec<Dirent> = Vec::new();

                        // process all directory entries
                        for (idx, entry_result) in read_dir.enumerate() {
                            // skip entries before offset
                            if idx < offset as usize {
                                continue;
                            }

                            if let Ok(dir_entry) = entry_result {
                                if let Ok(metadata) = dir_entry.metadata() {
                                    let qid = self.create_qid_from_metadata(&metadata);
                                    let name = dir_entry.file_name().to_string_lossy().to_string();
                                    let entry_type = qid.qtype;

                                    // directory offset is just the index
                                    let entry_offset = (idx + 1) as u64;

                                    entries_collection.push(Dirent {
                                        qid,
                                        offset: entry_offset,
                                        dtype: entry_type,
                                        name,
                                    });

                                    // check if we've collected enough entries
                                    // rough size estimate - not exactly accurate
                                    let total_size: usize = entries_collection
                                        .iter()
                                        .map(|e| 13 + 8 + 1 + 2 + e.name.len())
                                        .sum();

                                    if total_size >= count as usize {
                                        break;
                                    }
                                }
                            }
                        }

                        entries = entries_collection;
                    }
                    Err(e) => {
                        return Message::Rlerror {
                            tag,
                            ecode: e.raw_os_error().unwrap_or(EIO as i32) as u32,
                        };
                    }
                }

                Message::Rreaddir { tag, data: entries }
            }

            Message::Tfsync { tag, fid } => {
                // get the fid entry
                let mut fids = self.fids.lock().unwrap();
                let entry = match fids.get_mut(&fid) {
                    Some(entry) => entry,
                    None => {
                        return Message::Rlerror {
                            tag,
                            ecode: EIO as u32,
                        }
                    }
                };

                // ensure the file is opened
                if !entry.opened {
                    return Message::Rlerror {
                        tag,
                        ecode: EIO as u32,
                    };
                }

                // perform fsync operation if file exists
                if let Some(file) = &mut entry.file {
                    match file.sync_all() {
                        Ok(_) => Message::Rfsync { tag },
                        Err(e) => Message::Rlerror {
                            tag,
                            ecode: e.raw_os_error().unwrap_or(EIO as i32) as u32,
                        },
                    }
                } else {
                    // for directories or unopened files, just return success
                    Message::Rfsync { tag }
                }
            }

            Message::Tmkdir {
                tag,
                dfid,
                name,
                mode,
                gid,
            } => {
                let dir_path = match self.path_for_fid(dfid) {
                    Ok(path) => path,
                    Err(_) => {
                        return Message::Rlerror {
                            tag,
                            ecode: EIO as u32,
                        }
                    }
                };

                // check if parent is a directory
                match fs::metadata(&dir_path) {
                    Ok(metadata) => {
                        if !metadata.is_dir() {
                            return Message::Rlerror {
                                tag,
                                ecode: ENOTDIR as u32,
                            };
                        }
                    }
                    Err(e) => {
                        return Message::Rlerror {
                            tag,
                            ecode: e.raw_os_error().unwrap_or(EIO as i32) as u32,
                        }
                    }
                }

                // create the new directory
                let new_dir_path = dir_path.join(&name);
                match fs::create_dir(&new_dir_path) {
                    Ok(_) => {
                        // set permissions
                        #[cfg(unix)]
                        {
                            if let Ok(mut perms) =
                                fs::metadata(&new_dir_path).map(|m| m.permissions())
                            {
                                perms.set_mode(mode & 0o777);
                                let _ = fs::set_permissions(&new_dir_path, perms);
                            }
                        }

                        // get qid for the new directory
                        match fs::metadata(&new_dir_path) {
                            Ok(metadata) => {
                                let qid = self.create_qid_from_metadata(&metadata);
                                Message::Rmkdir { tag, qid }
                            }
                            Err(e) => Message::Rlerror {
                                tag,
                                ecode: e.raw_os_error().unwrap_or(EIO as i32) as u32,
                            },
                        }
                    }
                    Err(e) => Message::Rlerror {
                        tag,
                        ecode: e.raw_os_error().unwrap_or(EIO as i32) as u32,
                    },
                }
            }

            Message::Tsymlink {
                tag,
                fid,
                name,
                symtgt,
                gid,
            } => {
                let dir_path = match self.path_for_fid(fid) {
                    Ok(path) => path,
                    Err(_) => {
                        return Message::Rlerror {
                            tag,
                            ecode: EIO as u32,
                        }
                    }
                };

                // check if parent is a directory
                match fs::metadata(&dir_path) {
                    Ok(metadata) => {
                        if !metadata.is_dir() {
                            return Message::Rlerror {
                                tag,
                                ecode: ENOTDIR as u32,
                            };
                        }
                    }
                    Err(e) => {
                        return Message::Rlerror {
                            tag,
                            ecode: e.raw_os_error().unwrap_or(EIO as i32) as u32,
                        }
                    }
                }

                // create the symlink
                let symlink_path = dir_path.join(&name);

                #[cfg(unix)]
                let result = std::os::unix::fs::symlink(&symtgt, &symlink_path);

                #[cfg(not(unix))]
                let result = Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "Symlinks not supported on this platform",
                ));

                match result {
                    Ok(_) => {
                        // get qid for the new symlink
                        match fs::metadata(&symlink_path) {
                            Ok(metadata) => {
                                let qid = self.create_qid_from_metadata(&metadata);
                                Message::Rsymlink { tag, qid }
                            }
                            Err(e) => Message::Rlerror {
                                tag,
                                ecode: e.raw_os_error().unwrap_or(EIO as i32) as u32,
                            },
                        }
                    }
                    Err(e) => Message::Rlerror {
                        tag,
                        ecode: e.raw_os_error().unwrap_or(EIO as i32) as u32,
                    },
                }
            }

            Message::Treadlink { tag, fid } => {
                let path = match self.path_for_fid(fid) {
                    Ok(path) => path,
                    Err(_) => {
                        return Message::Rlerror {
                            tag,
                            ecode: EIO as u32,
                        }
                    }
                };

                // read the symlink target
                #[cfg(unix)]
                let result = fs::read_link(&path);

                #[cfg(not(unix))]
                let result = Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "Symlinks not supported on this platform",
                ));

                match result {
                    Ok(target_path) => Message::Rreadlink {
                        tag,
                        target: target_path.to_string_lossy().to_string(),
                    },
                    Err(e) => Message::Rlerror {
                        tag,
                        ecode: e.raw_os_error().unwrap_or(EIO as i32) as u32,
                    },
                }
            }

            Message::Tlink {
                tag,
                dfid,
                fid,
                name,
            } => {
                let dir_path = match self.path_for_fid(dfid) {
                    Ok(path) => path,
                    Err(_) => {
                        return Message::Rlerror {
                            tag,
                            ecode: EIO as u32,
                        }
                    }
                };

                let source_path = match self.path_for_fid(fid) {
                    Ok(path) => path,
                    Err(_) => {
                        return Message::Rlerror {
                            tag,
                            ecode: EIO as u32,
                        }
                    }
                };

                // create the hard link
                let link_path = dir_path.join(&name);

                #[cfg(unix)]
                let result = std::fs::hard_link(&source_path, &link_path);

                #[cfg(not(unix))]
                let result = Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "Hard links not supported on this platform",
                ));

                match result {
                    Ok(_) => Message::Rlink { tag },
                    Err(e) => Message::Rlerror {
                        tag,
                        ecode: e.raw_os_error().unwrap_or(EIO as i32) as u32,
                    },
                }
            }

            Message::Trenameat {
                tag,
                olddirfid,
                oldname,
                newdirfid,
                newname,
            } => {
                let old_dir_path = match self.path_for_fid(olddirfid) {
                    Ok(path) => path,
                    Err(_) => {
                        return Message::Rlerror {
                            tag,
                            ecode: EIO as u32,
                        }
                    }
                };

                let new_dir_path = match self.path_for_fid(newdirfid) {
                    Ok(path) => path,
                    Err(_) => {
                        return Message::Rlerror {
                            tag,
                            ecode: EIO as u32,
                        }
                    }
                };

                let old_path = old_dir_path.join(&oldname);
                let new_path = new_dir_path.join(&newname);

                match fs::rename(&old_path, &new_path) {
                    Ok(_) => Message::Rrenameat { tag },
                    Err(e) => Message::Rlerror {
                        tag,
                        ecode: e.raw_os_error().unwrap_or(EIO as i32) as u32,
                    },
                }
            }

            Message::Tunlinkat {
                tag,
                dirfid,
                name,
                flags,
            } => {
                let dir_path = match self.path_for_fid(dirfid) {
                    Ok(path) => path,
                    Err(_) => {
                        return Message::Rlerror {
                            tag,
                            ecode: EIO as u32,
                        }
                    }
                };

                let path = dir_path.join(&name);

                // check if it's a directory or file
                let is_dir = fs::metadata(&path).map(|m| m.is_dir()).unwrap_or(false);

                // remove the file or directory
                let result = if is_dir {
                    fs::remove_dir(&path)
                } else {
                    fs::remove_file(&path)
                };

                match result {
                    Ok(_) => Message::Runlinkat { tag },
                    Err(e) => Message::Rlerror {
                        tag,
                        ecode: e.raw_os_error().unwrap_or(EIO as i32) as u32,
                    },
                }
            }

            Message::Tstatfs { tag, fid } => {
                let path = match self.path_for_fid(fid) {
                    Ok(path) => path,
                    Err(_) => {
                        return Message::Rlerror {
                            tag,
                            ecode: EIO as u32,
                        }
                    }
                };

                // Get filesystem stats - this is platform dependent
                // We'll provide a basic implementation with default values

                // Try to get some basic stats from the filesystem
                match fs::metadata(&path) {
                    Ok(_) => {
                        // Create a basic StatFs structure
                        // Many values will be placeholders as getting real statfs
                        // data requires platform-specific code
                        let statfs = StatFs {
                            r#type: 0x01021994, // A magic value for "Linux"
                            bsize: 4096,        // Default block size
                            blocks: 1000000,    // Placeholder
                            bfree: 500000,      // Placeholder
                            bavail: 450000,     // Placeholder
                            files: 1000000,     // Placeholder
                            ffree: 900000,      // Placeholder
                            fsid: 0,            // Placeholder
                            namelen: 255,       // Common max filename length
                        };

                        Message::Rstatfs { tag, statfs }
                    }
                    Err(e) => Message::Rlerror {
                        tag,
                        ecode: e.raw_os_error().unwrap_or(EIO as i32) as u32,
                    },
                }
            }

            Message::Tmknod {
                tag,
                dfid,
                name,
                mode,
                major,
                minor,
                gid,
            } => {
                // mknod is a privileged operation that creates device files
                // this implementation doesn't support device file creation
                Message::Rlerror {
                    tag,
                    ecode: EOPNOTSUPP as u32,
                }
            }

            Message::Txattrwalk {
                tag,
                fid,
                newfid,
                name,
            } => {
                // extended attributes not supported in this implementation
                Message::Rlerror {
                    tag,
                    ecode: EOPNOTSUPP as u32,
                }
            }

            Message::Txattrcreate {
                tag,
                fid,
                name,
                attr_size,
                flags,
            } => {
                // extended attributes not supported in this implementation
                Message::Rlerror {
                    tag,
                    ecode: EOPNOTSUPP as u32,
                }
            }

            Message::Tlock { tag, fid, lock } => {
                // file locking not supported in this implementation
                Message::Rlerror {
                    tag,
                    ecode: EOPNOTSUPP as u32,
                }
            }

            Message::Tgetlock { tag, fid, lock } => {
                // file locking not supported in this implementation
                Message::Rlerror {
                    tag,
                    ecode: EOPNOTSUPP as u32,
                }
            }
            _ => todo!(),
        }
    }
}
