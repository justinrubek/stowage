use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use stowage_proto::{
    Message, Qid, QidType, Rattach, Rclunk, Rcreate, Rerror, Rflush, Ropen, Rread, Rremove, Rstat,
    Rwalk, Rwrite, Rwstat, Stat, Tattach, Tclunk, Tcreate, Tflush, Topen, Tread, Tremove, Tstat,
    Twalk, Twrite, Twstat,
};
use stowage_service::MessageHandler;

// Standard open mode flags for 9P2000
const O_RDONLY: u8 = 0;
const O_WRONLY: u8 = 1;
const O_RDWR: u8 = 2;
const O_EXEC: u8 = 3;

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
}

impl MessageHandler for Handler {
    async fn attach(&self, message: &Tattach) -> Message {
        // establish a new fid that points to the root directory
        let root_path = self.dir.clone();

        // verify the root directory exists
        match fs::metadata(&root_path) {
            Ok(metadata) => {
                if !metadata.is_dir() {
                    return Message::Rerror(Rerror {
                        ename: "Not a directory".to_string(),
                    });
                }

                // create a qid for the root directory
                let qid = create_qid_from_metadata(&metadata);

                // store this fid in our mapping
                let mut fids = self.fids.lock().unwrap();
                fids.insert(
                    message.fid,
                    FidEntry {
                        path: root_path,
                        opened: false,
                        is_dir: true,
                        file: None,
                    },
                );

                Message::Rattach(Rattach { qid })
            }
            Err(e) => Message::Rerror(Rerror {
                ename: format!("Cannot attach: {e}"),
            }),
        }
    }

    async fn flush(&self, _: &Tflush) -> Message {
        // flush doesn't need special file operations for this implementation
        // it simply acknowledges the flush request
        Message::Rflush(Rflush)
    }

    async fn walk(&self, message: &Twalk) -> Message {
        let fid = message.fid;
        let newfid = message.newfid;
        let wnames = message.wnames.clone();

        // get the source path
        let Ok(source_path) = self.path_for_fid(fid) else {
            return Message::Rerror(Rerror {
                ename: "Fid not found".to_string(),
            });
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
                return Message::Rerror(Rerror {
                    ename: "Fid not found".to_string(),
                });
            }
        }

        // empty walk is just a fid clone
        if wnames.is_empty() {
            return Message::Rwalk(Rwalk { wqids: vec![] });
        }

        // walk through each path component
        let mut wqids = Vec::with_capacity(wnames.len());
        let mut current_path = source_path;

        for wname in &wnames {
            current_path = current_path.join(wname);

            if let Ok(metadata) = fs::metadata(&current_path) {
                let qid = create_qid_from_metadata(&metadata);
                wqids.push(qid);
            } else {
                // path component not found, return what we have
                if wqids.is_empty() {
                    return Message::Rerror(Rerror {
                        ename: "File not found".to_string(),
                    });
                }
                break;
            }
        }

        // if we successfully walked all components, update the newfid's path
        if wqids.len() == wnames.len() {
            let mut fids = self.fids.lock().unwrap();
            if let Some(entry) = fids.get_mut(&newfid) {
                entry.path.clone_from(&current_path);
                entry.is_dir = fs::metadata(&current_path)
                    .map(|m| m.is_dir())
                    .unwrap_or(false);
            }
        }

        Message::Rwalk(Rwalk { wqids })
    }

    async fn open(&self, message: &Topen) -> Message {
        let fid = message.fid;
        let mode = message.mode;

        let Ok(path) = self.path_for_fid(fid) else {
            return Message::Rerror(Rerror {
                ename: "Fid not found".to_string(),
            });
        };

        // convert 9P2000 open modes to rust file open options
        let mut options = OpenOptions::new();

        // translate 9P2000 mode flags to Rust OpenOptions
        match mode {
            O_RDONLY => {
                options.read(true);
            }
            O_WRONLY => {
                options.write(true);
            }
            O_RDWR => {
                options.read(true).write(true);
            }
            O_EXEC => {
                options.read(true); // Execute mode is just read in this implementation
            }
            _ => {
                return Message::Rerror(Rerror {
                    ename: "Invalid open mode".to_string(),
                })
            }
        }

        // attempt to open the file
        let result = if fs::metadata(&path).is_ok_and(|m| m.is_dir()) {
            // for directories, just get metadata and don't actually open a file
            Ok(None)
        } else {
            options.open(&path).map(Some)
        };

        match result {
            Ok(file_opt) => {
                match fs::metadata(&path) {
                    Ok(metadata) => {
                        let qid = create_qid_from_metadata(&metadata);
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

                        Message::Ropen(Ropen { qid, iounit })
                    }
                    Err(e) => Message::Rerror(Rerror {
                        ename: format!("Cannot stat file: {e}"),
                    }),
                }
            }
            Err(e) => Message::Rerror(Rerror {
                ename: format!("Cannot open file: {e}"),
            }),
        }
    }

    async fn create(&self, message: &Tcreate) -> Message {
        let fid = message.fid;
        let name = message.name.clone();
        let perm = message.perm;
        let mode = message.mode;

        let Ok(dir_path) = self.path_for_fid(fid) else {
            return Message::error("Fid not found".to_string());
        };

        // check if the parent is a directory
        match fs::metadata(&dir_path) {
            Ok(metadata) => {
                if !metadata.is_dir() {
                    return Message::Rerror(Rerror {
                        ename: "Not a directory".to_string(),
                    });
                }
            }
            Err(e) => return Message::error(format!("Cannot stat directory: {e}")),
        }

        // prepare the new file path
        let file_path = dir_path.join(&name);

        // convert 9P mode to rust file open options
        let mut options = OpenOptions::new();
        options.create(true);

        // translate 9P mode flags to Rust OpenOptions
        match mode {
            O_RDONLY => {
                options.read(true);
            }
            O_WRONLY => {
                options.write(true);
            }
            O_RDWR => {
                options.read(true).write(true);
            }
            _ => return Message::error("Invalid open mode".to_string()),
        }

        // Check if it's a directory create request
        let is_dir = (perm & 0x8000_0000) != 0;

        // Handle directory creation
        if is_dir {
            match fs::create_dir(&file_path) {
                Ok(()) => {
                    // Set permissions
                    #[cfg(unix)]
                    {
                        if let Ok(mut perms) = fs::metadata(&file_path).map(|m| m.permissions()) {
                            perms.set_mode(perm & 0o777);
                            let _ = fs::set_permissions(&file_path, perms);
                        }
                    }

                    match fs::metadata(&file_path) {
                        Ok(metadata) => {
                            let qid = create_qid_from_metadata(&metadata);

                            // Update the fid to point to the new directory
                            let mut fids = self.fids.lock().unwrap();
                            if let Some(entry) = fids.get_mut(&fid) {
                                entry.path = file_path;
                                entry.opened = true;
                                entry.is_dir = true;
                                entry.file = None;
                            }

                            Message::Rcreate(Rcreate { qid, iounit: 4096 })
                        }
                        Err(e) => Message::Rerror(Rerror {
                            ename: format!("Cannot stat new directory: {e}"),
                        }),
                    }
                }
                Err(e) => Message::error(format!("Cannot create directory: {e}")),
            }
        } else {
            // Handle regular file creation
            match options.open(&file_path) {
                Ok(file) => {
                    // set file permissions
                    #[cfg(unix)]
                    {
                        if let Ok(mut perms) = fs::metadata(&file_path).map(|m| m.permissions()) {
                            perms.set_mode(perm & 0o777);
                            let _ = fs::set_permissions(&file_path, perms);
                        }
                    }

                    match fs::metadata(&file_path) {
                        Ok(metadata) => {
                            let qid = create_qid_from_metadata(&metadata);

                            // update the fid entry to point to the new file
                            let mut fids = self.fids.lock().unwrap();
                            if let Some(entry) = fids.get_mut(&fid) {
                                entry.path = file_path;
                                entry.opened = true;
                                entry.is_dir = false;
                                entry.file = Some(file);
                            }

                            Message::Rcreate(Rcreate { qid, iounit: 4096 })
                        }
                        Err(e) => Message::error(format!("Cannot stat new file: {e}")),
                    }
                }
                Err(e) => Message::error(format!("Cannot create file: {e}")),
            }
        }
    }

    async fn read(&self, message: &Tread) -> Message {
        let fid = message.fid;
        let offset = message.offset;
        let count = message.count;

        // get the fid entry
        let mut fids = self.fids.lock().unwrap();
        let Some(entry) = fids.get_mut(&fid) else {
            return Message::Rerror(Rerror {
                ename: "Fid not found".to_string(),
            });
        };

        // ensure the file is opened
        if !entry.opened {
            return Message::Rerror(Rerror {
                ename: "File not open".to_string(),
            });
        }

        // handle different types of reads
        if entry.is_dir {
            // For directories, we need to read directory entries
            // and format them as stat structures

            let path = entry.path.clone();
            drop(fids); // release lock before filesystem operations

            let mut data = Vec::new();

            match fs::read_dir(&path) {
                Ok(read_dir) => {
                    // Skip entries before offset
                    let entries: Vec<_> = read_dir.collect();
                    let entries_to_process = entries
                        .into_iter()
                        .skip(usize::try_from(offset).unwrap())
                        .take(count as usize / 128); // Rough estimate of stat size

                    for dir_entry in entries_to_process.flatten() {
                        if let Ok(metadata) = dir_entry.metadata() {
                            // Create a stat for each entry
                            let _stat = stat_from_metadata(&metadata, &dir_entry.path());

                            // Encode the stat structure to bytes
                            // This is simplified - you would need proper encoding logic here
                            // to serialize the stat structure

                            // For this example, we'll just append some placeholder data
                            // In a real implementation, you would encode each stat structure
                            data.extend_from_slice(&[0; 128]); // Placeholder
                        }
                    }

                    Message::Rread(Rread { data: data.into() })
                }
                Err(e) => Message::Rerror(Rerror {
                    ename: format!("Cannot read directory: {e}"),
                }),
            }
        } else {
            // read from regular file
            let Some(file) = &mut entry.file else {
                return Message::Rerror(Rerror {
                    ename: "No file handle".to_string(),
                });
            };

            // seek to the offset
            if let Err(e) = file.seek(SeekFrom::Start(offset)) {
                return Message::Rerror(Rerror {
                    ename: format!("Seek error: {e}"),
                });
            }

            // allocate buffer and read data
            let mut buffer = vec![0; count as usize];
            match file.read(&mut buffer) {
                Ok(n) => {
                    buffer.truncate(n);
                    Message::Rread(Rread {
                        data: buffer.into(),
                    })
                }
                Err(e) => Message::Rerror(Rerror {
                    ename: format!("Read error: {e}"),
                }),
            }
        }
    }

    async fn write(&self, message: &Twrite) -> Message {
        let fid = message.fid;
        let offset = message.offset;
        let data = message.data.clone();

        // get the fid entry
        let mut fids = self.fids.lock().unwrap();
        let Some(entry) = fids.get_mut(&fid) else {
            return Message::Rerror(Rerror {
                ename: "Fid not found".to_string(),
            });
        };

        // ensure the file is opened
        if !entry.opened {
            return Message::Rerror(Rerror {
                ename: "File not open".to_string(),
            });
        }

        // get the file handle
        let Some(file) = &mut entry.file else {
            return Message::Rerror(Rerror {
                ename: "No file handle".to_string(),
            });
        };

        // seek to the offset
        if let Err(e) = file.seek(SeekFrom::Start(offset)) {
            return Message::Rerror(Rerror {
                ename: format!("Seek error: {e}"),
            });
        }

        // write the data
        match file.write(&data) {
            Ok(count) => Message::Rwrite(Rwrite {
                count: u32::try_from(count).unwrap(), // unwrap - 9p data cannot exceed u32 size
            }),
            Err(e) => Message::Rerror(Rerror {
                ename: format!("Write error: {e}"),
            }),
        }
    }

    async fn clunk(&self, message: &Tclunk) -> Message {
        let fid = message.fid;

        // remove the fid from the map
        let mut fids = self.fids.lock().unwrap();

        // close any open file handle before removing
        if fids.remove(&fid).is_some() {
            // file will be closed when dropped by remove
        }

        // return success
        Message::Rclunk(Rclunk)
    }

    async fn remove(&self, message: &Tremove) -> Message {
        let fid = message.fid;

        // get the path
        let Ok(path) = self.path_for_fid(fid) else {
            return Message::Rerror(Rerror {
                ename: "Fid not found".to_string(),
            });
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
            Ok(()) => Message::Rremove(Rremove),
            Err(e) => Message::Rerror(Rerror {
                ename: format!("Remove error: {e}"),
            }),
        }
    }

    async fn stat(&self, message: &Tstat) -> Message {
        let fid = message.fid;

        // get the path and metadata for this fid
        let Ok(path) = self.path_for_fid(fid) else {
            return Message::Rerror(Rerror {
                ename: "Fid not found".to_string(),
            });
        };

        match fs::metadata(&path) {
            Ok(metadata) => {
                let stat = stat_from_metadata(&metadata, &path);
                Message::Rstat(Rstat { stat })
            }
            Err(e) => Message::Rerror(Rerror {
                ename: format!("Stat error: {e}"),
            }),
        }
    }

    async fn wstat(&self, message: &Twstat) -> Message {
        let fid = message.fid;
        let stat = &message.stat;

        // get the path
        let Ok(path) = self.path_for_fid(fid) else {
            return Message::Rerror(Rerror {
                ename: "Fid not found".to_string(),
            });
        };

        let mut error = None;

        // change permissions if mode is not ~0
        if stat.mode != 0xFFFF_FFFF {
            #[cfg(unix)]
            {
                if let Ok(mut perms) = fs::metadata(&path).map(|m| m.permissions()) {
                    perms.set_mode(stat.mode & 0o777);
                    if let Err(e) = fs::set_permissions(&path, perms) {
                        error = Some(e);
                    }
                } else {
                    error = Some(io::Error::other("Failed to get permissions"));
                }
            }
        }

        // change file size if length is not ~0
        if error.is_none() && stat.length != 0xFFFF_FFFF_FFFF_FFFF {
            if let Err(e) = fs::OpenOptions::new()
                .write(true)
                .open(&path)
                .and_then(|file| file.set_len(stat.length))
            {
                error = Some(e);
            }
        }

        // change name if not empty (rename file)
        if error.is_none() && !stat.name.is_empty() && stat.name != "." && stat.name != ".." {
            let parent = path.parent().unwrap_or(Path::new("."));
            let new_path = parent.join(&stat.name);

            if let Err(e) = fs::rename(&path, &new_path) {
                error = Some(e);
            } else {
                // Update the path in our fid table
                let mut fids = self.fids.lock().unwrap();
                if let Some(entry) = fids.get_mut(&fid) {
                    entry.path = new_path;
                }
            }
        }

        // note: In a full implementation, you might also handle:
        // - change owner/group (requires root)
        // - change modification times (requires specialized calls)

        match error {
            Some(e) => Message::Rerror(Rerror {
                ename: format!("Cannot change file attributes: {e}"),
            }),
            None => Message::Rwstat(Rwstat),
        }
    }
}

fn create_qid_from_metadata(metadata: &fs::Metadata) -> Qid {
    let qtype = if metadata.is_dir() {
        QidType::Dir as u8
    } else {
        QidType::File as u8
    };

    Qid {
        qtype,
        version: 0, // version is not tracked in this implementation
        path: metadata.ino(),
    }
}

fn stat_from_metadata(metadata: &fs::Metadata, path: &Path) -> Stat {
    let qid = create_qid_from_metadata(metadata);

    Stat {
        r#type: u16::from(qid.qtype),
        dev: 0, // not needed for this implementation
        qid,
        mode: metadata.mode(),
        atime: u32::try_from(metadata.atime()).unwrap(),
        mtime: u32::try_from(metadata.mtime()).unwrap(),
        length: metadata.len(),
        name: path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string(),
        uid: metadata.uid().to_string(),
        gid: metadata.gid().to_string(),
        muid: String::new(), // not tracked in this implementation
    }
}
