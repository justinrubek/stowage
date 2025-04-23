use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use stowage_proto::{Message, Qid, Stat};
use stowage_service::MessageHandler;
use tracing::info;

#[derive(Debug, Clone)]
enum FsNode {
    File {
        name: String,
        content: Vec<u8>,
        qid: Qid,
        mode: u32,
        atime: Timespec,
        mtime: Timespec,
        ctime: Timespec,
        creation_time: Timespec,
    },
    Directory {
        name: String,
        children: HashMap<String, Arc<Mutex<FsNode>>>,
        qid: Qid,
        mode: u32,
        atime: Timespec,
        mtime: Timespec,
        ctime: Timespec,
        creation_time: Timespec,
    },
}

impl FsNode {
    pub fn qid(&self) -> Qid {
        match self {
            FsNode::Directory { qid, .. } => qid.clone(),
            FsNode::File { qid, .. } => qid.clone(),
        }
    }

    pub fn atime_sec(&self) -> u64 {
        match self {
            FsNode::Directory { atime, .. } => atime.sec,
            FsNode::File { atime, .. } => atime.sec,
        }
    }

    pub fn atime_nsec(&self) -> u64 {
        match self {
            FsNode::Directory { atime, .. } => atime.nsec,
            FsNode::File { atime, .. } => atime.nsec,
        }
    }

    pub fn mtime_sec(&self) -> u64 {
        match self {
            FsNode::Directory { mtime, .. } => mtime.sec,
            FsNode::File { mtime, .. } => mtime.sec,
        }
    }

    pub fn mtime_nsec(&self) -> u64 {
        match self {
            FsNode::Directory { mtime, .. } => mtime.nsec,
            FsNode::File { mtime, .. } => mtime.nsec,
        }
    }

    pub fn ctime_sec(&self) -> u64 {
        match self {
            FsNode::Directory { ctime, .. } => ctime.sec,
            FsNode::File { ctime, .. } => ctime.sec,
        }
    }

    pub fn ctime_nsec(&self) -> u64 {
        match self {
            FsNode::Directory { ctime, .. } => ctime.nsec,
            FsNode::File { ctime, .. } => ctime.nsec,
        }
    }

    pub fn creation_time_sec(&self) -> u64 {
        match self {
            FsNode::Directory { creation_time, .. } => creation_time.sec,
            FsNode::File { creation_time, .. } => creation_time.sec,
        }
    }

    pub fn creation_time_nsec(&self) -> u64 {
        match self {
            FsNode::Directory { creation_time, .. } => creation_time.nsec,
            FsNode::File { creation_time, .. } => creation_time.nsec,
        }
    }

    pub fn update_atime(&mut self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0));

        let timestamp = Timespec {
            sec: now.as_secs(),
            nsec: now.subsec_nanos() as u64,
        };

        match self {
            FsNode::Directory { atime, .. } => *atime = timestamp,
            FsNode::File { atime, .. } => *atime = timestamp,
        }
    }

    pub fn update_mtime(&mut self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0));

        let timestamp = Timespec {
            sec: now.as_secs(),
            nsec: now.subsec_nanos() as u64,
        };

        match self {
            FsNode::Directory { mtime, qid, .. } => {
                *mtime = timestamp;
                qid.version += 1;
            }
            FsNode::File { mtime, qid, .. } => {
                *mtime = timestamp;
                qid.version += 1;
            }
        }
    }

    pub fn update_ctime(&mut self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0));

        let timestamp = Timespec {
            sec: now.as_secs(),
            nsec: now.subsec_nanos() as u64,
        };

        match self {
            FsNode::Directory { ctime, .. } => *ctime = timestamp,
            FsNode::File { ctime, .. } => *ctime = timestamp,
        }
    }

    fn to_stat(&self) -> Stat {
        match self {
            FsNode::Directory {
                name,
                children,
                qid,
                mode,
                atime,
                mtime,
                ..
            } => {
                Stat {
                    qtype: 0x80, // QTDIR
                    dev: 0,
                    qid: qid.clone(),
                    mode: *mode | 0x80000000, // directory permission + DMDIR flag
                    atime: atime.sec as u32,
                    mtime: mtime.sec as u32,
                    length: 0, // directories have zero length
                    name: name.clone(),
                    uid: "user".to_string(),
                    gid: "user".to_string(),
                    muid: "user".to_string(),
                }
            }
            FsNode::File {
                name,
                content,
                qid,
                mode,
                atime,
                mtime,
                ..
            } => Stat {
                qtype: 0,
                dev: 0,
                qid: qid.clone(),
                mode: *mode,
                atime: atime.sec as u32,
                mtime: mtime.sec as u32,
                length: content.len() as u64,
                name: name.clone(),
                uid: "user".to_string(),
                gid: "user".to_string(),
                muid: "user".to_string(),
            },
        }
    }
}

#[derive(Clone, Debug)]
pub struct Timespec {
    pub sec: u64,
    pub nsec: u64,
}

impl Timespec {
    pub fn now() -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0));

        Timespec {
            sec: now.as_secs(),
            nsec: now.subsec_nanos() as u64,
        }
    }
}

/// Tracks an opened fid and its state
#[derive(Debug, Clone)]
struct FidState {
    node: Arc<Mutex<FsNode>>,
    is_open: bool,
    open_mode: Option<u32>,
    path: Vec<String>,
}

pub struct Handler {
    root: Arc<Mutex<FsNode>>,
    fids: Mutex<HashMap<u32, FidState>>,
    next_qid_path: Mutex<u64>,
}

impl Handler {
    pub fn new() -> Self {
        let now = Timespec::now();
        let root = FsNode::Directory {
            name: "/".to_string(),
            children: HashMap::new(),
            qid: Qid {
                qtype: 0x80, // QTDIR
                version: 0,
                path: 0,
            },
            mode: 0o755,
            atime: now.clone(),
            mtime: now.clone(),
            ctime: now.clone(),
            creation_time: now,
        };

        Self {
            root: Arc::new(Mutex::new(root)),
            fids: Mutex::new(HashMap::new()),
            next_qid_path: Mutex::new(1), // 0 is reserved for root
        }
    }

    fn next_qid(&self, is_dir: bool) -> Qid {
        let mut next_path = self.next_qid_path.lock().unwrap();
        let path = *next_path;
        *next_path += 1;

        Qid {
            qtype: if is_dir { 0x80 } else { 0 }, // QTDIR or QTFILE
            version: 0,
            path,
        }
    }

    /// Find a node by path elements
    fn find_node(&self, path_elements: &[String]) -> Option<Arc<Mutex<FsNode>>> {
        if path_elements.is_empty() {
            return Some(self.root.clone());
        }

        let mut current = self.root.clone();

        for element in path_elements {
            // use a block scope to ensure the lock is released before reassigning current
            let next_node = {
                let node = current.lock().unwrap();
                match &*node {
                    FsNode::Directory { children, .. } => children.get(element).cloned(),
                    FsNode::File { .. } => None, // Cannot navigate into a file
                }
            };

            // process the result after the lock is released
            if let Some(child) = next_node {
                current = child;
            } else {
                return None;
            }
        }

        Some(current)
    }

    // create a directory entry list for Rread of a directory
    fn create_dir_entries(&self, dir_node: &FsNode) -> Vec<u8> {
        let mut result = Vec::new();

        if let FsNode::Directory { children, .. } = dir_node {
            // create a consistent stat structure format based on 9P2000 spec
            for (name, child) in children {
                let child_node = child.lock().unwrap();
                let stat = child_node.to_stat();

                // format correctly according to 9P spec:
                // size[2] + type[2] + dev[4] + qid.type[1] + qid.vers[4] + qid.path[8] +
                // mode[4] + atime[4] + mtime[4] + length[8] +
                // name[s] + uid[s] + gid[s] + muid[s]

                // Start with calculating the size (excluding size field itself)
                let strings_len = 2
                    + stat.name.len()
                    + 2
                    + stat.uid.len()
                    + 2
                    + stat.gid.len()
                    + 2
                    + stat.muid.len();
                let fixed_fields_len = 2 + 4 + 13 + 4 + 4 + 4 + 8; // All fixed-size fields
                let stat_size = fixed_fields_len + strings_len;

                // Now build the entry
                let mut entry = Vec::with_capacity(stat_size + 2);

                // Size field (2 bytes) - excluding itself
                entry.extend_from_slice(&(stat_size as u16).to_le_bytes());

                // Type field (2 bytes)
                entry.extend_from_slice(&(stat.qtype as u16).to_le_bytes());

                // Dev field (4 bytes)
                entry.extend_from_slice(&stat.dev.to_le_bytes());

                // Qid (13 bytes: 1+4+8)
                entry.push(stat.qid.qtype);
                entry.extend_from_slice(&stat.qid.version.to_le_bytes());
                entry.extend_from_slice(&stat.qid.path.to_le_bytes());

                // Mode (4 bytes)
                entry.extend_from_slice(&stat.mode.to_le_bytes());

                // Atime (4 bytes)
                entry.extend_from_slice(&stat.atime.to_le_bytes());

                // Mtime (4 bytes)
                entry.extend_from_slice(&stat.mtime.to_le_bytes());

                // Length (8 bytes)
                entry.extend_from_slice(&stat.length.to_le_bytes());

                // Strings
                for s in &[&stat.name, &stat.uid, &stat.gid, &stat.muid] {
                    entry.extend_from_slice(&(s.len() as u16).to_le_bytes());
                    entry.extend_from_slice(s.as_bytes());
                }

                // Add to result
                result.extend_from_slice(&entry);
            }
        }

        result
    }
}

impl MessageHandler for Handler {
    async fn handle_message(&self, message: Message) -> Message {
        info!(?message);

        match message {
            Message::Tversion { tag, msize, .. } => Message::Rversion {
                tag,
                msize: msize.min(8192),
                version: "9P2000.L".to_string(),
            },

            Message::Tauth { tag, .. } => {
                // We don't require authentication
                Message::Rlerror {
                    tag,
                    ecode: 2, // EOPNOTSUPP (Operation not supported)
                }
            }

            Message::Tattach { tag, fid, .. } => {
                // Create a new fid pointing to the root directory
                let mut fids = self.fids.lock().unwrap();

                fids.insert(
                    fid,
                    FidState {
                        node: self.root.clone(),
                        is_open: false,
                        open_mode: None,
                        path: Vec::new(),
                    },
                );

                Message::Rattach {
                    tag,
                    qid: self.root.lock().unwrap().qid(),
                }
            }

            Message::Twalk {
                tag,
                fid,
                newfid,
                wnames,
            } => {
                let mut fids = self.fids.lock().unwrap();

                // Check if source fid exists
                if !fids.contains_key(&fid) {
                    return Message::Rerror {
                        tag,
                        ename: "Source fid not found".to_string(),
                    };
                }

                // Special case: empty walk = clone the fid
                if wnames.is_empty() {
                    let source_state = fids.get(&fid).unwrap().clone();
                    fids.insert(newfid, source_state);

                    return Message::Rwalk {
                        tag,
                        wqids: Vec::new(),
                    };
                }

                // Get the starting point and create a path copy
                let source_state = fids.get(&fid).unwrap();
                let mut current_path = source_state.path.clone();
                let mut current_node = source_state.node.clone();
                let mut wqids = Vec::new();

                // Walk through each element
                for wname in &wnames {
                    // This block scope ensures the lock is released before reassigning current_node
                    let next_node = {
                        let node = current_node.lock().unwrap();
                        match &*node {
                            FsNode::Directory { children, .. } => {
                                if let Some(child) = children.get(wname) {
                                    Some(child.clone())
                                } else {
                                    None
                                }
                            }
                            FsNode::File { .. } => {
                                // Cannot walk through a file
                                return Message::Rerror {
                                    tag,
                                    ename: "Cannot walk through a file".to_string(),
                                };
                            }
                        }
                    };

                    // Process the result after the lock is released
                    if let Some(child) = next_node {
                        current_path.push(wname.clone());
                        wqids.push(child.lock().unwrap().qid());
                        current_node = child; // No borrowing conflict now
                    } else {
                        // Path element not found
                        if wqids.is_empty() {
                            return Message::Rlerror { tag, ecode: 2 };
                        }
                        break;
                    }
                }

                // Create the new fid if we walked the entire path
                if wqids.len() == wnames.len() {
                    fids.insert(
                        newfid,
                        FidState {
                            node: current_node,
                            is_open: false,
                            open_mode: None,
                            path: current_path,
                        },
                    );
                }

                Message::Rwalk { tag, wqids }
            }

            Message::Tlopen { tag, fid, flags } => {
                let mut fids = self.fids.lock().unwrap();

                // Check if fid exists
                if !fids.contains_key(&fid) {
                    return Message::Rlerror {
                        tag,
                        ecode: 2, // ENOENT
                    };
                }

                let fid_state = fids.get_mut(&fid).unwrap();

                if fid_state.is_open {
                    return Message::Rlerror {
                        tag,
                        ecode: 9, // EBADF
                    };
                }

                // Update the atime
                fid_state.node.lock().unwrap().update_atime();

                // Mark as open
                fid_state.is_open = true;
                fid_state.open_mode = Some(flags);

                let node = fid_state.node.lock().unwrap();
                let qid = node.qid();

                // Check if this is a directory and open flags are compatible
                match &*node {
                    FsNode::Directory { .. } => {
                        // For directories, typically only O_RDONLY (0) is allowed
                        if flags & 3 != 0 {
                            // Check if not O_RDONLY
                            return Message::Rlerror {
                                tag,
                                ecode: 21, // EISDIR
                            };
                        }
                    }
                    FsNode::File { .. } => {
                        // Files can have any open mode
                    }
                }

                Message::Rlopen {
                    tag,
                    qid,
                    iounit: 8192, // Maximum recommended transfer size
                }
            }

            Message::Tread {
                tag,
                fid,
                offset,
                count,
            } => {
                let mut fids = self.fids.lock().unwrap();

                // Check if fid exists and is open
                if !fids.contains_key(&fid) {
                    return Message::Rerror {
                        tag,
                        ename: "Fid not found".to_string(),
                    };
                }

                let fid_state = fids.get_mut(&fid).unwrap();

                if !fid_state.is_open {
                    return Message::Rerror {
                        tag,
                        ename: "Fid not open".to_string(),
                    };
                }

                let mut node = fid_state.node.lock().unwrap();
                node.update_atime();

                match &*node {
                    FsNode::File { content, .. } => {
                        // Read from file
                        let start = offset as usize;
                        let end = (offset + count as u64).min(content.len() as u64) as usize;

                        let data = if start >= content.len() {
                            Vec::new() // End of file
                        } else {
                            content[start..end].to_vec()
                        };

                        Message::Rread { tag, data }
                    }
                    FsNode::Directory { .. } => {
                        // For directories, we need to return directory entries
                        let dir_entries = self.create_dir_entries(&node);

                        // Apply offset and count
                        let start = offset as usize;
                        let end = (offset + count as u64).min(dir_entries.len() as u64) as usize;

                        let data = if start >= dir_entries.len() {
                            Vec::new() // End of directory
                        } else {
                            dir_entries[start..end].to_vec()
                        };

                        Message::Rread { tag, data }
                    }
                }
            }

            Message::Twrite {
                tag,
                fid,
                offset,
                data,
            } => {
                let mut fids = self.fids.lock().unwrap();

                // check if fid exists and is open for writing
                if !fids.contains_key(&fid) {
                    return Message::Rerror {
                        tag,
                        ename: "Fid not found".to_string(),
                    };
                }

                let fid_state = fids.get_mut(&fid).unwrap();

                if !fid_state.is_open {
                    return Message::Rerror {
                        tag,
                        ename: "Fid not open".to_string(),
                    };
                }

                // check write permission (simplified)
                let open_mode = fid_state.open_mode.unwrap_or(0);
                if open_mode & 0x01 == 0 && open_mode & 0x02 == 0 {
                    // Not O_WRITE or O_RDWR
                    return Message::Rerror {
                        tag,
                        ename: "Permission denied".to_string(),
                    };
                }

                let mut node = fid_state.node.lock().unwrap();

                match &mut *node {
                    FsNode::File {
                        ref mut content, ..
                    } => {
                        // write to file
                        let start = offset as usize;

                        // ensure file is large enough
                        if start + data.len() > content.len() {
                            content.resize(start + data.len(), 0);
                        }

                        // write the data
                        content[start..start + data.len()].copy_from_slice(&data);

                        // update modification time
                        node.update_mtime();

                        Message::Rwrite {
                            tag,
                            count: data.len() as u32,
                        }
                    }
                    FsNode::Directory { .. } => Message::Rerror {
                        tag,
                        ename: "Cannot write to directory".to_string(),
                    },
                }
            }

            Message::Tclunk { tag, fid } => {
                let mut fids = self.fids.lock().unwrap();

                if fids.remove(&fid).is_some() {
                    Message::Rclunk { tag }
                } else {
                    Message::Rerror {
                        tag,
                        ename: "Fid not found".to_string(),
                    }
                }
            }

            Message::Tremove { tag, fid } => {
                let mut fids = self.fids.lock().unwrap();

                if !fids.contains_key(&fid) {
                    return Message::Rerror {
                        tag,
                        ename: "Fid not found".to_string(),
                    };
                }

                let fid_state = fids.get(&fid).unwrap().clone();
                let path_elements = fid_state.path.clone();

                // cannot remove root
                if path_elements.is_empty() {
                    fids.remove(&fid);
                    return Message::Rerror {
                        tag,
                        ename: "Cannot remove root directory".to_string(),
                    };
                }

                // find parent directory
                let parent_path = &path_elements[0..path_elements.len() - 1];
                let filename = path_elements.last().unwrap();

                if let Some(parent_node) = self.find_node(parent_path) {
                    let mut parent = parent_node.lock().unwrap();

                    match &mut *parent {
                        FsNode::Directory {
                            ref mut children, ..
                        } => {
                            // remove the entry
                            if children.remove(filename).is_some() {
                                // update modification time
                                parent.update_mtime();

                                // remove the fid regardless of success
                                fids.remove(&fid);

                                return Message::Rremove { tag };
                            } else {
                                fids.remove(&fid);
                                return Message::Rerror {
                                    tag,
                                    ename: "File not found".to_string(),
                                };
                            }
                        }
                        FsNode::File { .. } => {
                            fids.remove(&fid);
                            return Message::Rerror {
                                tag,
                                ename: "Parent is not a directory".to_string(),
                            };
                        }
                    }
                } else {
                    fids.remove(&fid);
                    return Message::Rerror {
                        tag,
                        ename: "Parent directory not found".to_string(),
                    };
                }
            }

            Message::Tgetattr {
                tag,
                fid,
                request_mask,
            } => {
                let fids = self.fids.lock().unwrap();

                // Check if fid exists
                if !fids.contains_key(&fid) {
                    return Message::Rlerror {
                        tag,
                        ecode: 2, // ENOENT
                    };
                }

                let fid_state = fids.get(&fid).unwrap();
                let node = fid_state.node.lock().unwrap();

                // Default values
                let (mode, size, nlink) = match &*node {
                    FsNode::Directory { mode, children, .. } => {
                        // For directories: appropriate mode with directory bit, size 0, link count based on children + 2 (. and ..)
                        (*mode | 0x80000000, 0, (children.len() + 2) as u64)
                    }
                    FsNode::File { mode, content, .. } => {
                        // For files: file mode, content size, link count 1
                        (*mode, content.len() as u64, 1)
                    }
                };

                // TODO: filter based on request_mask
                let valid = 0xFFFFFFFF; // all fields valid

                Message::Rgetattr {
                    tag,
                    valid,
                    qid: node.qid(),
                    mode,
                    uid: 1000, // default user ID
                    gid: 1000, // default group ID
                    nlink,
                    rdev: 0, // not a device file
                    size,
                    blksize: 4096,                // default block size
                    blocks: (size + 4095) / 4096, // number of blocks used (rounded up)
                    atime_sec: node.atime_sec(),
                    atime_nsec: node.atime_nsec(),
                    mtime_sec: node.mtime_sec(),
                    mtime_nsec: node.mtime_nsec(),
                    ctime_sec: node.ctime_sec(),
                    ctime_nsec: node.ctime_nsec(),
                    btime_sec: node.creation_time_sec(),
                    btime_nsec: node.creation_time_nsec(),
                    gen: 0,          // generation number (not used)
                    data_version: 0, // data version (not used)
                }
            }

            Message::Tstat { tag, fid } => {
                let fids = self.fids.lock().unwrap();

                // check if fid exists
                if !fids.contains_key(&fid) {
                    return Message::Rerror {
                        tag,
                        ename: "Fid not found".to_string(),
                    };
                }

                let fid_state = fids.get(&fid).unwrap();
                let node = fid_state.node.lock().unwrap();

                Message::Rstat {
                    tag,
                    stat: node.to_stat(),
                }
            }

            Message::Twstat { tag, fid, stat } => {
                let fids = self.fids.lock().unwrap();

                // check if fid exists
                if !fids.contains_key(&fid) {
                    return Message::Rerror {
                        tag,
                        ename: "Fid not found".to_string(),
                    };
                }

                let fid_state = fids.get(&fid).unwrap();
                let mut node = fid_state.node.lock().unwrap();

                // for simplicity, we only allow changing mode and name
                match &mut *node {
                    FsNode::File {
                        ref mut name,
                        ref mut mode,
                        ..
                    } => {
                        // update fields if they're not ~0 (which means don't change)
                        if stat.mode != 0xFFFFFFFF {
                            *mode = stat.mode & 0o777; // Only allow changing permission bits
                        }

                        if !stat.name.is_empty() {
                            // changing name would require updating the parent directory too
                            // for simplicity, we don't allow this
                            // *name = stat.name.clone();
                            return Message::Rerror {
                                tag,
                                ename: "Changing name not supported".to_string(),
                            };
                        }

                        node.update_mtime();

                        Message::Rwstat { tag }
                    }
                    FsNode::Directory {
                        ref mut name,
                        ref mut mode,
                        ..
                    } => {
                        // update fields if they're not ~0 (which means don't change)
                        if stat.mode != 0xFFFFFFFF {
                            *mode = stat.mode & 0o777; // Only allow changing permission bits
                        }

                        if !stat.name.is_empty() {
                            // changing name would require updating the parent directory too
                            // for simplicity, we don't allow this
                            // *name = stat.name.clone();
                            return Message::Rerror {
                                tag,
                                ename: "Changing name not supported".to_string(),
                            };
                        }

                        node.update_mtime();

                        Message::Rwstat { tag }
                    }
                }
            }

            _ => Message::Rerror {
                tag: message.get_tag(),
                ename: "Operation not implemented".to_string(),
            },
        }
    }
}
