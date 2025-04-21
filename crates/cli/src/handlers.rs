use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use stowage_proto::{Message, Qid, Stat};
use stowage_service::MessageHandler;

#[derive(Debug, Clone)]
enum FsNode {
    File {
        name: String,
        content: Vec<u8>,
        qid: Qid,
        mode: u32,
        atime: u32,
        mtime: u32,
    },
    Directory {
        name: String,
        children: HashMap<String, Arc<Mutex<FsNode>>>,
        qid: Qid,
        mode: u32,
        atime: u32,
        mtime: u32,
    },
}

impl FsNode {
    fn qid(&self) -> Qid {
        match self {
            FsNode::File { qid, .. } => qid.clone(),
            FsNode::Directory { qid, .. } => qid.clone(),
        }
    }

    fn name(&self) -> String {
        match self {
            FsNode::File { name, .. } => name.clone(),
            FsNode::Directory { name, .. } => name.clone(),
        }
    }

    fn update_atime(&mut self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        match self {
            FsNode::File { atime, .. } => *atime = now,
            FsNode::Directory { atime, .. } => *atime = now,
        }
    }

    fn update_mtime(&mut self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        match self {
            FsNode::File { mtime, .. } => *mtime = now,
            FsNode::Directory { mtime, .. } => *mtime = now,
        }
    }

    fn to_stat(&self) -> Stat {
        match self {
            FsNode::File {
                name,
                content,
                qid,
                mode,
                atime,
                mtime,
            } => {
                Stat {
                    qtype: 0x00, // Regular file
                    dev: 0,
                    qid: qid.clone(),
                    mode: *mode,
                    atime: *atime,
                    mtime: *mtime,
                    length: content.len() as u64,
                    name: name.clone(),
                    uid: "nobody".to_string(),
                    gid: "nobody".to_string(),
                    muid: "nobody".to_string(),
                }
            }
            FsNode::Directory {
                name,
                qid,
                mode,
                atime,
                mtime,
                children,
            } => {
                Stat {
                    qtype: 0x80, // Directory
                    dev: 0,
                    qid: qid.clone(),
                    mode: *mode | 0x80000000, // DMDIR flag
                    atime: *atime,
                    mtime: *mtime,
                    length: 0,
                    name: name.clone(),
                    uid: "nobody".to_string(),
                    gid: "nobody".to_string(),
                    muid: "nobody".to_string(),
                }
            }
        }
    }
}

/// Tracks an opened fid and its state
#[derive(Debug, Clone)]
struct FidState {
    node: Arc<Mutex<FsNode>>,
    is_open: bool,
    open_mode: Option<u8>,
    path: Vec<String>,
}

pub struct Memory {
    root: Arc<Mutex<FsNode>>,
    fids: Mutex<HashMap<u32, FidState>>,
    next_qid_path: Mutex<u64>,
}

impl Memory {
    pub fn new() -> Self {
        // Create root directory
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        let root = FsNode::Directory {
            name: "/".to_string(),
            children: HashMap::new(),
            qid: Qid {
                qtype: 0x80, // QTDIR
                version: 0,
                path: 0,
            },
            mode: 0o755,
            atime: now,
            mtime: now,
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
            // Use a block scope to ensure the lock is released before reassigning current
            let next_node = {
                let node = current.lock().unwrap();
                match &*node {
                    FsNode::Directory { children, .. } => children.get(element).cloned(),
                    FsNode::File { .. } => None, // Cannot navigate into a file
                }
            };

            // Process the result after the lock is released
            if let Some(child) = next_node {
                current = child;
            } else {
                return None;
            }
        }

        Some(current)
    }

    // Create a directory entry list for Rread of a directory
    fn create_dir_entries(&self, dir_node: &FsNode) -> Vec<u8> {
        let mut result = Vec::new();

        if let FsNode::Directory { children, .. } = dir_node {
            // Add entry for current directory
            let stat = dir_node.to_stat();
            let mut entry_size = 2 + 13 + 4 + 4 + 4 + 8; // Fixed size elements
            entry_size += 2 + stat.name.len(); // name
            entry_size += 2 + stat.uid.len(); // uid
            entry_size += 2 + stat.gid.len(); // gid
            entry_size += 2 + stat.muid.len(); // muid

            let mut entry = Vec::with_capacity(entry_size + 2);
            entry.extend_from_slice(&(entry_size as u16).to_le_bytes());
            entry.extend_from_slice(&stat.qtype.to_le_bytes());
            entry.extend_from_slice(&0u32.to_le_bytes()); // dev
            entry.extend_from_slice(&stat.qid.qtype.to_le_bytes());
            entry.extend_from_slice(&stat.qid.version.to_le_bytes());
            entry.extend_from_slice(&stat.qid.path.to_le_bytes());
            entry.extend_from_slice(&stat.mode.to_le_bytes());
            entry.extend_from_slice(&stat.atime.to_le_bytes());
            entry.extend_from_slice(&stat.mtime.to_le_bytes());
            entry.extend_from_slice(&stat.length.to_le_bytes());

            // Add strings
            for s in &[&stat.name, &stat.uid, &stat.gid, &stat.muid] {
                entry.extend_from_slice(&(s.len() as u16).to_le_bytes());
                entry.extend_from_slice(s.as_bytes());
            }

            result.extend_from_slice(&entry);

            // Add entries for all children
            for (_, child) in children {
                let child_node = child.lock().unwrap();
                let stat = child_node.to_stat();

                let mut entry_size = 2 + 13 + 4 + 4 + 4 + 8; // Fixed size elements
                entry_size += 2 + stat.name.len(); // name
                entry_size += 2 + stat.uid.len(); // uid
                entry_size += 2 + stat.gid.len(); // gid
                entry_size += 2 + stat.muid.len(); // muid

                let mut entry = Vec::with_capacity(entry_size + 2);
                entry.extend_from_slice(&(entry_size as u16).to_le_bytes());
                entry.extend_from_slice(&stat.qtype.to_le_bytes());
                entry.extend_from_slice(&0u32.to_le_bytes()); // dev
                entry.extend_from_slice(&stat.qid.qtype.to_le_bytes());
                entry.extend_from_slice(&stat.qid.version.to_le_bytes());
                entry.extend_from_slice(&stat.qid.path.to_le_bytes());
                entry.extend_from_slice(&stat.mode.to_le_bytes());
                entry.extend_from_slice(&stat.atime.to_le_bytes());
                entry.extend_from_slice(&stat.mtime.to_le_bytes());
                entry.extend_from_slice(&stat.length.to_le_bytes());

                // Add strings
                for s in &[&stat.name, &stat.uid, &stat.gid, &stat.muid] {
                    entry.extend_from_slice(&(s.len() as u16).to_le_bytes());
                    entry.extend_from_slice(s.as_bytes());
                }

                result.extend_from_slice(&entry);
            }
        }

        result
    }
}

impl MessageHandler for Memory {
    async fn handle_message(&self, message: Message) -> Message {
        match message {
            Message::Tversion { tag, msize, .. } => Message::Rversion {
                tag,
                msize: msize.min(8192),
                version: "9P2000".to_string(),
            },

            Message::Tauth { tag, .. } => {
                // We don't require authentication
                Message::Rerror {
                    tag,
                    ename: "Authentication not required".to_string(),
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
                            return Message::Rerror {
                                tag,
                                ename: "Path not found".to_string(),
                            };
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

            Message::Topen { tag, fid, mode } => {
                let mut fids = self.fids.lock().unwrap();

                // Check if fid exists
                if !fids.contains_key(&fid) {
                    return Message::Rerror {
                        tag,
                        ename: "Fid not found".to_string(),
                    };
                }

                let fid_state = fids.get_mut(&fid).unwrap();

                if fid_state.is_open {
                    return Message::Rerror {
                        tag,
                        ename: "Fid already open".to_string(),
                    };
                }

                // Update the atime
                fid_state.node.lock().unwrap().update_atime();

                // Mark as open
                fid_state.is_open = true;
                fid_state.open_mode = Some(mode);

                let qid = fid_state.node.lock().unwrap().qid();

                Message::Ropen {
                    tag,
                    qid,
                    iounit: 8192, // Maximum recommended transfer size
                }
            }

            Message::Tcreate {
                tag,
                fid,
                name,
                perm,
                mode,
            } => {
                let mut fids = self.fids.lock().unwrap();

                // Check if fid exists and points to a directory
                if !fids.contains_key(&fid) {
                    return Message::Rerror {
                        tag,
                        ename: "Fid not found".to_string(),
                    };
                }

                let fid_state = fids.get_mut(&fid).unwrap();
                let node_ref = fid_state.node.clone();
                let mut node = node_ref.lock().unwrap();

                match &mut *node {
                    FsNode::Directory { children, .. } => {
                        // Check if entry already exists
                        if children.contains_key(&name) {
                            return Message::Rerror {
                                tag,
                                ename: "File already exists".to_string(),
                            };
                        }

                        let is_dir = (perm & 0x80000000) != 0;
                        let now = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_secs() as u32;

                        // Create the new node (file or directory)
                        let new_qid = self.next_qid(is_dir);
                        let new_node = if is_dir {
                            FsNode::Directory {
                                name: name.clone(),
                                children: HashMap::new(),
                                qid: new_qid.clone(),
                                mode: perm & 0o777,
                                atime: now,
                                mtime: now,
                            }
                        } else {
                            FsNode::File {
                                name: name.clone(),
                                content: Vec::new(),
                                qid: new_qid.clone(),
                                mode: perm & 0o777,
                                atime: now,
                                mtime: now,
                            }
                        };

                        // Add to parent directory
                        let new_node_ref = Arc::new(Mutex::new(new_node));
                        children.insert(name.clone(), new_node_ref.clone());

                        // Update parent directory's modification time
                        node.update_mtime();

                        // Update fid to point to the new node
                        drop(node); // Release lock on node before modifying fid_state

                        let mut new_path = fid_state.path.clone();
                        new_path.push(name);

                        fid_state.node = new_node_ref;
                        fid_state.path = new_path;
                        fid_state.is_open = true;
                        fid_state.open_mode = Some(mode);

                        Message::Rcreate {
                            tag,
                            qid: new_qid,
                            iounit: 8192,
                        }
                    }
                    FsNode::File { .. } => Message::Rerror {
                        tag,
                        ename: "Not a directory".to_string(),
                    },
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

                // Check if fid exists and is open for writing
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

                // Check write permission (simplified)
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
                        // Write to file
                        let start = offset as usize;

                        // Ensure file is large enough
                        if start + data.len() > content.len() {
                            content.resize(start + data.len(), 0);
                        }

                        // Write the data
                        content[start..start + data.len()].copy_from_slice(&data);

                        // Update modification time
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

                // Remove fid from our map
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

                // Check if fid exists
                if !fids.contains_key(&fid) {
                    return Message::Rerror {
                        tag,
                        ename: "Fid not found".to_string(),
                    };
                }

                let fid_state = fids.get(&fid).unwrap().clone();
                let path_elements = fid_state.path.clone();

                // Cannot remove root
                if path_elements.is_empty() {
                    fids.remove(&fid);
                    return Message::Rerror {
                        tag,
                        ename: "Cannot remove root directory".to_string(),
                    };
                }

                // Find parent directory
                let parent_path = &path_elements[0..path_elements.len() - 1];
                let filename = path_elements.last().unwrap();

                if let Some(parent_node) = self.find_node(parent_path) {
                    let mut parent = parent_node.lock().unwrap();

                    match &mut *parent {
                        FsNode::Directory {
                            ref mut children, ..
                        } => {
                            // Remove the entry
                            if children.remove(filename).is_some() {
                                // Update modification time
                                parent.update_mtime();

                                // Remove the fid regardless of success
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

            Message::Tstat { tag, fid } => {
                let fids = self.fids.lock().unwrap();

                // Check if fid exists
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

                // Check if fid exists
                if !fids.contains_key(&fid) {
                    return Message::Rerror {
                        tag,
                        ename: "Fid not found".to_string(),
                    };
                }

                let fid_state = fids.get(&fid).unwrap();
                let mut node = fid_state.node.lock().unwrap();

                // For simplicity, we only allow changing mode and name
                match &mut *node {
                    FsNode::File {
                        ref mut name,
                        ref mut mode,
                        ..
                    } => {
                        // Update fields if they're not ~0 (which means don't change)
                        if stat.mode != 0xFFFFFFFF {
                            *mode = stat.mode & 0o777; // Only allow changing permission bits
                        }

                        if !stat.name.is_empty() {
                            // Changing name would require updating the parent directory too
                            // For simplicity, we don't allow this
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
                        // Update fields if they're not ~0 (which means don't change)
                        if stat.mode != 0xFFFFFFFF {
                            *mode = stat.mode & 0o777; // Only allow changing permission bits
                        }

                        if !stat.name.is_empty() {
                            // Changing name would require updating the parent directory too
                            // For simplicity, we don't allow this
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

            _ => {
                // Return an error for any unimplemented messages
                Message::Rerror {
                    tag: message.get_tag(),
                    ename: "Operation not implemented".to_string(),
                }
            }
        }
    }
}
