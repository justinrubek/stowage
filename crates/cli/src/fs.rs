use std::{collections::HashMap, sync::Mutex};
use stowage_proto::{Message, Qid};
use stowage_service::MessageHandler;

/// Simple in-memory file-system implementation
pub struct MemoryFilesystem {
    files: Mutex<HashMap<u32, Vec<u8>>>,
    next_fid: Mutex<u32>,
}

impl MemoryFilesystem {
    pub fn new() -> Self {
        Self {
            files: Mutex::new(HashMap::new()),
            next_fid: Mutex::new(1),
        }
    }
}

impl MessageHandler for MemoryFilesystem {
    async fn handle_message(&self, message: Message) -> Message {
        match message {
            Message::Tversion { tag, msize, .. } => Message::Rversion {
                tag,
                msize: msize.min(8192),
                version: "9P2000".to_string(),
            },
            Message::Tattach { tag, .. } => {
                Message::Rattach {
                    tag,
                    qid: Qid {
                        qtype: 0x80, // QTDIR
                        version: 0,
                        path: 0,
                    },
                }
            }
            // TODO: implement other message handlers
            _ => {
                // default error response for unimplemented messages
                Message::Rerror {
                    tag: 0, // TODO: use appropriate tag
                    ename: "not implemented".to_string(),
                }
            }
        }
    }
}
