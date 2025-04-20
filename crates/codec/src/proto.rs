use bytes::{Buf, BufMut, BytesMut};
use std::convert::TryFrom;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    Tversion = 100,
    Rversion = 101,
    Tauth = 102,
    Rauth = 103,
    Tattach = 104,
    Rattach = 105,
    Terror = 106,
    Rerror = 107,
    Tflush = 108,
    Rflush = 109,
    Twalk = 110,
    Rwalk = 111,
    Topen = 112,
    Ropen = 113,
    Tcreate = 114,
    Rcreate = 115,
    Tread = 116,
    Rread = 117,
    Twrite = 118,
    Rwrite = 119,
    Tclunk = 120,
    Rclunk = 121,
    Tremove = 122,
    Rremove = 123,
    Tstat = 124,
    Rstat = 125,
    Twstat = 126,
    Rwstat = 127,
}

#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("Invalid message type: {0}")]
    InvalidMessageType(u8),
    #[error("Buffer too short")]
    BufferTooShort,
    #[error(transparent)]
    StdIo(#[from] std::io::Error),
}

#[derive(Debug, Clone)]
pub struct Qid {
    pub qtype: u8,
    pub version: u32,
    pub path: u64,
}

#[derive(Debug, Clone)]
pub enum Message {
    Tversion {
        tag: u16,
        msize: u32,
        version: String,
    },
    Rversion {
        tag: u16,
        msize: u32,
        version: String,
    },
    Tattach {
        tag: u16,
        fid: u32,
        afid: u32,
        uname: String,
        aname: String,
    },
    Rattach {
        tag: u16,
        qid: Qid,
    },
    Rerror {
        tag: u16,
        ename: String,
    },
}

impl Message {
    pub fn encode(&self, buf: &mut BytesMut) {
        match self {
            Message::Tversion {
                tag,
                msize,
                version,
            } => {
                buf.put_u8(MessageType::Tversion as u8);
                buf.put_u16(*tag);
                buf.put_u32(*msize);
                encode_string(buf, version);
            }
            Message::Rversion {
                tag,
                msize,
                version,
            } => {
                buf.put_u8(MessageType::Rversion as u8);
                buf.put_u16(*tag);
                buf.put_u32(*msize);
                encode_string(buf, version);
            }
            _ => {
                // TODO: implement encoding for other message types
            }
        }
    }

    pub fn decode(buf: &mut BytesMut) -> Result<Self, ProtocolError> {
        if buf.len() < 3 {
            return Err(ProtocolError::BufferTooShort);
        }

        let typ = buf.get_u8();
        let tag = buf.get_u16();

        match MessageType::try_from(typ) {
            Ok(MessageType::Tversion) => {
                let msize = buf.get_u32();
                let version = decode_string(buf)?;
                Ok(Message::Tversion {
                    tag,
                    msize,
                    version,
                })
            }
            // TODO: implement decoding for other message types
            _ => Err(ProtocolError::InvalidMessageType(typ)),
        }
    }
}

fn encode_string(buf: &mut BytesMut, s: &str) {
    let bytes = s.as_bytes();
    buf.put_u16(bytes.len() as u16);
    buf.put_slice(bytes);
}

fn decode_string(buf: &mut BytesMut) -> Result<String, ProtocolError> {
    if buf.len() < 2 {
        return Err(ProtocolError::BufferTooShort);
    }

    let len = buf.get_u16() as usize;
    if buf.len() < len {
        return Err(ProtocolError::BufferTooShort);
    }

    let bytes = buf.split_to(len);
    String::from_utf8(bytes.to_vec()).map_err(|_| ProtocolError::BufferTooShort)
    // TODO: use appropriate error
}

impl TryFrom<u8> for MessageType {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            100 => Ok(MessageType::Tversion),
            101 => Ok(MessageType::Rversion),
            // TODO: match other message types
            _ => Err(ProtocolError::InvalidMessageType(value)),
        }
    }
}
