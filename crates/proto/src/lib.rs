use crate::error::{Error, Result};
use bytes::{Buf, BufMut, BytesMut};
use std::convert::TryFrom;
use tokio_util::codec::{Decoder, Encoder};

pub mod error;

pub struct Codec;

impl Decoder for Codec {
    type Item = Message;
    type Error = Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>> {
        // 9p messages start with a 4-byte size field
        if src.len() < 4 {
            return Ok(None);
        }

        // read the message size (including the size field)
        let size = {
            let mut size_bytes = [0u8; 4];
            size_bytes.copy_from_slice(&src[..4]);
            u32::from_le_bytes(size_bytes) as usize
        };

        // check if we have the complete message
        if src.len() < size {
            return Ok(None);
        }

        // skip the size field and retrieve the body
        src.advance(4);
        let mut message_body = src.split_to(size - 4);
        let message = Message::decode(&mut message_body)?;

        Ok(Some(message))
    }
}

impl Encoder<Message> for Codec {
    type Error = Error;

    fn encode(&mut self, item: Message, dst: &mut BytesMut) -> Result<()> {
        // reserve space for message size + content
        dst.reserve(1024); // adjust size as needed

        // save current position to write size later
        let start_pos = dst.len();

        // add placeholder for size
        dst.put_u32(0);

        // Encode the message
        item.encode(dst);

        // calculate and write the actual size
        let message_size = dst.len() - start_pos;
        let size_bytes = (message_size as u32).to_le_bytes();
        dst[start_pos..start_pos + 4].copy_from_slice(&size_bytes);

        Ok(())
    }
}

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

    pub fn decode(buf: &mut BytesMut) -> Result<Self> {
        if buf.len() < 3 {
            return Err(Error::BufferTooShort);
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
            _ => Err(Error::InvalidMessageType(typ)),
        }
    }
}

fn encode_string(buf: &mut BytesMut, s: &str) {
    let bytes = s.as_bytes();
    buf.put_u16(bytes.len() as u16);
    buf.put_slice(bytes);
}

fn decode_string(buf: &mut BytesMut) -> Result<String> {
    if buf.len() < 2 {
        return Err(Error::BufferTooShort);
    }

    let len = buf.get_u16() as usize;
    if buf.len() < len {
        return Err(Error::BufferTooShort);
    }

    let bytes = buf.split_to(len);
    String::from_utf8(bytes.to_vec()).map_err(|_| Error::BufferTooShort)
    // TODO: use appropriate error
}

impl TryFrom<u8> for MessageType {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            100 => Ok(MessageType::Tversion),
            101 => Ok(MessageType::Rversion),
            // TODO: match other message types
            _ => Err(Error::InvalidMessageType(value)),
        }
    }
}
