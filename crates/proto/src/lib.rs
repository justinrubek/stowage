use crate::error::{Error, Result};
use byteorder::{LittleEndian, ReadBytesExt};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::io::{Cursor, Read};
use tokio_util::codec::{Decoder, Encoder, LengthDelimitedCodec};

pub mod consts;
pub mod error;
mod fmt;

pub trait Protocol: Sized {
    /// # Errors
    /// - implementation specific
    fn encode(&self, buf: &mut BytesMut) -> Result<()>;
    /// # Errors
    /// - implementation specific
    fn decode(buf: &mut Cursor<&[u8]>) -> Result<Self>;

    /// calculate encoded size if known at compile time
    fn encoded_size(&self) -> Option<usize> {
        None
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    Tversion = 100,
    Rversion = 101,
    Tauth = 102,
    Rauth = 103,
    Tattach = 104,
    Rattach = 105,
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

impl MessageType {
    /// # Errors
    /// - the provided `value` is not a valid 9p message type
    pub fn from_u8(value: u8) -> Result<Self> {
        match value {
            100 => Ok(MessageType::Tversion),
            101 => Ok(MessageType::Rversion),
            102 => Ok(MessageType::Tauth),
            103 => Ok(MessageType::Rauth),
            104 => Ok(MessageType::Tattach),
            105 => Ok(MessageType::Rattach),
            107 => Ok(MessageType::Rerror),
            108 => Ok(MessageType::Tflush),
            109 => Ok(MessageType::Rflush),
            110 => Ok(MessageType::Twalk),
            111 => Ok(MessageType::Rwalk),
            112 => Ok(MessageType::Topen),
            113 => Ok(MessageType::Ropen),
            114 => Ok(MessageType::Tcreate),
            115 => Ok(MessageType::Rcreate),
            116 => Ok(MessageType::Tread),
            117 => Ok(MessageType::Rread),
            118 => Ok(MessageType::Twrite),
            119 => Ok(MessageType::Rwrite),
            120 => Ok(MessageType::Tclunk),
            121 => Ok(MessageType::Rclunk),
            122 => Ok(MessageType::Tremove),
            123 => Ok(MessageType::Rremove),
            124 => Ok(MessageType::Tstat),
            125 => Ok(MessageType::Rstat),
            126 => Ok(MessageType::Twstat),
            127 => Ok(MessageType::Rwstat),
            _ => Err(Error::InvalidMessageType(value)),
        }
    }

    #[must_use]
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum QidType {
    Dir = 0x80,
    Append = 0x40,
    Exclusive = 0x20,
    Mount = 0x10,
    Auth = 0x08,
    Tmp = 0x04,
    File = 0x00,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Qid {
    pub qtype: u8,
    pub version: u32,
    pub path: u64,
}

// `Message` wrapper that includes a tag
#[derive(Debug, Clone, PartialEq)]
pub struct TaggedMessage {
    pub tag: u16,
    pub message: Message,
}

impl TaggedMessage {
    pub fn new(tag: u16, message: Message) -> Self {
        Self { tag, message }
    }

    pub fn message_type(&self) -> MessageType {
        self.message.message_type()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Message {
    Tversion(Tversion),
    Rversion(Rversion),
    Tauth(Tauth),
    Rauth(Rauth),
    Tattach(Tattach),
    Rattach(Rattach),
    Rerror(Rerror),
    Tflush(Tflush),
    Rflush(Rflush),
    Twalk(Twalk),
    Rwalk(Rwalk),
    Topen(Topen),
    Ropen(Ropen),
    Tcreate(Tcreate),
    Rcreate(Rcreate),
    Tread(Tread),
    Rread(Rread),
    Twrite(Twrite),
    Rwrite(Rwrite),
    Tclunk(Tclunk),
    Rclunk(Rclunk),
    Tremove(Tremove),
    Rremove(Rremove),
    Tstat(Tstat),
    Rstat(Rstat),
    Twstat(Twstat),
    Rwstat(Rwstat),
}

impl Message {
    #[must_use]
    pub fn error(ename: String) -> Message {
        Message::Rerror(Rerror { ename })
    }

    pub fn message_type(&self) -> MessageType {
        match self {
            Message::Tversion(_) => MessageType::Tversion,
            Message::Rversion(_) => MessageType::Rversion,
            Message::Tauth(_) => MessageType::Tauth,
            Message::Rauth(_) => MessageType::Rauth,
            Message::Tattach(_) => MessageType::Tattach,
            Message::Rattach(_) => MessageType::Rattach,
            Message::Rerror(_) => MessageType::Rerror,
            Message::Tflush(_) => MessageType::Tflush,
            Message::Rflush(_) => MessageType::Rflush,
            Message::Twalk(_) => MessageType::Twalk,
            Message::Rwalk(_) => MessageType::Rwalk,
            Message::Topen(_) => MessageType::Topen,
            Message::Ropen(_) => MessageType::Ropen,
            Message::Tcreate(_) => MessageType::Tcreate,
            Message::Rcreate(_) => MessageType::Rcreate,
            Message::Tread(_) => MessageType::Tread,
            Message::Rread(_) => MessageType::Rread,
            Message::Twrite(_) => MessageType::Twrite,
            Message::Rwrite(_) => MessageType::Rwrite,
            Message::Tclunk(_) => MessageType::Tclunk,
            Message::Rclunk(_) => MessageType::Rclunk,
            Message::Tremove(_) => MessageType::Tremove,
            Message::Rremove(_) => MessageType::Rremove,
            Message::Tstat(_) => MessageType::Tstat,
            Message::Rstat(_) => MessageType::Rstat,
            Message::Twstat(_) => MessageType::Twstat,
            Message::Rwstat(_) => MessageType::Rwstat,
        }
    }

    pub fn to_tagged(self, tag: u16) -> TaggedMessage {
        TaggedMessage { tag, message: self }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Tversion {
    pub msize: u32,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Rversion {
    pub msize: u32,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Tauth {
    pub afid: u32,
    pub uname: String,
    pub aname: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Rauth {
    pub aqid: Qid,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Tattach {
    pub fid: u32,
    pub afid: u32,
    pub uname: String,
    pub aname: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Rattach {
    pub qid: Qid,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Rerror {
    pub ename: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Tflush {
    pub oldtag: u16,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Rflush;

#[derive(Debug, Clone, PartialEq)]
pub struct Twalk {
    pub fid: u32,
    pub newfid: u32,
    pub wnames: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Rwalk {
    pub wqids: Vec<Qid>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Topen {
    pub fid: u32,
    pub mode: u8,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Ropen {
    pub qid: Qid,
    pub iounit: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Tcreate {
    pub fid: u32,
    pub name: String,
    pub perm: u32,
    pub mode: u8,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Rcreate {
    pub qid: Qid,
    pub iounit: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Tread {
    pub fid: u32,
    pub offset: u64,
    pub count: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Rread {
    pub data: Bytes,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Twrite {
    pub fid: u32,
    pub offset: u64,
    pub data: Bytes,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Rwrite {
    pub count: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Tclunk {
    pub fid: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Rclunk;

#[derive(Debug, Clone, PartialEq)]
pub struct Tremove {
    pub fid: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Rremove;

#[derive(Debug, Clone, PartialEq)]
pub struct Tstat {
    pub fid: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Rstat {
    pub stat: Stat,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Twstat {
    pub fid: u32,
    pub stat: Stat,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Rwstat;

impl Protocol for u8 {
    fn encode(&self, buf: &mut BytesMut) -> Result<()> {
        buf.put_u8(*self);
        Ok(())
    }

    fn decode(buf: &mut Cursor<&[u8]>) -> Result<Self> {
        Ok(buf.read_u8()?)
    }

    fn encoded_size(&self) -> Option<usize> {
        Some(1)
    }
}

impl Protocol for u16 {
    fn encode(&self, buf: &mut BytesMut) -> Result<()> {
        buf.put_u16_le(*self);
        Ok(())
    }

    fn decode(buf: &mut Cursor<&[u8]>) -> Result<Self> {
        Ok(buf.read_u16::<LittleEndian>()?)
    }

    fn encoded_size(&self) -> Option<usize> {
        Some(2)
    }
}

impl Protocol for u32 {
    fn encode(&self, buf: &mut BytesMut) -> Result<()> {
        buf.put_u32_le(*self);
        Ok(())
    }

    fn decode(buf: &mut Cursor<&[u8]>) -> Result<Self> {
        Ok(buf.read_u32::<LittleEndian>()?)
    }

    fn encoded_size(&self) -> Option<usize> {
        Some(4)
    }
}

impl Protocol for u64 {
    fn encode(&self, buf: &mut BytesMut) -> Result<()> {
        buf.put_u64_le(*self);
        Ok(())
    }

    fn decode(buf: &mut Cursor<&[u8]>) -> Result<Self> {
        Ok(buf.read_u64::<LittleEndian>()?)
    }

    fn encoded_size(&self) -> Option<usize> {
        Some(8)
    }
}

impl Protocol for String {
    /// # Errors
    /// - string length overflows u16
    fn encode(&self, buf: &mut BytesMut) -> Result<()> {
        let bytes = self.as_bytes();
        if bytes.len() > u16::MAX as usize {
            return Err(Error::StringTooLong(bytes.len()));
        }

        // reserve space for length + string data
        buf.reserve(2 + bytes.len());
        buf.put_u16_le(u16::try_from(bytes.len()).unwrap()); // unwrap - checked above
        buf.put_slice(bytes);
        Ok(())
    }

    fn decode(buf: &mut Cursor<&[u8]>) -> Result<Self> {
        let len = buf.read_u16::<LittleEndian>()? as usize;
        if buf.remaining() < len {
            return Err(Error::InsufficientData {
                expected: len,
                actual: buf.remaining(),
            });
        }

        let mut string_bytes = vec![0u8; len];
        buf.copy_to_slice(&mut string_bytes);
        Ok(String::from_utf8(string_bytes)?)
    }
}

impl Protocol for Bytes {
    /// # Errors
    /// - length exceeds u32 max
    fn encode(&self, buf: &mut BytesMut) -> Result<()> {
        let len = u32::try_from(self.len()).map_err(|_| Error::BytesTooLong(self.len()))?;

        buf.reserve(4 + self.len());
        buf.put_u32_le(len);
        buf.put_slice(self);
        Ok(())
    }

    fn decode(buf: &mut Cursor<&[u8]>) -> Result<Self> {
        let len = buf.read_u32::<LittleEndian>()? as usize;
        if buf.remaining() < len {
            return Err(Error::InsufficientData {
                expected: len,
                actual: buf.remaining(),
            });
        }

        let mut data = vec![0u8; len];
        buf.copy_to_slice(&mut data);
        Ok(Bytes::from(data))
    }
}

impl Protocol for Qid {
    fn encode(&self, buf: &mut BytesMut) -> Result<()> {
        buf.reserve(13); // fixed size: 1 + 4 + 8
        self.qtype.encode(buf)?;
        self.version.encode(buf)?;
        self.path.encode(buf)?;
        Ok(())
    }

    fn decode(buf: &mut Cursor<&[u8]>) -> Result<Self> {
        Ok(Qid {
            qtype: u8::decode(buf)?,
            version: u32::decode(buf)?,
            path: u64::decode(buf)?,
        })
    }

    fn encoded_size(&self) -> Option<usize> {
        Some(13)
    }
}

impl<T: Protocol> Protocol for Vec<T> {
    fn encode(&self, buf: &mut BytesMut) -> Result<()> {
        if self.len() > u16::MAX as usize {
            return Err(Error::VectorTooLong(self.len()));
        }
        let len = u16::try_from(self.len()).unwrap(); // unwrap - checked above

        let mut total_size = 2;
        if let Some(item_size) = self.first().and_then(Protocol::encoded_size) {
            total_size += item_size * self.len();
            buf.reserve(total_size);
        }

        len.encode(buf)?;
        for item in self {
            item.encode(buf)?;
        }
        Ok(())
    }

    fn decode(buf: &mut Cursor<&[u8]>) -> Result<Self> {
        let len = u16::decode(buf)? as usize;
        let mut vec = Vec::with_capacity(len);
        for _ in 0..len {
            vec.push(T::decode(buf)?);
        }
        Ok(vec)
    }
}

impl Protocol for () {
    fn encode(&self, _buf: &mut BytesMut) -> Result<()> {
        Ok(())
    }

    fn decode(_buf: &mut Cursor<&[u8]>) -> Result<Self> {
        Ok(())
    }

    fn encoded_size(&self) -> Option<usize> {
        Some(0)
    }
}

impl Protocol for Tversion {
    fn encode(&self, buf: &mut BytesMut) -> Result<()> {
        self.msize.encode(buf)?;
        self.version.encode(buf)?;
        Ok(())
    }

    fn decode(buf: &mut Cursor<&[u8]>) -> Result<Self> {
        Ok(Tversion {
            msize: u32::decode(buf)?,
            version: String::decode(buf)?,
        })
    }
}

impl Protocol for Rversion {
    fn encode(&self, buf: &mut BytesMut) -> Result<()> {
        self.msize.encode(buf)?;
        self.version.encode(buf)?;
        Ok(())
    }

    fn decode(buf: &mut Cursor<&[u8]>) -> Result<Self> {
        Ok(Rversion {
            msize: u32::decode(buf)?,
            version: String::decode(buf)?,
        })
    }
}

impl Protocol for Tauth {
    fn encode(&self, buf: &mut BytesMut) -> Result<()> {
        self.afid.encode(buf)?;
        self.uname.encode(buf)?;
        self.aname.encode(buf)?;
        Ok(())
    }

    fn decode(buf: &mut Cursor<&[u8]>) -> Result<Self> {
        Ok(Tauth {
            afid: u32::decode(buf)?,
            uname: String::decode(buf)?,
            aname: String::decode(buf)?,
        })
    }
}

impl Protocol for Rauth {
    fn encode(&self, buf: &mut BytesMut) -> Result<()> {
        self.aqid.encode(buf)?;
        Ok(())
    }

    fn decode(buf: &mut Cursor<&[u8]>) -> Result<Self> {
        Ok(Rauth {
            aqid: Qid::decode(buf)?,
        })
    }
}

impl Protocol for Tattach {
    fn encode(&self, buf: &mut BytesMut) -> Result<()> {
        self.fid.encode(buf)?;
        self.afid.encode(buf)?;
        self.uname.encode(buf)?;
        self.aname.encode(buf)?;
        Ok(())
    }

    fn decode(buf: &mut Cursor<&[u8]>) -> Result<Self> {
        Ok(Tattach {
            fid: u32::decode(buf)?,
            afid: u32::decode(buf)?,
            uname: String::decode(buf)?,
            aname: String::decode(buf)?,
        })
    }
}

impl Protocol for Rattach {
    fn encode(&self, buf: &mut BytesMut) -> Result<()> {
        self.qid.encode(buf)?;
        Ok(())
    }

    fn decode(buf: &mut Cursor<&[u8]>) -> Result<Self> {
        Ok(Rattach {
            qid: Qid::decode(buf)?,
        })
    }
}

impl Protocol for Rerror {
    fn encode(&self, buf: &mut BytesMut) -> Result<()> {
        self.ename.encode(buf)?;
        Ok(())
    }

    fn decode(buf: &mut Cursor<&[u8]>) -> Result<Self> {
        Ok(Rerror {
            ename: String::decode(buf)?,
        })
    }
}

impl Protocol for Tflush {
    fn encode(&self, buf: &mut BytesMut) -> Result<()> {
        self.oldtag.encode(buf)?;
        Ok(())
    }

    fn decode(buf: &mut Cursor<&[u8]>) -> Result<Self> {
        Ok(Tflush {
            oldtag: u16::decode(buf)?,
        })
    }
}

impl Protocol for Rflush {
    fn encode(&self, _buf: &mut BytesMut) -> Result<()> {
        Ok(())
    }

    fn decode(_buf: &mut Cursor<&[u8]>) -> Result<Self> {
        Ok(Rflush)
    }
}

impl Protocol for Twalk {
    fn encode(&self, buf: &mut BytesMut) -> Result<()> {
        self.fid.encode(buf)?;
        self.newfid.encode(buf)?;
        self.wnames.encode(buf)?;
        Ok(())
    }

    fn decode(buf: &mut Cursor<&[u8]>) -> Result<Self> {
        Ok(Twalk {
            fid: u32::decode(buf)?,
            newfid: u32::decode(buf)?,
            wnames: Vec::<String>::decode(buf)?,
        })
    }
}

impl Protocol for Rwalk {
    fn encode(&self, buf: &mut BytesMut) -> Result<()> {
        self.wqids.encode(buf)?;
        Ok(())
    }

    fn decode(buf: &mut Cursor<&[u8]>) -> Result<Self> {
        Ok(Rwalk {
            wqids: Vec::<Qid>::decode(buf)?,
        })
    }
}

impl Protocol for Topen {
    fn encode(&self, buf: &mut BytesMut) -> Result<()> {
        self.fid.encode(buf)?;
        self.mode.encode(buf)?;
        Ok(())
    }

    fn decode(buf: &mut Cursor<&[u8]>) -> Result<Self> {
        Ok(Topen {
            fid: u32::decode(buf)?,
            mode: u8::decode(buf)?,
        })
    }
}

impl Protocol for Ropen {
    fn encode(&self, buf: &mut BytesMut) -> Result<()> {
        self.qid.encode(buf)?;
        self.iounit.encode(buf)?;
        Ok(())
    }

    fn decode(buf: &mut Cursor<&[u8]>) -> Result<Self> {
        Ok(Ropen {
            qid: Qid::decode(buf)?,
            iounit: u32::decode(buf)?,
        })
    }
}

impl Protocol for Tcreate {
    fn encode(&self, buf: &mut BytesMut) -> Result<()> {
        self.fid.encode(buf)?;
        self.name.encode(buf)?;
        self.perm.encode(buf)?;
        self.mode.encode(buf)?;
        Ok(())
    }

    fn decode(buf: &mut Cursor<&[u8]>) -> Result<Self> {
        Ok(Tcreate {
            fid: u32::decode(buf)?,
            name: String::decode(buf)?,
            perm: u32::decode(buf)?,
            mode: u8::decode(buf)?,
        })
    }
}

impl Protocol for Rcreate {
    fn encode(&self, buf: &mut BytesMut) -> Result<()> {
        self.qid.encode(buf)?;
        self.iounit.encode(buf)?;
        Ok(())
    }

    fn decode(buf: &mut Cursor<&[u8]>) -> Result<Self> {
        Ok(Rcreate {
            qid: Qid::decode(buf)?,
            iounit: u32::decode(buf)?,
        })
    }
}

impl Protocol for Tread {
    fn encode(&self, buf: &mut BytesMut) -> Result<()> {
        self.fid.encode(buf)?;
        self.offset.encode(buf)?;
        self.count.encode(buf)?;
        Ok(())
    }

    fn decode(buf: &mut Cursor<&[u8]>) -> Result<Self> {
        Ok(Tread {
            fid: u32::decode(buf)?,
            offset: u64::decode(buf)?,
            count: u32::decode(buf)?,
        })
    }
}

impl Protocol for Rread {
    fn encode(&self, buf: &mut BytesMut) -> Result<()> {
        self.data.encode(buf)?;
        Ok(())
    }

    fn decode(buf: &mut Cursor<&[u8]>) -> Result<Self> {
        Ok(Rread {
            data: Bytes::decode(buf)?,
        })
    }
}

impl Protocol for Twrite {
    fn encode(&self, buf: &mut BytesMut) -> Result<()> {
        self.fid.encode(buf)?;
        self.offset.encode(buf)?;
        self.data.encode(buf)?;
        Ok(())
    }

    fn decode(buf: &mut Cursor<&[u8]>) -> Result<Self> {
        Ok(Twrite {
            fid: u32::decode(buf)?,
            offset: u64::decode(buf)?,
            data: Bytes::decode(buf)?,
        })
    }
}

impl Protocol for Rwrite {
    fn encode(&self, buf: &mut BytesMut) -> Result<()> {
        self.count.encode(buf)?;
        Ok(())
    }

    fn decode(buf: &mut Cursor<&[u8]>) -> Result<Self> {
        Ok(Rwrite {
            count: u32::decode(buf)?,
        })
    }
}

impl Protocol for Tclunk {
    fn encode(&self, buf: &mut BytesMut) -> Result<()> {
        self.fid.encode(buf)?;
        Ok(())
    }

    fn decode(buf: &mut Cursor<&[u8]>) -> Result<Self> {
        Ok(Tclunk {
            fid: u32::decode(buf)?,
        })
    }
}

impl Protocol for Rclunk {
    fn encode(&self, _buf: &mut BytesMut) -> Result<()> {
        Ok(())
    }

    fn decode(_buf: &mut Cursor<&[u8]>) -> Result<Self> {
        Ok(Rclunk)
    }
}

impl Protocol for Tremove {
    fn encode(&self, buf: &mut BytesMut) -> Result<()> {
        self.fid.encode(buf)?;
        Ok(())
    }

    fn decode(buf: &mut Cursor<&[u8]>) -> Result<Self> {
        Ok(Tremove {
            fid: u32::decode(buf)?,
        })
    }
}

impl Protocol for Rremove {
    fn encode(&self, _buf: &mut BytesMut) -> Result<()> {
        Ok(())
    }

    fn decode(_buf: &mut Cursor<&[u8]>) -> Result<Self> {
        Ok(Rremove)
    }
}

impl Protocol for Tstat {
    fn encode(&self, buf: &mut BytesMut) -> Result<()> {
        self.fid.encode(buf)?;
        Ok(())
    }

    fn decode(buf: &mut Cursor<&[u8]>) -> Result<Self> {
        Ok(Tstat {
            fid: u32::decode(buf)?,
        })
    }
}

impl Protocol for Rstat {
    fn encode(&self, buf: &mut BytesMut) -> Result<()> {
        // First encode the size of the stat structure
        // This is the first size field in the Rstat message

        // Calculate the size that Stat::encode would produce
        let mut temp_buf = BytesMut::new();
        self.stat.encode(&mut temp_buf)?;
        let stat_size =
            u16::try_from(temp_buf.len()).map_err(|_| Error::StringTooLong(temp_buf.len()))?;

        // Encode the size of the stat structure
        stat_size.encode(buf)?;

        // Now encode the stat structure itself
        // This will include its own size field as part of Stat::encode
        self.stat.encode(buf)?;

        Ok(())
    }

    fn decode(buf: &mut Cursor<&[u8]>) -> Result<Self> {
        // Read the size of the stat structure (first size field)
        let stat_size = u16::decode(buf)?;

        // Record the current position
        let start_pos = buf.position();

        // Decode the stat structure (which has its own size field)
        let stat = Stat::decode(buf)?;

        // Verify we read the expected number of bytes
        let bytes_read = buf.position() - start_pos;
        if bytes_read != stat_size as u64 {
            println!(
                "Warning: Rstat size field indicated {} bytes but {} were read",
                stat_size, bytes_read
            );
            // You could return an error here, but real-world implementations
            // often need to be lenient with size fields
        }

        Ok(Rstat { stat })
    }
}

impl Protocol for Twstat {
    fn encode(&self, buf: &mut BytesMut) -> Result<()> {
        self.fid.encode(buf)?;

        let mut temp_buf = BytesMut::new();
        self.stat.encode(&mut temp_buf)?;
        let stat_size =
            u16::try_from(temp_buf.len()).map_err(|_| Error::StringTooLong(temp_buf.len()))?;
        stat_size.encode(buf)?;
        self.stat.encode(buf)?;

        Ok(())
    }

    fn decode(buf: &mut Cursor<&[u8]>) -> Result<Self> {
        let fid = u32::decode(buf)?;

        let stat_size = u16::decode(buf)?;

        let start_pos = buf.position();
        let stat = Stat::decode(buf)?;

        let bytes_read = buf.position() - start_pos;
        if bytes_read != stat_size as u64 {
            println!(
                "Warning: Twstat size field indicated {} bytes but {} were read",
                stat_size, bytes_read
            );
            // being lenient with size fields
        }

        Ok(Twstat { fid, stat })
    }
}

impl Protocol for Rwstat {
    fn encode(&self, _buf: &mut BytesMut) -> Result<()> {
        Ok(())
    }

    fn decode(_buf: &mut Cursor<&[u8]>) -> Result<Self> {
        Ok(Rwstat)
    }
}

impl Protocol for Message {
    fn encode(&self, buf: &mut BytesMut) -> Result<()> {
        match self {
            Message::Tversion(msg) => msg.encode(buf),
            Message::Rversion(msg) => msg.encode(buf),
            Message::Tauth(msg) => msg.encode(buf),
            Message::Rauth(msg) => msg.encode(buf),
            Message::Tattach(msg) => msg.encode(buf),
            Message::Rattach(msg) => msg.encode(buf),
            Message::Rerror(msg) => msg.encode(buf),
            Message::Tflush(msg) => msg.encode(buf),
            Message::Rflush(msg) => msg.encode(buf),
            Message::Twalk(msg) => msg.encode(buf),
            Message::Rwalk(msg) => msg.encode(buf),
            Message::Topen(msg) => msg.encode(buf),
            Message::Ropen(msg) => msg.encode(buf),
            Message::Tcreate(msg) => msg.encode(buf),
            Message::Rcreate(msg) => msg.encode(buf),
            Message::Tread(msg) => msg.encode(buf),
            Message::Rread(msg) => msg.encode(buf),
            Message::Twrite(msg) => msg.encode(buf),
            Message::Rwrite(msg) => msg.encode(buf),
            Message::Tclunk(msg) => msg.encode(buf),
            Message::Rclunk(msg) => msg.encode(buf),
            Message::Tremove(msg) => msg.encode(buf),
            Message::Rremove(msg) => msg.encode(buf),
            Message::Tstat(msg) => msg.encode(buf),
            Message::Rstat(msg) => msg.encode(buf),
            Message::Twstat(msg) => msg.encode(buf),
            Message::Rwstat(msg) => msg.encode(buf),
        }
    }

    /// This should not be called directly - use `TaggedMessage::decode` instead.
    fn decode(_buf: &mut Cursor<&[u8]>) -> Result<Self> {
        Err(Error::Protocol(
            "Message::decode called directly".to_string(),
        ))
    }
}

impl Protocol for TaggedMessage {
    fn encode(&self, buf: &mut BytesMut) -> Result<()> {
        self.message.message_type().to_u8().encode(buf)?;
        self.tag.encode(buf)?;
        self.message.encode(buf)?;
        Ok(())
    }

    fn decode(buf: &mut Cursor<&[u8]>) -> Result<Self> {
        let message_type = MessageType::from_u8(u8::decode(buf)?)?;
        let tag = u16::decode(buf)?;

        let message = match message_type {
            MessageType::Tversion => Message::Tversion(Tversion::decode(buf)?),
            MessageType::Rversion => Message::Rversion(Rversion::decode(buf)?),
            MessageType::Tauth => Message::Tauth(Tauth::decode(buf)?),
            MessageType::Rauth => Message::Rauth(Rauth::decode(buf)?),
            MessageType::Tattach => Message::Tattach(Tattach::decode(buf)?),
            MessageType::Rattach => Message::Rattach(Rattach::decode(buf)?),
            MessageType::Rerror => Message::Rerror(Rerror::decode(buf)?),
            MessageType::Tflush => Message::Tflush(Tflush::decode(buf)?),
            MessageType::Rflush => Message::Rflush(Rflush::decode(buf)?),
            MessageType::Twalk => Message::Twalk(Twalk::decode(buf)?),
            MessageType::Rwalk => Message::Rwalk(Rwalk::decode(buf)?),
            MessageType::Topen => Message::Topen(Topen::decode(buf)?),
            MessageType::Ropen => Message::Ropen(Ropen::decode(buf)?),
            MessageType::Tcreate => Message::Tcreate(Tcreate::decode(buf)?),
            MessageType::Rcreate => Message::Rcreate(Rcreate::decode(buf)?),
            MessageType::Tread => Message::Tread(Tread::decode(buf)?),
            MessageType::Rread => Message::Rread(Rread::decode(buf)?),
            MessageType::Twrite => Message::Twrite(Twrite::decode(buf)?),
            MessageType::Rwrite => Message::Rwrite(Rwrite::decode(buf)?),
            MessageType::Tclunk => Message::Tclunk(Tclunk::decode(buf)?),
            MessageType::Rclunk => Message::Rclunk(Rclunk::decode(buf)?),
            MessageType::Tremove => Message::Tremove(Tremove::decode(buf)?),
            MessageType::Rremove => Message::Rremove(Rremove::decode(buf)?),
            MessageType::Tstat => Message::Tstat(Tstat::decode(buf)?),
            MessageType::Rstat => Message::Rstat(Rstat::decode(buf)?),
            MessageType::Twstat => Message::Twstat(Twstat::decode(buf)?),
            MessageType::Rwstat => Message::Rwstat(Rwstat::decode(buf)?),
        };

        Ok(TaggedMessage { tag, message })
    }
}

pub struct MessageCodec {
    length_codec: LengthDelimitedCodec,
}

impl MessageCodec {
    #[must_use]
    pub fn new() -> Self {
        Self {
            length_codec: LengthDelimitedCodec::builder()
                .little_endian()
                .length_field_length(4)
                .length_adjustment(-4) // don't include length field in payload
                .new_codec(),
        }
    }
}

impl Default for MessageCodec {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder for MessageCodec {
    type Item = TaggedMessage;
    type Error = Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>> {
        if let Some(frame) = self.length_codec.decode(src).map_err(Error::Io)? {
            let mut cursor = Cursor::new(frame.as_ref());
            let message = TaggedMessage::decode(&mut cursor)?;
            Ok(Some(message))
        } else {
            Ok(None)
        }
    }
}

impl Encoder<TaggedMessage> for MessageCodec {
    type Error = Error;

    fn encode(&mut self, item: TaggedMessage, dst: &mut BytesMut) -> Result<()> {
        let mut payload = BytesMut::new();
        item.encode(&mut payload)?;
        self.length_codec
            .encode(payload.freeze(), dst)
            .map_err(Error::Io)?;
        Ok(())
    }
}

impl Qid {
    #[must_use]
    pub fn from_log_format(path: u64, version: u32, qtype_char: char) -> Self {
        let qtype = match qtype_char {
            'd' => 0x80, // QTDIR
            'a' => 0x40, // QTAPPEND
            'l' => 0x02, // QTLINK
            _ => 0x00,   // QTFILE
        };

        Self {
            qtype,
            version,
            path,
        }
    }
}

/// Represents a 9P stat structure as defined in the protocol
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stat {
    pub r#type: u16,
    pub dev: u32,
    pub qid: Qid,
    pub mode: u32,
    pub atime: u32,
    pub mtime: u32,
    pub length: u64,
    pub name: String,
    pub uid: String,
    pub gid: String,
    pub muid: String,
}

impl Stat {
    /// Create a new Stat with "don't touch" values for all fields
    /// This is useful for creating wstat messages that only modify specific fields
    #[must_use]
    pub fn new_dont_touch() -> Self {
        Stat {
            r#type: u16::MAX,
            dev: u32::MAX,
            qid: Qid {
                qtype: 0xFF, // Don't touch value for qtype
                version: u32::MAX,
                path: u64::MAX,
            },
            mode: u32::MAX,
            atime: u32::MAX,
            mtime: u32::MAX,
            length: u64::MAX,
            name: String::new(), // Empty string = don't touch
            uid: String::new(),
            gid: String::new(),
            muid: String::new(),
        }
    }

    /// Check if a field has a "don't touch" value
    #[must_use]
    pub fn is_dont_touch_u16(val: u16) -> bool {
        val == u16::MAX
    }

    #[must_use]
    pub fn is_dont_touch_u32(val: u32) -> bool {
        val == u32::MAX
    }

    #[must_use]
    pub fn is_dont_touch_u64(val: u64) -> bool {
        val == u64::MAX
    }

    #[must_use]
    pub fn is_dont_touch_string(val: &str) -> bool {
        val.is_empty()
    }
}

impl Protocol for Stat {
    fn encode(&self, buf: &mut BytesMut) -> Result<()> {
        // Calculate size of all fields
        let mut size_calc = BytesMut::new();

        // Encode all fields except the size
        self.r#type.encode(&mut size_calc)?;
        self.dev.encode(&mut size_calc)?;

        // Encode QID fields directly
        self.qid.qtype.encode(&mut size_calc)?;
        self.qid.version.encode(&mut size_calc)?;
        self.qid.path.encode(&mut size_calc)?;

        self.mode.encode(&mut size_calc)?;
        self.atime.encode(&mut size_calc)?;
        self.mtime.encode(&mut size_calc)?;
        self.length.encode(&mut size_calc)?;

        // String fields
        self.name.encode(&mut size_calc)?;
        self.uid.encode(&mut size_calc)?;
        self.gid.encode(&mut size_calc)?;
        self.muid.encode(&mut size_calc)?;

        // Calculate total size
        let total_size =
            u16::try_from(size_calc.len()).map_err(|_| Error::StringTooLong(size_calc.len()))?;

        // Now encode the actual data
        total_size.encode(buf)?;
        buf.extend_from_slice(&size_calc);

        Ok(())
    }

    fn decode(buf: &mut Cursor<&[u8]>) -> Result<Self> {
        // Read the size field
        let stat_size = u16::decode(buf)?;

        // Verify we have enough data
        if buf.remaining() < stat_size as usize {
            return Err(Error::InsufficientData {
                expected: stat_size as usize,
                actual: buf.remaining(),
            });
        }

        // Read the entire stat block as raw bytes
        let mut stat_data = vec![0u8; stat_size as usize];
        buf.copy_to_slice(&mut stat_data);

        // Create a new cursor for parsing these bytes
        let mut stat_cursor = Cursor::new(&stat_data[..]);

        // Parse all fields, ignoring potential size mismatches
        let r#type = u16::decode(&mut stat_cursor).unwrap_or(0);
        let dev = u32::decode(&mut stat_cursor).unwrap_or(0);

        // Handling QID fields with fallbacks
        let qtype = u8::decode(&mut stat_cursor).unwrap_or(0);
        let version = u32::decode(&mut stat_cursor).unwrap_or(0);
        let path = u64::decode(&mut stat_cursor).unwrap_or(0);

        let mode = u32::decode(&mut stat_cursor).unwrap_or(0);
        let atime = u32::decode(&mut stat_cursor).unwrap_or(0);
        let mtime = u32::decode(&mut stat_cursor).unwrap_or(0);
        let length = u64::decode(&mut stat_cursor).unwrap_or(0);

        // String fields with empty fallbacks
        let name = String::decode(&mut stat_cursor).unwrap_or_default();
        let uid = String::decode(&mut stat_cursor).unwrap_or_default();
        let gid = String::decode(&mut stat_cursor).unwrap_or_default();
        let muid = String::decode(&mut stat_cursor).unwrap_or_default();

        Ok(Stat {
            r#type,
            dev,
            qid: Qid {
                qtype,
                version,
                path,
            },
            mode,
            atime,
            mtime,
            length,
            name,
            uid,
            gid,
            muid,
        })
    }
}

/// Variant 1: Standard 9P specification ordering
fn decode_stat_standard(data: &[u8]) -> Result<Stat> {
    let mut cursor = Cursor::new(data);

    // Read the size field
    let stat_size = u16::decode(&mut cursor)?;
    println!("Size field: {}", stat_size);

    let r#type = u16::decode(&mut cursor)?;
    let dev = u32::decode(&mut cursor)?;

    // Read QID fields directly
    let qtype = u8::decode(&mut cursor)?;
    let version = u32::decode(&mut cursor)?;
    let path = u64::decode(&mut cursor)?;

    let mode = u32::decode(&mut cursor)?;
    let atime = u32::decode(&mut cursor)?;
    let mtime = u32::decode(&mut cursor)?;
    let length = u64::decode(&mut cursor)?;

    // String fields
    let name = String::decode(&mut cursor)?;
    let uid = String::decode(&mut cursor)?;
    let gid = String::decode(&mut cursor)?;
    let muid = String::decode(&mut cursor)?;

    let stat = Stat {
        r#type,
        dev,
        qid: Qid {
            qtype,
            version,
            path,
        },
        mode,
        atime,
        mtime,
        length,
        name,
        uid,
        gid,
        muid,
    };

    println!("VARIANT 1 RESULT: {:?}", stat);
    println!("uid: '{}', gid: '{}'", stat.uid, stat.gid);
    println!("cursor position: {}", cursor.position());

    Ok(stat)
}

/// Variant 2: Shifted string fields by one position
fn decode_stat_shifted_strings(data: &[u8]) -> Result<Stat> {
    let mut cursor = Cursor::new(data);

    let stat_size = u16::decode(&mut cursor)?;
    println!("Size field: {}", stat_size);

    let r#type = u16::decode(&mut cursor)?;
    let dev = u32::decode(&mut cursor)?;

    // Read QID fields directly
    let qtype = u8::decode(&mut cursor)?;
    let version = u32::decode(&mut cursor)?;
    let path = u64::decode(&mut cursor)?;

    let mode = u32::decode(&mut cursor)?;
    let atime = u32::decode(&mut cursor)?;
    let mtime = u32::decode(&mut cursor)?;
    let length = u64::decode(&mut cursor)?;

    // String fields SHIFTED - try all permutations
    let s1 = String::decode(&mut cursor)?;
    let s2 = String::decode(&mut cursor)?;
    let s3 = String::decode(&mut cursor)?;
    let s4 = String::decode(&mut cursor)?;

    println!(
        "String1: '{}', String2: '{}', String3: '{}', String4: '{}'",
        s1, s2, s3, s4
    );

    // Try different orderings
    let name = s1.clone(); // Try name as first string
    let uid = s2.clone(); // Try uid as second string
    let gid = s3.clone(); // Try gid as third string
    let muid = s4.clone(); // Try muid as fourth string

    let stat = Stat {
        r#type,
        dev,
        qid: Qid {
            qtype,
            version,
            path,
        },
        mode,
        atime,
        mtime,
        length,
        name,
        uid,
        gid,
        muid,
    };

    println!("VARIANT 2 RESULT: {:?}", stat);
    println!("cursor position: {}", cursor.position());

    Ok(stat)
}

/// Variant 3: Different field offsets
fn decode_stat_alternate_offsets(data: &[u8]) -> Result<Stat> {
    // Dump the raw bytes for detailed analysis
    println!("Raw bytes for manual analysis:");
    for (i, chunk) in data.chunks(16).enumerate() {
        print!("{:04x}:  ", i * 16);
        for byte in chunk {
            print!("{:02x} ", *byte);
        }
        println!();
    }

    // Try offsets 2 bytes apart from standard
    if data.len() < 60 {
        return Err(Error::InsufficientData {
            expected: 60,
            actual: data.len(),
        });
    }

    // Read fields at specific offsets
    let r#type = u16::from_le_bytes([data[2], data[3]]);
    let dev = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);

    // QID at +2 offset
    let qtype = data[8];
    let version = u32::from_le_bytes([data[9], data[10], data[11], data[12]]);
    let path = u64::from_le_bytes([
        data[13], data[14], data[15], data[16], data[17], data[18], data[19], data[20],
    ]);

    // Rest of fields at shifted positions
    let mode = u32::from_le_bytes([data[21], data[22], data[23], data[24]]);
    let atime = u32::from_le_bytes([data[25], data[26], data[27], data[28]]);
    let mtime = u32::from_le_bytes([data[29], data[30], data[31], data[32]]);
    let length = u64::from_le_bytes([
        data[33], data[34], data[35], data[36], data[37], data[38], data[39], data[40],
    ]);

    // Attempt to read strings starting at different offsets
    let stat = Stat {
        r#type,
        dev,
        qid: Qid {
            qtype,
            version,
            path,
        },
        mode,
        atime,
        mtime,
        length,
        name: String::from_utf8_lossy(&[]).to_string(), // Empty for now
        uid: String::from_utf8_lossy(&data[45..50]).to_string(),
        gid: String::from_utf8_lossy(&data[52..57]).to_string(),
        muid: String::from_utf8_lossy(&[]).to_string(),
    };

    println!("VARIANT 3 RESULT: {:?}", stat);
    println!("Offset-based parsing, strings may be truncated");

    Ok(stat)
}

/// Variant 4: Custom string reading logic
fn decode_stat_custom_strings(data: &[u8]) -> Result<Stat> {
    let mut cursor = Cursor::new(data);

    let stat_size = u16::decode(&mut cursor)?;
    println!("Size field: {}", stat_size);

    // Skip past all the numeric fields (41 bytes)
    // 2 (type) + 4 (dev) + 1 (qtype) + 4 (version) + 8 (path) +
    // 4 (mode) + 4 (atime) + 4 (mtime) + 8 (length) = 39
    let pos = 2 + 39; // 2 for stat_size already read
    cursor.set_position(pos);

    // Now try to manually read the strings
    let mut strings: Vec<String> = Vec::new();

    // Read up to 4 strings or until the end of stat_size
    let end_pos = 2 + stat_size as u64;
    while cursor.position() < end_pos && strings.len() < 4 {
        if let Ok(s) = String::decode(&mut cursor) {
            strings.push(s);
        } else {
            break;
        }
    }

    // Create stat with placeholder values
    let mut stat = Stat {
        r#type: 0,
        dev: 0,
        qid: Qid {
            qtype: 0,
            version: 0,
            path: 0,
        },
        mode: 0,
        atime: 0,
        mtime: 0,
        length: 0,
        name: String::new(),
        uid: String::new(),
        gid: String::new(),
        muid: String::new(),
    };

    // Assign strings based on how many we found
    if strings.len() >= 1 {
        stat.name = strings[0].clone();
    }
    if strings.len() >= 2 {
        stat.uid = strings[1].clone();
    }
    if strings.len() >= 3 {
        stat.gid = strings[2].clone();
    }
    if strings.len() >= 4 {
        stat.muid = strings[3].clone();
    }

    println!("VARIANT 4 RESULT: Found {} strings:", strings.len());
    for (i, s) in strings.iter().enumerate() {
        println!("  String {}: '{}'", i, s);
    }

    Ok(stat)
}

/// Variant 5: Skip size field entirely
fn decode_stat_skip_size(data: &[u8]) -> Result<Stat> {
    let mut cursor = Cursor::new(data);

    // Skip the size field
    cursor.set_position(2);

    // Read remaining fields
    let r#type = u16::decode(&mut cursor)?;
    let dev = u32::decode(&mut cursor)?;

    // Skip QID completely and try different offsets
    cursor.set_position(15); // Arbitrary skip

    let mode = u32::decode(&mut cursor)?;
    let atime = u32::decode(&mut cursor)?;
    let mtime = u32::decode(&mut cursor)?;
    let length = u64::decode(&mut cursor)?;

    // Try reading strings from where we are now
    let s1 = String::decode(&mut cursor).unwrap_or_default();
    let s2 = String::decode(&mut cursor).unwrap_or_default();

    let stat = Stat {
        r#type,
        dev,
        qid: Qid {
            qtype: 0,
            version: 0,
            path: 0,
        },
        mode,
        atime,
        mtime,
        length,
        name: String::new(),
        uid: s1.clone(),
        gid: s2.clone(),
        muid: String::new(),
    };

    println!("VARIANT 5 RESULT: {:?}", stat);
    println!("String1: '{}', String2: '{}'", s1, s2);

    Ok(stat)
}

/// Variant 6: Reversed numeric field order
fn decode_stat_reversed_nums(data: &[u8]) -> Result<Stat> {
    if data.len() < 60 {
        return Err(Error::InsufficientData {
            expected: 60,
            actual: data.len(),
        });
    }

    // Read things in reverse order to see if alignment changes
    let mut cursor = Cursor::new(data);

    // Skip past the size field
    cursor.set_position(2);

    // Try different combinations of fields
    let length = u64::decode(&mut cursor)?; // Read length first
    let mtime = u32::decode(&mut cursor)?;
    let atime = u32::decode(&mut cursor)?;
    let mode = u32::decode(&mut cursor)?;

    // QID fields in different order
    let path = u64::decode(&mut cursor)?;
    let version = u32::decode(&mut cursor)?;
    let qtype = u8::decode(&mut cursor)?;

    let dev = u32::decode(&mut cursor)?;
    let r#type = u16::decode(&mut cursor)?;

    // Try reading any strings left
    let pos = cursor.position();
    let s1 = if cursor.remaining() > 2 {
        String::decode(&mut cursor).unwrap_or_default()
    } else {
        String::new()
    };

    let s2 = if cursor.remaining() > 2 {
        String::decode(&mut cursor).unwrap_or_default()
    } else {
        String::new()
    };

    let stat = Stat {
        r#type,
        dev,
        qid: Qid {
            qtype,
            version,
            path,
        },
        mode,
        atime,
        mtime,
        length,
        name: String::new(),
        uid: s1.clone(),
        gid: s2.clone(),
        muid: String::new(),
    };

    println!("VARIANT 6 RESULT: {:?}", stat);
    println!("Reversed field order, string start at pos {}", pos);
    println!("String1: '{}', String2: '{}'", s1, s2);

    Ok(stat)
}

/// Variant 7: Direct cursor-based reading, byte by byte
fn decode_stat_cursor_bytes(data: &[u8]) -> Result<Stat> {
    // Raw parsing, reading bytes directly
    let mut cursor = Cursor::new(data);

    // Skip size field
    cursor.set_position(2);

    // Read fields as individual bytes to avoid alignment issues
    let mut bytes = [0u8; 8]; // Buffer for reading

    // Read type (2 bytes)
    cursor.read_exact(&mut bytes[0..2]).unwrap();
    let r#type = u16::from_le_bytes([bytes[0], bytes[1]]);

    // Read dev (4 bytes)
    cursor.read_exact(&mut bytes[0..4]).unwrap();
    let dev = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);

    // Read QID fields
    cursor.read_exact(&mut bytes[0..1]).unwrap();
    let qtype = bytes[0];

    cursor.read_exact(&mut bytes[0..4]).unwrap();
    let version = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);

    cursor.read_exact(&mut bytes[0..8]).unwrap();
    let path = u64::from_le_bytes(bytes);

    // Read mode (4 bytes)
    cursor.read_exact(&mut bytes[0..4]).unwrap();
    let mode = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);

    // Read atime (4 bytes)
    cursor.read_exact(&mut bytes[0..4]).unwrap();
    let atime = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);

    // Read mtime (4 bytes)
    cursor.read_exact(&mut bytes[0..4]).unwrap();
    let mtime = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);

    // Read length (8 bytes)
    cursor.read_exact(&mut bytes[0..8]).unwrap();
    let length = u64::from_le_bytes(bytes);

    // Custom string reading
    let mut read_string = || -> String {
        if cursor.remaining() < 2 {
            return String::new();
        }

        let mut len_bytes = [0u8; 2];
        cursor.read_exact(&mut len_bytes).unwrap();
        let len = u16::from_le_bytes(len_bytes) as usize;

        if len == 0 || cursor.remaining() < len {
            return String::new();
        }

        let mut str_bytes = vec![0u8; len];
        cursor.read_exact(&mut str_bytes).unwrap();
        String::from_utf8_lossy(&str_bytes).to_string()
    };

    let name = read_string();
    let uid = read_string();
    let gid = read_string();
    let muid = read_string();

    let stat = Stat {
        r#type,
        dev,
        qid: Qid {
            qtype,
            version,
            path,
        },
        mode,
        atime,
        mtime,
        length,
        name,
        uid,
        gid,
        muid,
    };

    println!("VARIANT 7 RESULT: {:?}", stat);
    println!("Byte-by-byte cursor reading");

    Ok(stat)
}

/// Variant 8: Manual inspection and string hunting
fn decode_stat_manual_inspection(data: &[u8]) -> Result<Stat> {
    // Dump the entire byte array for manual inspection
    println!("Full byte array:");
    for (i, chunk) in data.chunks(16).enumerate() {
        print!("{:04x}:  ", i * 16);
        for byte in chunk {
            print!("{:02x} ", *byte);
        }

        // Print ASCII representation
        print!("  ");
        for byte in chunk {
            if byte.is_ascii_graphic() || *byte == b' ' {
                print!("{}", *byte as char);
            } else {
                print!(".");
            }
        }
        println!();
    }

    // Look for potential strings in the byte array
    println!("\nPotential string locations:");

    let mut i = 0;
    while i < data.len() {
        // If we find a length byte followed by ASCII characters
        if i + 2 < data.len() {
            let len = u16::from_le_bytes([data[i], data[i + 1]]) as usize;
            if len > 0 && len < 100 && i + 2 + len <= data.len() {
                let text = &data[i + 2..i + 2 + len];
                if text.iter().all(|&b| b.is_ascii_graphic() || b == b' ') {
                    println!(
                        "Offset {:04x}: len={}, '{}'",
                        i,
                        len,
                        String::from_utf8_lossy(text)
                    );
                }
            }
        }
        i += 1;
    }

    // Create a placeholder stat
    let stat = Stat {
        r#type: 0,
        dev: 0,
        qid: Qid {
            qtype: 0,
            version: 0,
            path: 0,
        },
        mode: 0,
        atime: 0,
        mtime: 0,
        length: 0,
        name: String::new(),
        uid: String::new(),
        gid: String::new(),
        muid: String::new(),
    };

    println!("VARIANT 8: Manual inspection - examine the byte dump and potential strings");

    Ok(stat)
}

#[cfg(test)]
mod tests;
