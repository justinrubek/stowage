use crate::error::{Error, Result};
use bytes::{Buf, BufMut, BytesMut};
use std::convert::TryFrom;
use stowage_derive::{DecodeBytes, EncodeBytes};
use tokio_util::codec::{Decoder, Encoder};

pub mod consts;
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
        println!("dec: {:?}", message_body);
        let message = Message::decode(&mut message_body)?;

        Ok(Some(message))
    }
}

impl Encoder<Message> for Codec {
    type Error = Error;

    fn encode(&mut self, item: Message, dst: &mut BytesMut) -> Result<()> {
        // reserve space for message size + content
        dst.reserve(1024);

        // save current position to write size later
        let start_pos = dst.len();

        // add placeholder for size
        dst.put_u32_le(0);

        // encode the message
        item.encode(dst);

        // calculate and write the actual size
        let message_size = dst.len() - start_pos;
        let size_bytes = u32::try_from(message_size)?.to_le_bytes();
        dst[start_pos..start_pos + 4].copy_from_slice(&size_bytes);
        println!("enc: {:?}", dst);

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    Tlerror = 6,
    Rlerror = 7,
    Tstatfs = 8,
    Rstatfs = 9,
    Tlopen = 12,
    Rlopen = 13,
    Tlcreate = 14,
    Rlcreate = 15,
    Tsymlink = 16,
    Rsymlink = 17,
    Tmknod = 18,
    Rmknod = 19,
    Trename = 20,
    Rrename = 21,
    Treadlink = 22,
    Rreadlink = 23,
    Tgetattr = 24,
    Rgetattr = 25,
    Tsetattr = 26,
    Rsetattr = 27,
    Txattrwalk = 30,
    Rxattrwalk = 31,
    Txattrcreate = 32,
    Rxattrcreate = 33,
    Treaddir = 40,
    Rreaddir = 41,
    Tfsync = 50,
    Rfsync = 51,
    Tlock = 52,
    Rlock = 53,
    Tgetlock = 54,
    Rgetlock = 55,
    Tlink = 70,
    Rlink = 71,
    Tmkdir = 72,
    Rmkdir = 73,
    Trenameat = 74,
    Rrenameat = 75,
    Tunlinkat = 76,
    Runlinkat = 77,
    Tversion = 100,
    Rversion = 101,
    Tauth = 102,
    Rauth = 103,
    Tattach = 104,
    Rattach = 105,
    Tflush = 108,
    Rflush = 109,
    Twalk = 110,
    Rwalk = 111,
    Tread = 116,
    Rread = 117,
    Twrite = 118,
    Rwrite = 119,
    Tclunk = 120,
    Rclunk = 121,
    Tremove = 122,
    Rremove = 123,
}

/// File types
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

/// Bitmap for getattr
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GetattrMask {
    Mode = 0x00000001,
    Nlink = 0x00000002,
    Uid = 0x00000004,
    Gid = 0x00000008,
    Rdev = 0x00000010,
    Atime = 0x00000020,
    Mtime = 0x00000040,
    Ctime = 0x00000080,
    Ino = 0x00000100,
    Size = 0x00000200,
    Blocks = 0x00000400,
    Btime = 0x00000800,
    Gen = 0x00001000,
    DataVersion = 0x00002000,
    Basic = 0x000007ff, // Mask for fields up to blocks
    All = 0x00003fff,   // Mask for all fields
}

/// Setattr bitmask for which fields are valid
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetattrValid {
    Mode = 0x00000001,
    Uid = 0x00000002,
    Gid = 0x00000004,
    Size = 0x00000008,
    Atime = 0x00000010,
    Mtime = 0x00000020,
    Ctime = 0x00000040,
    AtimeSet = 0x00000080,
    MtimeSet = 0x00000100,
}

#[derive(Debug, Clone, PartialEq, DecodeBytes, EncodeBytes)]
pub struct Qid {
    pub qtype: u8,
    pub version: u32,
    pub path: u64,
}

#[derive(Debug, Clone, PartialEq, DecodeBytes, EncodeBytes)]
pub struct Stat {
    /// File type
    pub qtype: u16,
    /// Device ID
    pub dev: u32,
    /// Unique ID from the server
    pub qid: Qid,
    /// Permissions and flags
    pub mode: u32,
    /// Last access time
    pub atime: u32,
    /// Last modification time
    pub mtime: u32,
    /// Length in bytes
    pub length: u64,
    /// Filename
    pub name: String,
    /// Owner name
    pub uid: String,
    /// Group name
    pub gid: String,
    /// Last modifier name
    pub muid: String,
}

/// Linux-specific extended attribute structure
#[derive(Debug, Clone, PartialEq)]
pub struct Attr {
    pub valid: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub nlink: u64,
    pub rdev: u64,
    pub size: u64,
    pub blocks: u64,
    pub atime_sec: u64,
    pub atime_nsec: u64,
    pub mtime_sec: u64,
    pub mtime_nsec: u64,
    pub ctime_sec: u64,
    pub ctime_nsec: u64,
    pub btime_sec: u64,
    pub btime_nsec: u64,
    pub gen: u64,
    pub data_version: u64,
}

#[derive(Debug, Clone, PartialEq, DecodeBytes, EncodeBytes)]
pub struct Dirent {
    pub qid: Qid,
    pub offset: u64,
    pub dtype: u8,
    pub name: String,
}

/// Represents file system statistics
#[derive(Debug, Clone, PartialEq, DecodeBytes, EncodeBytes)]
pub struct StatFs {
    pub r#type: u32,
    pub bsize: u32,
    pub blocks: u64,
    pub bfree: u64,
    pub bavail: u64,
    pub files: u64,
    pub ffree: u64,
    pub fsid: u64,
    pub namelen: u32,
}

/// Lock structure for file locking
#[derive(Debug, Clone, PartialEq, DecodeBytes, EncodeBytes)]
pub struct Lock {
    pub ltype: u8,
    pub flags: u32,
    pub start: u64,
    pub length: u64,
    pub proc_id: u32,
    pub client_id: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Message {
    Rattach(Rattach),
    Rauth(Rauth),
    Rclunk(Rclunk),
    Rlcreate(Rlcreate),
    Rflush(Rflush),
    Rfsync(Rfsync),
    Rgetattr(Rgetattr),
    Rgetlock(Rgetlock),
    Rlerror(Rlerror),
    Rlock(Rlock),
    Rmkdir(Rmkdir),
    Rmknod(Rmknod),
    Rlopen(Rlopen),
    Rreaddir(Rreaddir),
    Rread(Rread),
    Rremove(Rremove),
    Tlink(Tlink),
    Rlink(Rlink),
    Tstatfs(Tstatfs),
    Rstatfs(Rstatfs),
    Rrenameat(Rrenameat),
    Rsetattr(Rsetattr),
    Rstat(Rstat),
    Rsymlink(Rsymlink),
    Runlinkat(Runlinkat),
    Rversion(Rversion),
    Rwalk(Rwalk),
    Rwrite(Rwrite),
    Rwstat(Rwstat),
    Rxattrcreate(Rxattrcreate),
    Rxattrwalk(Rxattrwalk),
    Tattach(Tattach),
    Tauth(Tauth),
    Tclunk(Tclunk),
    Tlcreate(Tlcreate),
    Tflush(Tflush),
    Tfsync(Tfsync),
    Tgetattr(Tgetattr),
    Tgetlock(Tgetlock),
    Tlock(Tlock),
    Tmkdir(Tmkdir),
    Tmknod(Tmknod),
    Tlopen(Tlopen),
    Treaddir(Treaddir),
    Tread(Tread),
    Treadlink(Treadlink),
    Rreadlink(Rreadlink),
    Tremove(Tremove),
    Trename(Trename),
    Rrename(Rrename),
    Trenameat(Trenameat),
    Tsetattr(Tsetattr),
    Tstat(Tstat),
    Tsymlink(Tsymlink),
    Tunlinkat(Tunlinkat),
    Tversion(Tversion),
    Twalk(Twalk),
    Twrite(Twrite),
    Twstat(Twstat),
    Txattrcreate(Txattrcreate),
    Txattrwalk(Txattrwalk),
}

// The error response type (used in the enum above)
#[derive(Debug, Clone, PartialEq)]
pub struct Rerror {
    pub tag: u16,
    pub ename: String,
    pub errno: u32, // Linux extension: includes numeric error code
}

impl Message {
    pub fn encode(&self, buf: &mut BytesMut) {
        match self {
            Message::Tlink(m) => m.encode_bytes(buf),
            Message::Rlink(m) => m.encode_bytes(buf),
            Message::Tstatfs(m) => m.encode_bytes(buf),
            Message::Rstatfs(m) => m.encode_bytes(buf),
            Message::Rversion(m) => m.encode_bytes(buf),
            Message::Tversion(m) => m.encode_bytes(buf),
            Message::Rversion(m) => m.encode_bytes(buf),
            Message::Tauth(m) => m.encode_bytes(buf),
            Message::Rauth(m) => m.encode_bytes(buf),
            Message::Tattach(m) => m.encode_bytes(buf),
            Message::Rattach(m) => m.encode_bytes(buf),
            Message::Tflush(m) => m.encode_bytes(buf),
            Message::Rflush(m) => m.encode_bytes(buf),
            Message::Twalk(m) => m.encode_bytes(buf),
            Message::Rwalk(m) => m.encode_bytes(buf),
            Message::Tlopen(m) => m.encode_bytes(buf),
            Message::Rlopen(m) => m.encode_bytes(buf),
            Message::Tlcreate(m) => m.encode_bytes(buf),
            Message::Rlcreate(m) => m.encode_bytes(buf),
            Message::Tread(m) => m.encode_bytes(buf),
            Message::Rread(m) => m.encode_bytes(buf),
            Message::Twrite(m) => m.encode_bytes(buf),
            Message::Rwrite(m) => m.encode_bytes(buf),
            Message::Tclunk(m) => m.encode_bytes(buf),
            Message::Rclunk(m) => m.encode_bytes(buf),
            Message::Tremove(m) => m.encode_bytes(buf),
            Message::Rremove(m) => m.encode_bytes(buf),
            Message::Tstat(m) => m.encode_bytes(buf),
            Message::Rstat(m) => m.encode_bytes(buf),
            Message::Twstat(m) => m.encode_bytes(buf),
            Message::Rwstat(m) => m.encode_bytes(buf),
            Message::Treadlink(m) => m.encode_bytes(buf),
            Message::Rreadlink(m) => m.encode_bytes(buf),
            Message::Tgetattr(m) => m.encode_bytes(buf),
            Message::Rgetattr(m) => m.encode_bytes(buf),
            Message::Tsetattr(m) => m.encode_bytes(buf),
            Message::Rsetattr(m) => m.encode_bytes(buf),
            Message::Txattrwalk(m) => m.encode_bytes(buf),
            Message::Rxattrwalk(m) => m.encode_bytes(buf),
            Message::Txattrcreate(m) => m.encode_bytes(buf),
            Message::Rxattrcreate(m) => m.encode_bytes(buf),
            Message::Treaddir(m) => m.encode_bytes(buf),
            Message::Rreaddir(m) => m.encode_bytes(buf),
            Message::Tfsync(m) => m.encode_bytes(buf),
            Message::Rfsync(m) => m.encode_bytes(buf),
            Message::Tlock(m) => m.encode_bytes(buf),
            Message::Rlock(m) => m.encode_bytes(buf),
            Message::Tgetlock(m) => m.encode_bytes(buf),
            Message::Rgetlock(m) => m.encode_bytes(buf),
            Message::Tmkdir(m) => m.encode_bytes(buf),
            Message::Rmkdir(m) => m.encode_bytes(buf),
            Message::Trename(m) => m.encode_bytes(buf),
            Message::Rrename(m) => m.encode_bytes(buf),
            Message::Trenameat(m) => m.encode_bytes(buf),
            Message::Rrenameat(m) => m.encode_bytes(buf),
            Message::Tunlinkat(m) => m.encode_bytes(buf),
            Message::Runlinkat(m) => m.encode_bytes(buf),
            Message::Tsymlink(m) => m.encode_bytes(buf),
            Message::Rsymlink(m) => m.encode_bytes(buf),
            Message::Tmknod(m) => m.encode_bytes(buf),
            Message::Rmknod(m) => m.encode_bytes(buf),
            Message::Rlerror(m) => m.encode_bytes(buf),
        }
    }

    pub fn decode(buf: &mut BytesMut) -> Result<Self> {
        if buf.len() < 3 {
            println!("decode: too small");
            return Err(Error::BufferTooSmall);
        }

        let typ = buf.get_u8();
        // we don't consume the tag here since each DecodeBytes implementation will read it

        match MessageType::try_from(typ) {
            Ok(MessageType::Tversion) => Ok(Message::Tversion(Tversion::decode_bytes(buf)?)),
            Ok(MessageType::Rversion) => Ok(Message::Rversion(Rversion::decode_bytes(buf)?)),
            Ok(MessageType::Tauth) => Ok(Message::Tauth(Tauth::decode_bytes(buf)?)),
            Ok(MessageType::Rauth) => Ok(Message::Rauth(Rauth::decode_bytes(buf)?)),
            Ok(MessageType::Tattach) => Ok(Message::Tattach(Tattach::decode_bytes(buf)?)),
            Ok(MessageType::Rattach) => Ok(Message::Rattach(Rattach::decode_bytes(buf)?)),
            Ok(MessageType::Tflush) => Ok(Message::Tflush(Tflush::decode_bytes(buf)?)),
            Ok(MessageType::Rflush) => Ok(Message::Rflush(Rflush::decode_bytes(buf)?)),
            Ok(MessageType::Twalk) => Ok(Message::Twalk(Twalk::decode_bytes(buf)?)),
            Ok(MessageType::Rwalk) => Ok(Message::Rwalk(Rwalk::decode_bytes(buf)?)),
            Ok(MessageType::Tread) => Ok(Message::Tread(Tread::decode_bytes(buf)?)),
            Ok(MessageType::Rread) => Ok(Message::Rread(Rread::decode_bytes(buf)?)),
            Ok(MessageType::Twrite) => Ok(Message::Twrite(Twrite::decode_bytes(buf)?)),
            Ok(MessageType::Rwrite) => Ok(Message::Rwrite(Rwrite::decode_bytes(buf)?)),
            Ok(MessageType::Tclunk) => Ok(Message::Tclunk(Tclunk::decode_bytes(buf)?)),
            Ok(MessageType::Rclunk) => Ok(Message::Rclunk(Rclunk::decode_bytes(buf)?)),
            Ok(MessageType::Tremove) => Ok(Message::Tremove(Tremove::decode_bytes(buf)?)),
            Ok(MessageType::Rremove) => Ok(Message::Rremove(Rremove::decode_bytes(buf)?)),

            // Linux-specific message types
            Ok(MessageType::Tgetattr) => Ok(Message::Tgetattr(Tgetattr::decode_bytes(buf)?)),
            Ok(MessageType::Rgetattr) => Ok(Message::Rgetattr(Rgetattr::decode_bytes(buf)?)),
            Ok(MessageType::Tsetattr) => Ok(Message::Tsetattr(Tsetattr::decode_bytes(buf)?)),
            Ok(MessageType::Rsetattr) => Ok(Message::Rsetattr(Rsetattr::decode_bytes(buf)?)),
            Ok(MessageType::Txattrwalk) => Ok(Message::Txattrwalk(Txattrwalk::decode_bytes(buf)?)),
            Ok(MessageType::Rxattrwalk) => Ok(Message::Rxattrwalk(Rxattrwalk::decode_bytes(buf)?)),
            Ok(MessageType::Txattrcreate) => {
                Ok(Message::Txattrcreate(Txattrcreate::decode_bytes(buf)?))
            }
            Ok(MessageType::Rxattrcreate) => {
                Ok(Message::Rxattrcreate(Rxattrcreate::decode_bytes(buf)?))
            }
            Ok(MessageType::Treaddir) => Ok(Message::Treaddir(Treaddir::decode_bytes(buf)?)),
            Ok(MessageType::Rreaddir) => Ok(Message::Rreaddir(Rreaddir::decode_bytes(buf)?)),
            Ok(MessageType::Tfsync) => Ok(Message::Tfsync(Tfsync::decode_bytes(buf)?)),
            Ok(MessageType::Rfsync) => Ok(Message::Rfsync(Rfsync::decode_bytes(buf)?)),
            Ok(MessageType::Tlock) => Ok(Message::Tlock(Tlock::decode_bytes(buf)?)),
            Ok(MessageType::Rlock) => Ok(Message::Rlock(Rlock::decode_bytes(buf)?)),
            Ok(MessageType::Tgetlock) => Ok(Message::Tgetlock(Tgetlock::decode_bytes(buf)?)),
            Ok(MessageType::Rgetlock) => Ok(Message::Rgetlock(Rgetlock::decode_bytes(buf)?)),
            Ok(MessageType::Tmkdir) => Ok(Message::Tmkdir(Tmkdir::decode_bytes(buf)?)),
            Ok(MessageType::Rmkdir) => Ok(Message::Rmkdir(Rmkdir::decode_bytes(buf)?)),
            Ok(MessageType::Trename) => Ok(Message::Trename(Trename::decode_bytes(buf)?)),
            Ok(MessageType::Rrename) => Ok(Message::Rrename(Rrename::decode_bytes(buf)?)),
            Ok(MessageType::Trenameat) => Ok(Message::Trenameat(Trenameat::decode_bytes(buf)?)),
            Ok(MessageType::Rrenameat) => Ok(Message::Rrenameat(Rrenameat::decode_bytes(buf)?)),
            Ok(MessageType::Tunlinkat) => Ok(Message::Tunlinkat(Tunlinkat::decode_bytes(buf)?)),
            Ok(MessageType::Runlinkat) => Ok(Message::Runlinkat(Runlinkat::decode_bytes(buf)?)),
            Ok(MessageType::Tsymlink) => Ok(Message::Tsymlink(Tsymlink::decode_bytes(buf)?)),
            Ok(MessageType::Rsymlink) => Ok(Message::Rsymlink(Rsymlink::decode_bytes(buf)?)),
            Ok(MessageType::Tmknod) => Ok(Message::Tmknod(Tmknod::decode_bytes(buf)?)),
            Ok(MessageType::Rmknod) => Ok(Message::Rmknod(Rmknod::decode_bytes(buf)?)),

            // Error handling
            Ok(MessageType::Rlerror) => Ok(Message::Rlerror(Rlerror::decode_bytes(buf)?)),

            // Invalid message types
            _ => Err(Error::InvalidMessageType(typ)),
        }
    }
}

impl TryFrom<u8> for MessageType {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            6 => Ok(MessageType::Tlerror),
            7 => Ok(MessageType::Rlerror),
            8 => Ok(MessageType::Tstatfs),
            9 => Ok(MessageType::Rstatfs),
            12 => Ok(MessageType::Tlopen),
            13 => Ok(MessageType::Rlopen),
            14 => Ok(MessageType::Tlcreate),
            15 => Ok(MessageType::Rlcreate),
            16 => Ok(MessageType::Tsymlink),
            17 => Ok(MessageType::Rsymlink),
            18 => Ok(MessageType::Tmknod),
            19 => Ok(MessageType::Rmknod),
            20 => Ok(MessageType::Trename),
            21 => Ok(MessageType::Rrename),
            22 => Ok(MessageType::Treadlink),
            23 => Ok(MessageType::Rreadlink),
            24 => Ok(MessageType::Tgetattr),
            25 => Ok(MessageType::Rgetattr),
            26 => Ok(MessageType::Tsetattr),
            27 => Ok(MessageType::Rsetattr),
            30 => Ok(MessageType::Txattrwalk),
            31 => Ok(MessageType::Rxattrwalk),
            32 => Ok(MessageType::Txattrcreate),
            33 => Ok(MessageType::Rxattrcreate),
            40 => Ok(MessageType::Treaddir),
            41 => Ok(MessageType::Rreaddir),
            50 => Ok(MessageType::Tfsync),
            51 => Ok(MessageType::Rfsync),
            52 => Ok(MessageType::Tlock),
            53 => Ok(MessageType::Rlock),
            54 => Ok(MessageType::Tgetlock),
            55 => Ok(MessageType::Rgetlock),
            70 => Ok(MessageType::Tlink),
            71 => Ok(MessageType::Rlink),
            72 => Ok(MessageType::Tmkdir),
            73 => Ok(MessageType::Rmkdir),
            74 => Ok(MessageType::Trenameat),
            75 => Ok(MessageType::Rrenameat),
            76 => Ok(MessageType::Tunlinkat),
            77 => Ok(MessageType::Runlinkat),

            100 => Ok(MessageType::Tversion),
            101 => Ok(MessageType::Rversion),
            102 => Ok(MessageType::Tauth),
            103 => Ok(MessageType::Rauth),
            104 => Ok(MessageType::Tattach),
            105 => Ok(MessageType::Rattach),
            108 => Ok(MessageType::Tflush),
            109 => Ok(MessageType::Rflush),
            110 => Ok(MessageType::Twalk),
            111 => Ok(MessageType::Rwalk),
            116 => Ok(MessageType::Tread),
            117 => Ok(MessageType::Rread),
            118 => Ok(MessageType::Twrite),
            119 => Ok(MessageType::Rwrite),
            120 => Ok(MessageType::Tclunk),
            121 => Ok(MessageType::Rclunk),
            122 => Ok(MessageType::Tremove),
            123 => Ok(MessageType::Rremove),
            _ => Err(Error::InvalidMessageType(value)),
        }
    }
}

impl Message {
    pub fn get_tag(&self) -> u16 {
        match self {
            Message::Tlink(m) => m.tag,
            Message::Rlink(m) => m.tag,
            Message::Tstatfs(m) => m.tag,
            Message::Rstatfs(m) => m.tag,
            Message::Tversion(m) => m.tag,
            Message::Rversion(m) => m.tag,
            Message::Tauth(m) => m.tag,
            Message::Rauth(m) => m.tag,
            Message::Tattach(m) => m.tag,
            Message::Rattach(m) => m.tag,
            Message::Tflush(m) => m.tag,
            Message::Rflush(m) => m.tag,
            Message::Twalk(m) => m.tag,
            Message::Rwalk(m) => m.tag,
            Message::Tlopen(m) => m.tag,
            Message::Rlopen(m) => m.tag,
            Message::Tlcreate(m) => m.tag,
            Message::Rlcreate(m) => m.tag,
            Message::Tread(m) => m.tag,
            Message::Rread(m) => m.tag,
            Message::Treadlink(m) => m.tag,
            Message::Rreadlink(m) => m.tag,
            Message::Twrite(m) => m.tag,
            Message::Rwrite(m) => m.tag,
            Message::Tclunk(m) => m.tag,
            Message::Rclunk(m) => m.tag,
            Message::Tremove(m) => m.tag,
            Message::Rremove(m) => m.tag,
            Message::Tstat(m) => m.tag,
            Message::Rstat(m) => m.tag,
            Message::Twstat(m) => m.tag,
            Message::Rwstat(m) => m.tag,

            // Linux-specific 9P2000.L extensions
            Message::Tgetattr(m) => m.tag,
            Message::Rgetattr(m) => m.tag,
            Message::Tsetattr(m) => m.tag,
            Message::Rsetattr(m) => m.tag,
            Message::Txattrwalk(m) => m.tag,
            Message::Rxattrwalk(m) => m.tag,
            Message::Txattrcreate(m) => m.tag,
            Message::Rxattrcreate(m) => m.tag,
            Message::Treaddir(m) => m.tag,
            Message::Rreaddir(m) => m.tag,
            Message::Tfsync(m) => m.tag,
            Message::Rfsync(m) => m.tag,
            Message::Tlock(m) => m.tag,
            Message::Rlock(m) => m.tag,
            Message::Tgetlock(m) => m.tag,
            Message::Rgetlock(m) => m.tag,
            Message::Tmkdir(m) => m.tag,
            Message::Rmkdir(m) => m.tag,
            Message::Trename(m) => m.tag,
            Message::Rrename(m) => m.tag,
            Message::Trenameat(m) => m.tag,
            Message::Rrenameat(m) => m.tag,
            Message::Tunlinkat(m) => m.tag,
            Message::Runlinkat(m) => m.tag,
            Message::Tsymlink(m) => m.tag,
            Message::Rsymlink(m) => m.tag,
            Message::Tmknod(m) => m.tag,
            Message::Rmknod(m) => m.tag,

            // Error response
            Message::Rlerror(m) => m.tag,
        }
    }
}

#[derive(Debug, Clone, PartialEq, DecodeBytes, EncodeBytes)]
pub struct Tversion {
    pub tag: u16,
    pub msize: u32,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, DecodeBytes, EncodeBytes)]
pub struct Rversion {
    pub tag: u16,
    pub msize: u32,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, DecodeBytes, EncodeBytes)]
pub struct Tauth {
    pub tag: u16,
    pub afid: u32,
    pub uname: String,
    pub aname: String,
}

#[derive(Debug, Clone, PartialEq, DecodeBytes, EncodeBytes)]
pub struct Rauth {
    pub tag: u16,
    pub aqid: Qid,
}

#[derive(Debug, Clone, PartialEq, DecodeBytes, EncodeBytes)]
pub struct Tattach {
    pub tag: u16,
    pub fid: u32,
    pub afid: u32,
    pub uname: String,
    pub aname: String,
}

#[derive(Debug, Clone, PartialEq, DecodeBytes, EncodeBytes)]
pub struct Rattach {
    pub tag: u16,
    pub qid: Qid,
}

#[derive(Debug, Clone, PartialEq, DecodeBytes, EncodeBytes)]
pub struct Tflush {
    pub tag: u16,
    pub oldtag: u16,
}

#[derive(Debug, Clone, PartialEq, DecodeBytes, EncodeBytes)]
pub struct Rflush {
    pub tag: u16,
}

#[derive(Debug, Clone, PartialEq, DecodeBytes, EncodeBytes)]
pub struct Twalk {
    pub tag: u16,
    pub fid: u32,
    pub newfid: u32,
    pub wnames: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, DecodeBytes, EncodeBytes)]
pub struct Rwalk {
    pub tag: u16,
    pub wqids: Vec<Qid>,
}

#[derive(Debug, Clone, PartialEq, DecodeBytes, EncodeBytes)]
pub struct Tlopen {
    pub tag: u16,
    pub fid: u32,
    pub flags: u32,
}

#[derive(Debug, Clone, PartialEq, DecodeBytes, EncodeBytes)]
pub struct Rlopen {
    pub tag: u16,
    pub qid: Qid,
    pub iounit: u32,
}

#[derive(Debug, Clone, PartialEq, DecodeBytes, EncodeBytes)]
pub struct Tlcreate {
    pub tag: u16,
    pub fid: u32,
    pub name: String,
    pub flags: u32,
    pub mode: u32,
    pub gid: u32,
}

#[derive(Debug, Clone, PartialEq, DecodeBytes, EncodeBytes)]
pub struct Rlcreate {
    pub tag: u16,
    pub qid: Qid,
    pub iounit: u32,
}

#[derive(Debug, Clone, PartialEq, DecodeBytes, EncodeBytes)]
pub struct Tread {
    pub tag: u16,
    pub fid: u32,
    pub offset: u64,
    pub count: u32,
}

#[derive(Debug, Clone, PartialEq, DecodeBytes, EncodeBytes)]
pub struct Rread {
    pub tag: u16,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, DecodeBytes, EncodeBytes)]
pub struct Twrite {
    pub tag: u16,
    pub fid: u32,
    pub offset: u64,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, DecodeBytes, EncodeBytes)]
pub struct Rwrite {
    pub tag: u16,
    pub count: u32,
}

#[derive(Debug, Clone, PartialEq, DecodeBytes, EncodeBytes)]
pub struct Tclunk {
    pub tag: u16,
    pub fid: u32,
}

#[derive(Debug, Clone, PartialEq, DecodeBytes, EncodeBytes)]
pub struct Rclunk {
    pub tag: u16,
}

#[derive(Debug, Clone, PartialEq, DecodeBytes, EncodeBytes)]
pub struct Tremove {
    pub tag: u16,
    pub fid: u32,
}

#[derive(Debug, Clone, PartialEq, DecodeBytes, EncodeBytes)]
pub struct Rremove {
    pub tag: u16,
}

#[derive(Debug, Clone, PartialEq, DecodeBytes, EncodeBytes)]
pub struct Tstat {
    pub tag: u16,
    pub fid: u32,
}

#[derive(Debug, Clone, PartialEq, DecodeBytes, EncodeBytes)]
pub struct Rstat {
    pub tag: u16,
    pub stat: Stat,
}

#[derive(Debug, Clone, PartialEq, DecodeBytes, EncodeBytes)]
pub struct Twstat {
    pub tag: u16,
    pub fid: u32,
    pub stat: Stat,
}

#[derive(Debug, Clone, PartialEq, DecodeBytes, EncodeBytes)]
pub struct Rwstat {
    pub tag: u16,
}

#[derive(Debug, Clone, PartialEq, DecodeBytes, EncodeBytes)]
pub struct Treadlink {
    pub tag: u16,
    pub fid: u32,
}

#[derive(Debug, Clone, PartialEq, DecodeBytes, EncodeBytes)]
pub struct Rreadlink {
    pub tag: u16,
    pub target: String,
}

#[derive(Debug, Clone, PartialEq, DecodeBytes, EncodeBytes)]
pub struct Tlink {
    pub tag: u16,
    pub dfid: u32,
    pub fid: u32,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, DecodeBytes, EncodeBytes)]
pub struct Rlink {
    pub tag: u16,
}

#[derive(Debug, Clone, PartialEq, DecodeBytes, EncodeBytes)]
pub struct Tgetattr {
    pub tag: u16,
    pub fid: u32,
    pub request_mask: u64,
}

#[derive(Debug, Clone, PartialEq, DecodeBytes, EncodeBytes)]
pub struct Rgetattr {
    pub tag: u16,
    pub valid: u64,
    pub qid: Qid,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub nlink: u64,
    pub rdev: u64,
    pub size: u64,
    pub blksize: u64,
    pub blocks: u64,
    pub atime_sec: u64,
    pub atime_nsec: u64,
    pub mtime_sec: u64,
    pub mtime_nsec: u64,
    pub ctime_sec: u64,
    pub ctime_nsec: u64,
    pub btime_sec: u64,
    pub btime_nsec: u64,
    pub gen: u64,
    pub data_version: u64,
}

#[derive(Debug, Clone, PartialEq, DecodeBytes, EncodeBytes)]
pub struct Tsetattr {
    pub tag: u16,
    pub fid: u32,
    pub valid: u32,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub atime_sec: u64,
    pub atime_nsec: u64,
    pub mtime_sec: u64,
    pub mtime_nsec: u64,
}

#[derive(Debug, Clone, PartialEq, DecodeBytes, EncodeBytes)]
pub struct Rsetattr {
    pub tag: u16,
}

#[derive(Debug, Clone, PartialEq, DecodeBytes, EncodeBytes)]
pub struct Txattrwalk {
    pub tag: u16,
    pub fid: u32,
    pub newfid: u32,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, DecodeBytes, EncodeBytes)]
pub struct Rxattrwalk {
    pub tag: u16,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, DecodeBytes, EncodeBytes)]
pub struct Txattrcreate {
    pub tag: u16,
    pub fid: u32,
    pub name: String,
    pub attr_size: u64,
    pub flags: u32,
}

#[derive(Debug, Clone, PartialEq, DecodeBytes, EncodeBytes)]
pub struct Rxattrcreate {
    pub tag: u16,
}

#[derive(Debug, Clone, PartialEq, DecodeBytes, EncodeBytes)]
pub struct Treaddir {
    pub tag: u16,
    pub fid: u32,
    pub offset: u64,
    pub count: u32,
}

#[derive(Debug, Clone, PartialEq, DecodeBytes, EncodeBytes)]
pub struct Rreaddir {
    pub tag: u16,
    pub data: Vec<Dirent>, // Contains packed Dirent structures
}

#[derive(Debug, Clone, PartialEq, DecodeBytes, EncodeBytes)]
pub struct Tfsync {
    pub tag: u16,
    pub fid: u32,
}

#[derive(Debug, Clone, PartialEq, DecodeBytes, EncodeBytes)]
pub struct Rfsync {
    pub tag: u16,
}

#[derive(Debug, Clone, PartialEq, DecodeBytes, EncodeBytes)]
pub struct Tlock {
    pub tag: u16,
    pub fid: u32,
    pub type_: u8,
    pub flags: u32,
    pub start: u64,
    pub length: u64,
    pub proc_id: u32,
    pub client_id: String,
}

#[derive(Debug, Clone, PartialEq, DecodeBytes, EncodeBytes)]
pub struct Rlock {
    pub tag: u16,
    pub status: u8,
}

#[derive(Debug, Clone, PartialEq, DecodeBytes, EncodeBytes)]
pub struct Tgetlock {
    pub tag: u16,
    pub fid: u32,
    pub type_: u8,
    pub start: u64,
    pub length: u64,
    pub proc_id: u32,
    pub client_id: String,
}

#[derive(Debug, Clone, PartialEq, DecodeBytes, EncodeBytes)]
pub struct Rgetlock {
    pub tag: u16,
    pub type_: u8,
    pub start: u64,
    pub length: u64,
    pub proc_id: u32,
    pub client_id: String,
}

#[derive(Debug, Clone, PartialEq, DecodeBytes, EncodeBytes)]
pub struct Tmkdir {
    pub tag: u16,
    pub dfid: u32,
    pub name: String,
    pub mode: u32,
    pub gid: u32,
}

#[derive(Debug, Clone, PartialEq, DecodeBytes, EncodeBytes)]
pub struct Rmkdir {
    pub tag: u16,
    pub qid: Qid,
}

#[derive(Debug, Clone, PartialEq, DecodeBytes, EncodeBytes)]
pub struct Trename {
    pub tag: u16,
    pub fid: u32,
    pub dfid: u32,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, DecodeBytes, EncodeBytes)]
pub struct Rrename {
    pub tag: u16,
}

#[derive(Debug, Clone, PartialEq, DecodeBytes, EncodeBytes)]
pub struct Trenameat {
    pub tag: u16,
    pub olddirfid: u32,
    pub oldname: String,
    pub newdirfid: u32,
    pub newname: String,
}

#[derive(Debug, Clone, PartialEq, DecodeBytes, EncodeBytes)]
pub struct Rrenameat {
    pub tag: u16,
}

#[derive(Debug, Clone, PartialEq, DecodeBytes, EncodeBytes)]
pub struct Tunlinkat {
    pub tag: u16,
    pub dirfid: u32,
    pub name: String,
    pub flags: u32,
}

#[derive(Debug, Clone, PartialEq, DecodeBytes, EncodeBytes)]
pub struct Runlinkat {
    pub tag: u16,
}

#[derive(Debug, Clone, PartialEq, DecodeBytes, EncodeBytes)]
pub struct Tsymlink {
    pub tag: u16,
    pub fid: u32,
    pub name: String,
    pub symtgt: String,
    pub gid: u32,
}

#[derive(Debug, Clone, PartialEq, DecodeBytes, EncodeBytes)]
pub struct Rsymlink {
    pub tag: u16,
    pub qid: Qid,
}

#[derive(Debug, Clone, PartialEq, DecodeBytes, EncodeBytes)]
pub struct Tmknod {
    pub tag: u16,
    pub dirfid: u32,
    pub name: String,
    pub mode: u32,
    pub major: u32,
    pub minor: u32,
    pub gid: u32,
}

#[derive(Debug, Clone, PartialEq, DecodeBytes, EncodeBytes)]
pub struct Tstatfs {
    pub tag: u16,
    pub fid: u32,
}

#[derive(Debug, Clone, PartialEq, DecodeBytes, EncodeBytes)]
pub struct Rstatfs {
    pub tag: u16,
    pub r#type: u32,
    pub bsize: u32,
    pub blocks: u64,
    pub bfree: u64,
    pub bavail: u64,
    pub files: u64,
    pub ffree: u64,
    pub fsid: u64,
    pub namelen: u32,
}

#[derive(Debug, Clone, PartialEq, DecodeBytes, EncodeBytes)]
pub struct Rmknod {
    pub tag: u16,
    pub qid: Qid,
}

#[derive(Debug, Clone, PartialEq, DecodeBytes, EncodeBytes)]
pub struct Rlerror {
    pub tag: u16,
    pub ecode: u32,
}

pub trait DecodeBytes: Sized {
    fn decode_bytes(buf: &mut BytesMut) -> Result<Self>;
}

pub trait EncodeBytes {
    fn encode_bytes(&self, buf: &mut BytesMut);
}

impl DecodeBytes for u8 {
    fn decode_bytes(buf: &mut BytesMut) -> Result<Self> {
        if buf.is_empty() {
            println!("u8: too small");
            return Err(Error::BufferTooSmall);
        }
        Ok(buf.get_u8())
    }
}

impl EncodeBytes for u8 {
    fn encode_bytes(&self, buf: &mut BytesMut) {
        buf.put_u8(*self);
    }
}

impl DecodeBytes for u16 {
    fn decode_bytes(buf: &mut BytesMut) -> Result<Self> {
        if buf.len() < 2 {
            println!("u16: too small");
            return Err(Error::BufferTooSmall);
        }
        Ok(buf.get_u16_le())
    }
}

impl EncodeBytes for u16 {
    fn encode_bytes(&self, buf: &mut BytesMut) {
        buf.put_u16_le(*self);
    }
}

impl DecodeBytes for u32 {
    fn decode_bytes(buf: &mut BytesMut) -> Result<Self> {
        if buf.len() < 4 {
            println!("u32: too small");
            return Err(Error::BufferTooSmall);
        }
        Ok(buf.get_u32_le())
    }
}

impl EncodeBytes for u32 {
    fn encode_bytes(&self, buf: &mut BytesMut) {
        buf.put_u32_le(*self);
    }
}

impl DecodeBytes for u64 {
    fn decode_bytes(buf: &mut BytesMut) -> Result<Self> {
        if buf.len() < 8 {
            println!("u64: too small");
            return Err(Error::BufferTooSmall);
        }
        Ok(buf.get_u64_le())
    }
}

impl EncodeBytes for u64 {
    fn encode_bytes(&self, buf: &mut BytesMut) {
        buf.put_u64_le(*self);
    }
}

impl DecodeBytes for String {
    fn decode_bytes(buf: &mut BytesMut) -> Result<Self> {
        // First decode the string length as u32
        let length = u16::decode_bytes(buf)? as usize;

        // Check if we have enough bytes for the string
        if buf.len() < length {
            println!("string: too small");
            return Err(Error::BufferTooSmall);
        }

        // Extract the string bytes
        let bytes = buf.split_to(length);

        // Convert to UTF-8 string
        String::from_utf8(bytes.to_vec()).map_err(|_| Error::InvalidUtf8)
    }
}

impl EncodeBytes for String {
    fn encode_bytes(&self, buf: &mut BytesMut) {
        // First encode the length as u32
        (self.len() as u16).encode_bytes(buf);

        // Then encode the string bytes
        buf.put_slice(self.as_bytes());
    }
}

impl DecodeBytes for Vec<u8> {
    fn decode_bytes(buf: &mut BytesMut) -> Result<Self> {
        if buf.len() < 4 {
            println!("Vec<u8>: too small");
            return Err(Error::BufferTooSmall);
        }

        // Read 4-byte length prefix (data blocks use 4 bytes for length)
        let len = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        buf.advance(4);

        if buf.len() < len {
            println!("Vec<u8>: too small");
            return Err(Error::BufferTooSmall);
        }

        // Extract the data bytes
        let data = buf.split_to(len).to_vec();
        Ok(data)
    }
}

impl EncodeBytes for Vec<u8> {
    fn encode_bytes(&self, buf: &mut BytesMut) {
        // Ensure buffer capacity
        buf.reserve(4 + self.len());

        // Write 4-byte length
        buf.extend_from_slice(&(self.len() as u32).to_le_bytes());

        // Write data bytes
        buf.extend_from_slice(self);
    }
}

// Implementation for Vec<String> (e.g., wnames in Twalk)
impl DecodeBytes for Vec<String> {
    fn decode_bytes(buf: &mut BytesMut) -> Result<Self> {
        if buf.len() < 2 {
            println!("Vec<String> too small");
            return Err(Error::BufferTooSmall);
        }

        // Read 2-byte count prefix
        let count = u16::from_le_bytes([buf[0], buf[1]]) as usize;
        buf.advance(2);

        let mut strings = Vec::with_capacity(count);
        for _ in 0..count {
            strings.push(String::decode_bytes(buf)?);
        }

        Ok(strings)
    }
}

impl EncodeBytes for Vec<String> {
    fn encode_bytes(&self, buf: &mut BytesMut) {
        // Write 2-byte count
        buf.extend_from_slice(&(self.len() as u16).to_le_bytes());

        // Write each string
        for s in self {
            s.encode_bytes(buf);
        }
    }
}

// Implementation for Vec<Qid> (e.g., wqids in Rwalk)
impl DecodeBytes for Vec<Qid> {
    fn decode_bytes(buf: &mut BytesMut) -> Result<Self> {
        if buf.len() < 2 {
            println!("Vec<Qid> too small");
            return Err(Error::BufferTooSmall);
        }

        // Read 2-byte count prefix
        let count = u16::from_le_bytes([buf[0], buf[1]]) as usize;
        buf.advance(2);

        let mut qids = Vec::with_capacity(count);
        for _ in 0..count {
            qids.push(Qid::decode_bytes(buf)?);
        }

        Ok(qids)
    }
}

impl EncodeBytes for Vec<Qid> {
    fn encode_bytes(&self, buf: &mut BytesMut) {
        // Write 2-byte count
        buf.extend_from_slice(&(self.len() as u16).to_le_bytes());

        // Write each Qid
        for qid in self {
            qid.encode_bytes(buf);
        }
    }
}

// Implementation for Vec<Dirent> (used in Rreaddir)
impl DecodeBytes for Vec<Dirent> {
    fn decode_bytes(buf: &mut BytesMut) -> Result<Self> {
        // For Rreaddir, the data section contains consecutive Dirent entries
        // until the buffer is exhausted
        let mut dirents = Vec::new();

        // Keep decoding until buffer is empty
        while !buf.is_empty() {
            // Dirent has specific format according to 9P2000.L
            // Each entry should be decodable as a Dirent
            dirents.push(Dirent::decode_bytes(buf)?);
        }

        Ok(dirents)
    }
}

impl EncodeBytes for Vec<Dirent> {
    fn encode_bytes(&self, buf: &mut BytesMut) {
        // For Rreaddir, we just concatenate the entries
        for dirent in self {
            dirent.encode_bytes(buf);
        }
    }
}
