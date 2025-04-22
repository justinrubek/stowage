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
    // Classic 9P messages
    Tversion = 100,
    Rversion = 101,
    Tauth = 102,
    Rauth = 103,
    Tattach = 104,
    Rattach = 105,
    /// Not used in protocol - illegal message type
    #[doc(hidden)]
    #[deprecated(note = "Terror is an illegal message type in 9P protocol")]
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
    Topenfd = 98,
    Ropenfd = 99,
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

#[derive(Debug, Clone, PartialEq)]
pub struct Qid {
    pub qtype: u8,
    pub version: u32,
    pub path: u64,
}

/// Traditional 9P stat structure, kept for compatibility
#[derive(Debug, Clone, PartialEq)]
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

/// Represents a directory entry in 9P2000.L
#[derive(Debug, Clone, PartialEq)]
pub struct Dirent {
    pub qid: Qid,
    pub offset: u64,
    pub typ: u8,
    pub name: String,
}

/// Represents file system statistics
#[derive(Debug, Clone, PartialEq)]
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
#[derive(Debug, Clone, PartialEq)]
pub struct Lock {
    pub r#type: u8,
    pub flags: u32,
    pub start: u64,
    pub length: u64,
    pub proc_id: u32,
    pub client_id: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Message {
    // Classic 9P messages
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
    Tauth {
        tag: u16,
        afid: u32,
        uname: String,
        aname: String,
    },
    Rauth {
        tag: u16,
        aqid: Qid,
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
    Rlerror {
        tag: u16,
        ecode: u32,
    },
    Tflush {
        tag: u16,
        oldtag: u16,
    },
    Rflush {
        tag: u16,
    },
    Twalk {
        tag: u16,
        fid: u32,
        newfid: u32,
        wnames: Vec<String>,
    },
    Rwalk {
        tag: u16,
        wqids: Vec<Qid>,
    },
    Topen {
        tag: u16,
        fid: u32,
        mode: u8,
    },
    Ropen {
        tag: u16,
        qid: Qid,
        iounit: u32,
    },
    Tcreate {
        tag: u16,
        fid: u32,
        name: String,
        perm: u32,
        mode: u8,
    },
    Rcreate {
        tag: u16,
        qid: Qid,
        iounit: u32,
    },
    Tread {
        tag: u16,
        fid: u32,
        offset: u64,
        count: u32,
    },
    Rread {
        tag: u16,
        data: Vec<u8>,
    },
    Twrite {
        tag: u16,
        fid: u32,
        offset: u64,
        data: Vec<u8>,
    },
    Rwrite {
        tag: u16,
        count: u32,
    },
    Tclunk {
        tag: u16,
        fid: u32,
    },
    Rclunk {
        tag: u16,
    },
    Tremove {
        tag: u16,
        fid: u32,
    },
    Rremove {
        tag: u16,
    },
    Tstat {
        tag: u16,
        fid: u32,
    },
    Rstat {
        tag: u16,
        stat: Stat,
    },
    Twstat {
        tag: u16,
        fid: u32,
        stat: Stat,
    },
    Rwstat {
        tag: u16,
    },
    Topenfd {
        tag: u16,
        fid: u32,
        mode: u8,
    },
    Ropenfd {
        tag: u16,
        qid: Qid,
        iounit: u32,
        fd: u32,
    },

    // 9P2000.L specific messages
    Tlopen {
        tag: u16,
        fid: u32,
        flags: u32,
    },
    Rlopen {
        tag: u16,
        qid: Qid,
        iounit: u32,
    },
    Tlcreate {
        tag: u16,
        fid: u32,
        name: String,
        flags: u32,
        mode: u32,
        gid: u32,
    },
    Rlcreate {
        tag: u16,
        qid: Qid,
        iounit: u32,
    },
    Tsymlink {
        tag: u16,
        fid: u32,
        name: String,
        symtgt: String,
        gid: u32,
    },
    Rsymlink {
        tag: u16,
        qid: Qid,
    },
    Tmknod {
        tag: u16,
        dfid: u32,
        name: String,
        mode: u32,
        major: u32,
        minor: u32,
        gid: u32,
    },
    Rmknod {
        tag: u16,
        qid: Qid,
    },
    Trename {
        tag: u16,
        fid: u32,
        dfid: u32,
        name: String,
    },
    Rrename {
        tag: u16,
    },
    Treadlink {
        tag: u16,
        fid: u32,
    },
    Rreadlink {
        tag: u16,
        target: String,
    },
    Tgetattr {
        tag: u16,
        fid: u32,
        request_mask: u64,
    },
    Rgetattr {
        tag: u16,
        valid: u64,
        qid: Qid,
        mode: u32,
        uid: u32,
        gid: u32,
        nlink: u64,
        rdev: u64,
        size: u64,
        blksize: u64,
        blocks: u64,
        atime_sec: u64,
        atime_nsec: u64,
        mtime_sec: u64,
        mtime_nsec: u64,
        ctime_sec: u64,
        ctime_nsec: u64,
        btime_sec: u64,
        btime_nsec: u64,
        gen: u64,
        data_version: u64,
    },
    Tsetattr {
        tag: u16,
        fid: u32,
        valid: u32,
        mode: u32,
        uid: u32,
        gid: u32,
        size: u64,
        atime_sec: u64,
        atime_nsec: u64,
        mtime_sec: u64,
        mtime_nsec: u64,
    },
    Rsetattr {
        tag: u16,
    },
    Txattrwalk {
        tag: u16,
        fid: u32,
        newfid: u32,
        name: String,
    },
    Rxattrwalk {
        tag: u16,
        size: u64,
    },
    Txattrcreate {
        tag: u16,
        fid: u32,
        name: String,
        attr_size: u64,
        flags: u32,
    },
    Rxattrcreate {
        tag: u16,
    },
    Treaddir {
        tag: u16,
        fid: u32,
        offset: u64,
        count: u32,
    },
    Rreaddir {
        tag: u16,
        data: Vec<Dirent>,
    },
    Tfsync {
        tag: u16,
        fid: u32,
    },
    Rfsync {
        tag: u16,
    },
    Tlock {
        tag: u16,
        fid: u32,
        lock: Lock,
    },
    Rlock {
        tag: u16,
        status: u8,
    },
    Tgetlock {
        tag: u16,
        fid: u32,
        lock: Lock,
    },
    Rgetlock {
        tag: u16,
        lock: Lock,
    },
    Tlink {
        tag: u16,
        dfid: u32,
        fid: u32,
        name: String,
    },
    Rlink {
        tag: u16,
    },
    Tmkdir {
        tag: u16,
        dfid: u32,
        name: String,
        mode: u32,
        gid: u32,
    },
    Rmkdir {
        tag: u16,
        qid: Qid,
    },
    Trenameat {
        tag: u16,
        olddirfid: u32,
        oldname: String,
        newdirfid: u32,
        newname: String,
    },
    Rrenameat {
        tag: u16,
    },
    Tunlinkat {
        tag: u16,
        dirfid: u32,
        name: String,
        flags: u32,
    },
    Runlinkat {
        tag: u16,
    },
    Tstatfs {
        tag: u16,
        fid: u32,
    },
    Rstatfs {
        tag: u16,
        statfs: StatFs,
    },
}

impl Message {
    #[allow(clippy::too_many_lines)]
    pub fn encode(&self, buf: &mut BytesMut) {
        match self {
            Message::Tversion {
                tag,
                msize,
                version,
            } => {
                buf.put_u8(MessageType::Tversion as u8);
                buf.put_u16_le(*tag);
                buf.put_u32_le(*msize);
                encode_string(buf, version);
            }
            Message::Rversion {
                tag,
                msize,
                version,
            } => {
                buf.put_u8(MessageType::Rversion as u8);
                buf.put_u16_le(*tag);
                buf.put_u32_le(*msize);
                encode_string(buf, version);
            }
            Message::Tauth {
                tag,
                afid,
                uname,
                aname,
            } => {
                buf.put_u8(MessageType::Tauth as u8);
                buf.put_u16_le(*tag);
                buf.put_u32_le(*afid);
                encode_string(buf, uname);
                encode_string(buf, aname);
            }
            Message::Rauth { tag, aqid } => {
                buf.put_u8(MessageType::Rauth as u8);
                buf.put_u16_le(*tag);
                encode_qid(buf, aqid);
            }
            Message::Tattach {
                tag,
                fid,
                afid,
                uname,
                aname,
            } => {
                buf.put_u8(MessageType::Tattach as u8);
                buf.put_u16_le(*tag);
                buf.put_u32_le(*fid);
                buf.put_u32_le(*afid);
                encode_string(buf, uname);
                encode_string(buf, aname);
            }
            Message::Rattach { tag, qid } => {
                buf.put_u8(MessageType::Rattach as u8);
                buf.put_u16_le(*tag);
                encode_qid(buf, qid);
            }
            Message::Rerror { tag, ename } => {
                buf.put_u8(MessageType::Rerror as u8);
                buf.put_u16_le(*tag);
                encode_string(buf, ename);
            }
            Message::Rlerror { tag, ecode } => {
                buf.put_u8(MessageType::Rlerror as u8);
                buf.put_u16_le(*tag);
                buf.put_u32_le(*ecode);
            }
            Message::Tflush { tag, oldtag } => {
                buf.put_u8(MessageType::Tflush as u8);
                buf.put_u16_le(*tag);
                buf.put_u16_le(*oldtag);
            }
            Message::Rflush { tag } => {
                buf.put_u8(MessageType::Rflush as u8);
                buf.put_u16_le(*tag);
            }
            Message::Twalk {
                tag,
                fid,
                newfid,
                wnames,
            } => {
                buf.put_u8(MessageType::Twalk as u8);
                buf.put_u16_le(*tag);
                buf.put_u32_le(*fid);
                buf.put_u32_le(*newfid);

                // number of walk elements
                buf.put_u16_le(wnames.len() as u16);

                // encode each name
                for name in wnames {
                    encode_string(buf, name);
                }
            }
            Message::Rwalk { tag, wqids } => {
                buf.put_u8(MessageType::Rwalk as u8);
                buf.put_u16_le(*tag);

                // number of qids
                buf.put_u16_le(wqids.len() as u16);

                // encode each qid
                for qid in wqids {
                    encode_qid(buf, qid);
                }
            }
            Message::Topen { tag, fid, mode } => {
                buf.put_u8(MessageType::Topen as u8);
                buf.put_u16_le(*tag);
                buf.put_u32_le(*fid);
                buf.put_u8(*mode);
            }
            Message::Ropen { tag, qid, iounit } => {
                buf.put_u8(MessageType::Ropen as u8);
                buf.put_u16_le(*tag);
                encode_qid(buf, qid);
                buf.put_u32_le(*iounit);
            }
            Message::Tcreate {
                tag,
                fid,
                name,
                perm,
                mode,
            } => {
                buf.put_u8(MessageType::Tcreate as u8);
                buf.put_u16_le(*tag);
                buf.put_u32_le(*fid);
                encode_string(buf, name);
                buf.put_u32_le(*perm);
                buf.put_u8(*mode);
            }
            Message::Rcreate { tag, qid, iounit } => {
                buf.put_u8(MessageType::Rcreate as u8);
                buf.put_u16_le(*tag);
                encode_qid(buf, qid);
                buf.put_u32_le(*iounit);
            }
            Message::Tread {
                tag,
                fid,
                offset,
                count,
            } => {
                buf.put_u8(MessageType::Tread as u8);
                buf.put_u16_le(*tag);
                buf.put_u32_le(*fid);
                buf.put_u64_le(*offset);
                buf.put_u32_le(*count);
            }
            Message::Rread { tag, data } => {
                buf.put_u8(MessageType::Rread as u8);
                buf.put_u16_le(*tag);
                buf.put_u32_le(data.len() as u32);
                buf.put_slice(data);
            }
            Message::Twrite {
                tag,
                fid,
                offset,
                data,
            } => {
                buf.put_u8(MessageType::Twrite as u8);
                buf.put_u16_le(*tag);
                buf.put_u32_le(*fid);
                buf.put_u64_le(*offset);
                buf.put_u32_le(data.len() as u32);
                buf.put_slice(data);
            }
            Message::Rwrite { tag, count } => {
                buf.put_u8(MessageType::Rwrite as u8);
                buf.put_u16_le(*tag);
                buf.put_u32_le(*count);
            }
            Message::Tclunk { tag, fid } => {
                buf.put_u8(MessageType::Tclunk as u8);
                buf.put_u16_le(*tag);
                buf.put_u32_le(*fid);
            }
            Message::Rclunk { tag } => {
                buf.put_u8(MessageType::Rclunk as u8);
                buf.put_u16_le(*tag);
            }
            Message::Tremove { tag, fid } => {
                buf.put_u8(MessageType::Tremove as u8);
                buf.put_u16_le(*tag);
                buf.put_u32_le(*fid);
            }
            Message::Rremove { tag } => {
                buf.put_u8(MessageType::Rremove as u8);
                buf.put_u16_le(*tag);
            }
            Message::Tstat { tag, fid } => {
                buf.put_u8(MessageType::Tstat as u8);
                buf.put_u16_le(*tag);
                buf.put_u32_le(*fid);
            }
            Message::Rstat { tag, stat } => {
                buf.put_u8(MessageType::Rstat as u8);
                buf.put_u16_le(*tag);

                // reserve space for stat size
                let stat_start = buf.len();
                buf.put_u16_le(0);

                // encode stat structure
                encode_stat(buf, stat);

                // update size field
                let stat_size = buf.len() - stat_start - 2;
                let size_bytes = (stat_size as u16).to_le_bytes();
                buf[stat_start..stat_start + 2].copy_from_slice(&size_bytes);
            }
            Message::Twstat { tag, fid, stat } => {
                buf.put_u8(MessageType::Twstat as u8);
                buf.put_u16_le(*tag);
                buf.put_u32_le(*fid);

                // reserve space for stat size
                let stat_start = buf.len();
                buf.put_u16_le(0);

                // encode stat structure
                encode_stat(buf, stat);

                // update size field
                let stat_size = buf.len() - stat_start - 2;
                let size_bytes = (stat_size as u16).to_le_bytes();
                buf[stat_start..stat_start + 2].copy_from_slice(&size_bytes);
            }
            Message::Rwstat { tag } => {
                buf.put_u8(MessageType::Rwstat as u8);
                buf.put_u16_le(*tag);
            }
            Message::Topenfd { tag, fid, mode } => {
                buf.put_u8(MessageType::Topenfd as u8);
                buf.put_u16_le(*tag);
                buf.put_u32_le(*fid);
                buf.put_u8(*mode);
            }
            Message::Ropenfd {
                tag,
                qid,
                iounit,
                fd,
            } => {
                buf.put_u8(MessageType::Ropenfd as u8);
                buf.put_u16_le(*tag);
                encode_qid(buf, qid);
                buf.put_u32_le(*iounit);
                buf.put_u32_le(*fd);
            }
            // 9P2000.L specific message encoding
            Message::Tlopen { tag, fid, flags } => {
                buf.put_u8(MessageType::Tlopen as u8);
                buf.put_u16_le(*tag);
                buf.put_u32_le(*fid);
                buf.put_u32_le(*flags);
            }
            Message::Rlopen { tag, qid, iounit } => {
                buf.put_u8(MessageType::Rlopen as u8);
                buf.put_u16_le(*tag);
                encode_qid(buf, qid);
                buf.put_u32_le(*iounit);
            }
            Message::Tlcreate {
                tag,
                fid,
                name,
                flags,
                mode,
                gid,
            } => {
                buf.put_u8(MessageType::Tlcreate as u8);
                buf.put_u16_le(*tag);
                buf.put_u32_le(*fid);
                encode_string(buf, name);
                buf.put_u32_le(*flags);
                buf.put_u32_le(*mode);
                buf.put_u32_le(*gid);
            }
            Message::Rlcreate { tag, qid, iounit } => {
                buf.put_u8(MessageType::Rlcreate as u8);
                buf.put_u16_le(*tag);
                encode_qid(buf, qid);
                buf.put_u32_le(*iounit);
            }
            Message::Tsymlink {
                tag,
                fid,
                name,
                symtgt,
                gid,
            } => {
                buf.put_u8(MessageType::Tsymlink as u8);
                buf.put_u16_le(*tag);
                buf.put_u32_le(*fid);
                encode_string(buf, name);
                encode_string(buf, symtgt);
                buf.put_u32_le(*gid);
            }
            Message::Rsymlink { tag, qid } => {
                buf.put_u8(MessageType::Rsymlink as u8);
                buf.put_u16_le(*tag);
                encode_qid(buf, qid);
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
                buf.put_u8(MessageType::Tmknod as u8);
                buf.put_u16_le(*tag);
                buf.put_u32_le(*dfid);
                encode_string(buf, name);
                buf.put_u32_le(*mode);
                buf.put_u32_le(*major);
                buf.put_u32_le(*minor);
                buf.put_u32_le(*gid);
            }
            Message::Rmknod { tag, qid } => {
                buf.put_u8(MessageType::Rmknod as u8);
                buf.put_u16_le(*tag);
                encode_qid(buf, qid);
            }
            Message::Trename {
                tag,
                fid,
                dfid,
                name,
            } => {
                buf.put_u8(MessageType::Trename as u8);
                buf.put_u16_le(*tag);
                buf.put_u32_le(*fid);
                buf.put_u32_le(*dfid);
                encode_string(buf, name);
            }
            Message::Rrename { tag } => {
                buf.put_u8(MessageType::Rrename as u8);
                buf.put_u16_le(*tag);
            }
            Message::Treadlink { tag, fid } => {
                buf.put_u8(MessageType::Treadlink as u8);
                buf.put_u16_le(*tag);
                buf.put_u32_le(*fid);
            }
            Message::Rreadlink { tag, target } => {
                buf.put_u8(MessageType::Rreadlink as u8);
                buf.put_u16_le(*tag);
                encode_string(buf, target);
            }
            Message::Tgetattr {
                tag,
                fid,
                request_mask,
            } => {
                buf.put_u8(MessageType::Tgetattr as u8);
                buf.put_u16_le(*tag);
                buf.put_u32_le(*fid);
                buf.put_u64_le(*request_mask);
            }
            Message::Rgetattr {
                tag,
                valid,
                qid,
                mode,
                uid,
                gid,
                nlink,
                rdev,
                size,
                blksize,
                blocks,
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
            } => {
                buf.put_u8(MessageType::Rgetattr as u8);
                buf.put_u16_le(*tag);
                buf.put_u64_le(*valid);

                // Encode qid (13 bytes)
                buf.put_u8(qid.qtype);
                buf.put_u32_le(qid.version);
                buf.put_u64_le(qid.path);

                // Encode remaining attributes
                buf.put_u32_le(*mode);
                buf.put_u32_le(*uid);
                buf.put_u32_le(*gid);
                buf.put_u64_le(*nlink);
                buf.put_u64_le(*rdev);
                buf.put_u64_le(*size);
                buf.put_u64_le(*blksize);
                buf.put_u64_le(*blocks);
                buf.put_u64_le(*atime_sec);
                buf.put_u64_le(*atime_nsec);
                buf.put_u64_le(*mtime_sec);
                buf.put_u64_le(*mtime_nsec);
                buf.put_u64_le(*ctime_sec);
                buf.put_u64_le(*ctime_nsec);
                buf.put_u64_le(*btime_sec);
                buf.put_u64_le(*btime_nsec);
                buf.put_u64_le(*gen);
                buf.put_u64_le(*data_version);
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
                buf.put_u8(MessageType::Tsetattr as u8);
                buf.put_u16_le(*tag);
                buf.put_u32_le(*fid);
                buf.put_u32_le(*valid);
                buf.put_u32_le(*mode);
                buf.put_u32_le(*uid);
                buf.put_u32_le(*gid);
                buf.put_u64_le(*size);
                buf.put_u64_le(*atime_sec);
                buf.put_u64_le(*atime_nsec);
                buf.put_u64_le(*mtime_sec);
                buf.put_u64_le(*mtime_nsec);
            }
            Message::Rsetattr { tag } => {
                buf.put_u8(MessageType::Rsetattr as u8);
                buf.put_u16_le(*tag);
            }
            Message::Txattrwalk {
                tag,
                fid,
                newfid,
                name,
            } => {
                buf.put_u8(MessageType::Txattrwalk as u8);
                buf.put_u16_le(*tag);
                buf.put_u32_le(*fid);
                buf.put_u32_le(*newfid);
                encode_string(buf, name);
            }
            Message::Rxattrwalk { tag, size } => {
                buf.put_u8(MessageType::Rxattrwalk as u8);
                buf.put_u16_le(*tag);
                buf.put_u64_le(*size);
            }
            Message::Txattrcreate {
                tag,
                fid,
                name,
                attr_size,
                flags,
            } => {
                buf.put_u8(MessageType::Txattrcreate as u8);
                buf.put_u16_le(*tag);
                buf.put_u32_le(*fid);
                encode_string(buf, name);
                buf.put_u64_le(*attr_size);
                buf.put_u32_le(*flags);
            }
            Message::Rxattrcreate { tag } => {
                buf.put_u8(MessageType::Rxattrcreate as u8);
                buf.put_u16_le(*tag);
            }
            Message::Treaddir {
                tag,
                fid,
                offset,
                count,
            } => {
                buf.put_u8(MessageType::Treaddir as u8);
                buf.put_u16_le(*tag);
                buf.put_u32_le(*fid);
                buf.put_u64_le(*offset);
                buf.put_u32_le(*count);
            }
            Message::Rreaddir { tag, data } => {
                buf.put_u8(MessageType::Rreaddir as u8);
                buf.put_u16_le(*tag);

                // Reserve space for data size
                let count_pos = buf.len();
                buf.put_u32_le(0);

                // Encode all directory entries
                let start_pos = buf.len();
                for entry in data {
                    encode_dirent(buf, entry);
                }

                // Update count field
                let count = (buf.len() - start_pos) as u32;
                let count_bytes = count.to_le_bytes();
                buf[count_pos..count_pos + 4].copy_from_slice(&count_bytes);
            }
            Message::Tfsync { tag, fid } => {
                buf.put_u8(MessageType::Tfsync as u8);
                buf.put_u16_le(*tag);
                buf.put_u32_le(*fid);
            }
            Message::Rfsync { tag } => {
                buf.put_u8(MessageType::Rfsync as u8);
                buf.put_u16_le(*tag);
            }
            Message::Tlock { tag, fid, lock } => {
                buf.put_u8(MessageType::Tlock as u8);
                buf.put_u16_le(*tag);
                buf.put_u32_le(*fid);
                encode_lock(buf, lock);
            }
            Message::Rlock { tag, status } => {
                buf.put_u8(MessageType::Rlock as u8);
                buf.put_u16_le(*tag);
                buf.put_u8(*status);
            }
            Message::Tgetlock { tag, fid, lock } => {
                buf.put_u8(MessageType::Tgetlock as u8);
                buf.put_u16_le(*tag);
                buf.put_u32_le(*fid);
                encode_lock(buf, lock);
            }
            Message::Rgetlock { tag, lock } => {
                buf.put_u8(MessageType::Rgetlock as u8);
                buf.put_u16_le(*tag);
                encode_lock(buf, lock);
            }
            Message::Tlink {
                tag,
                dfid,
                fid,
                name,
            } => {
                buf.put_u8(MessageType::Tlink as u8);
                buf.put_u16_le(*tag);
                buf.put_u32_le(*dfid);
                buf.put_u32_le(*fid);
                encode_string(buf, name);
            }
            Message::Rlink { tag } => {
                buf.put_u8(MessageType::Rlink as u8);
                buf.put_u16_le(*tag);
            }
            Message::Tmkdir {
                tag,
                dfid,
                name,
                mode,
                gid,
            } => {
                buf.put_u8(MessageType::Tmkdir as u8);
                buf.put_u16_le(*tag);
                buf.put_u32_le(*dfid);
                encode_string(buf, name);
                buf.put_u32_le(*mode);
                buf.put_u32_le(*gid);
            }
            Message::Rmkdir { tag, qid } => {
                buf.put_u8(MessageType::Rmkdir as u8);
                buf.put_u16_le(*tag);
                encode_qid(buf, qid);
            }
            Message::Trenameat {
                tag,
                olddirfid,
                oldname,
                newdirfid,
                newname,
            } => {
                buf.put_u8(MessageType::Trenameat as u8);
                buf.put_u16_le(*tag);
                buf.put_u32_le(*olddirfid);
                encode_string(buf, oldname);
                buf.put_u32_le(*newdirfid);
                encode_string(buf, newname);
            }
            Message::Rrenameat { tag } => {
                buf.put_u8(MessageType::Rrenameat as u8);
                buf.put_u16_le(*tag);
            }
            Message::Tunlinkat {
                tag,
                dirfid,
                name,
                flags,
            } => {
                buf.put_u8(MessageType::Tunlinkat as u8);
                buf.put_u16_le(*tag);
                buf.put_u32_le(*dirfid);
                encode_string(buf, name);
                buf.put_u32_le(*flags);
            }
            Message::Runlinkat { tag } => {
                buf.put_u8(MessageType::Runlinkat as u8);
                buf.put_u16_le(*tag);
            }
            Message::Tstatfs { tag, fid } => {
                buf.put_u8(MessageType::Tstatfs as u8);
                buf.put_u16_le(*tag);
                buf.put_u32_le(*fid);
            }
            Message::Rstatfs { tag, statfs } => {
                buf.put_u8(MessageType::Rstatfs as u8);
                buf.put_u16_le(*tag);
                encode_statfs(buf, statfs);
            }
        }
    }

    pub fn decode(buf: &mut BytesMut) -> Result<Self> {
        if buf.len() < 3 {
            return Err(Error::BufferTooShort);
        }

        let typ = buf.get_u8();
        let tag = buf.get_u16_le();
        println!("type: {typ}");
        println!("tag: {tag}");

        match MessageType::try_from(typ) {
            Ok(MessageType::Tversion) => {
                let msize = buf.get_u32_le();
                let version = decode_string(buf)?;
                Ok(Message::Tversion {
                    tag,
                    msize,
                    version,
                })
            }
            Ok(MessageType::Rversion) => {
                let msize = buf.get_u32_le();
                let version = decode_string(buf)?;
                Ok(Message::Rversion {
                    tag,
                    msize,
                    version,
                })
            }
            Ok(MessageType::Tauth) => {
                let afid = buf.get_u32_le();
                let uname = decode_string(buf)?;
                let aname = decode_string(buf)?;
                Ok(Message::Tauth {
                    tag,
                    afid,
                    uname,
                    aname,
                })
            }
            Ok(MessageType::Rauth) => {
                let aqid = decode_qid(buf)?;
                Ok(Message::Rauth { tag, aqid })
            }
            Ok(MessageType::Tattach) => {
                let fid = buf.get_u32_le();
                let afid = buf.get_u32_le();
                let uname = decode_string(buf)?;
                let aname = decode_string(buf)?;
                Ok(Message::Tattach {
                    tag,
                    fid,
                    afid,
                    uname,
                    aname,
                })
            }
            Ok(MessageType::Rattach) => {
                let qid = decode_qid(buf)?;
                Ok(Message::Rattach { tag, qid })
            }
            Ok(MessageType::Rerror) => {
                let ename = decode_string(buf)?;
                Ok(Message::Rerror { tag, ename })
            }
            Ok(MessageType::Rlerror) => {
                let ecode = buf.get_u32_le();
                Ok(Message::Rlerror { tag, ecode })
            }
            Ok(MessageType::Tflush) => {
                let oldtag = buf.get_u16_le();
                Ok(Message::Tflush { tag, oldtag })
            }
            Ok(MessageType::Rflush) => Ok(Message::Rflush { tag }),
            Ok(MessageType::Twalk) => {
                let fid = buf.get_u32_le();
                let newfid = buf.get_u32_le();
                let nwname = buf.get_u16_le() as usize;

                let mut wnames = Vec::with_capacity(nwname);
                for _ in 0..nwname {
                    wnames.push(decode_string(buf)?);
                }

                Ok(Message::Twalk {
                    tag,
                    fid,
                    newfid,
                    wnames,
                })
            }
            Ok(MessageType::Rwalk) => {
                let nwqid = buf.get_u16_le() as usize;

                let mut wqids = Vec::with_capacity(nwqid);
                for _ in 0..nwqid {
                    wqids.push(decode_qid(buf)?);
                }

                Ok(Message::Rwalk { tag, wqids })
            }
            Ok(MessageType::Topen) => {
                let fid = buf.get_u32_le();
                let mode = buf.get_u8();
                Ok(Message::Topen { tag, fid, mode })
            }
            Ok(MessageType::Ropen) => {
                let qid = decode_qid(buf)?;
                let iounit = buf.get_u32_le();
                Ok(Message::Ropen { tag, qid, iounit })
            }
            Ok(MessageType::Tcreate) => {
                let fid = buf.get_u32_le();
                let name = decode_string(buf)?;
                let perm = buf.get_u32_le();
                let mode = buf.get_u8();
                Ok(Message::Tcreate {
                    tag,
                    fid,
                    name,
                    perm,
                    mode,
                })
            }
            Ok(MessageType::Rcreate) => {
                let qid = decode_qid(buf)?;
                let iounit = buf.get_u32_le();
                Ok(Message::Rcreate { tag, qid, iounit })
            }
            Ok(MessageType::Tread) => {
                let fid = buf.get_u32_le();
                let offset = buf.get_u64_le();
                let count = buf.get_u32_le();
                Ok(Message::Tread {
                    tag,
                    fid,
                    offset,
                    count,
                })
            }
            Ok(MessageType::Rread) => {
                let count = buf.get_u32_le() as usize;
                if buf.len() < count {
                    return Err(Error::BufferTooShort);
                }

                let data = buf.split_to(count).to_vec();
                Ok(Message::Rread { tag, data })
            }
            Ok(MessageType::Twrite) => {
                let fid = buf.get_u32_le();
                let offset = buf.get_u64_le();
                let count = buf.get_u32_le() as usize;

                if buf.len() < count {
                    return Err(Error::BufferTooShort);
                }

                let data = buf.split_to(count).to_vec();
                Ok(Message::Twrite {
                    tag,
                    fid,
                    offset,
                    data,
                })
            }
            Ok(MessageType::Rwrite) => {
                let count = buf.get_u32_le();
                Ok(Message::Rwrite { tag, count })
            }
            Ok(MessageType::Tclunk) => {
                let fid = buf.get_u32_le();
                Ok(Message::Tclunk { tag, fid })
            }
            Ok(MessageType::Rclunk) => Ok(Message::Rclunk { tag }),
            Ok(MessageType::Tremove) => {
                let fid = buf.get_u32_le();
                Ok(Message::Tremove { tag, fid })
            }
            Ok(MessageType::Rremove) => Ok(Message::Rremove { tag }),
            Ok(MessageType::Tstat) => {
                let fid = buf.get_u32_le();
                Ok(Message::Tstat { tag, fid })
            }
            Ok(MessageType::Rstat) => {
                // Skip the stat size field since we decode the entire structure
                let _stat_size = buf.get_u16_le();
                let stat = decode_stat(buf)?;
                Ok(Message::Rstat { tag, stat })
            }
            Ok(MessageType::Twstat) => {
                let fid = buf.get_u32_le();
                // Skip the stat size field
                let _stat_size = buf.get_u16_le();
                let stat = decode_stat(buf)?;
                Ok(Message::Twstat { tag, fid, stat })
            }
            Ok(MessageType::Rwstat) => Ok(Message::Rwstat { tag }),
            Ok(MessageType::Topenfd) => {
                let fid = buf.get_u32_le();
                let mode = buf.get_u8();
                Ok(Message::Topenfd { tag, fid, mode })
            }
            Ok(MessageType::Ropenfd) => {
                let qid = decode_qid(buf)?;
                let iounit = buf.get_u32_le();
                let fd = buf.get_u32_le();
                Ok(Message::Ropenfd {
                    tag,
                    qid,
                    iounit,
                    fd,
                })
            }
            // 9P2000.L specific message decoding
            Ok(MessageType::Tlopen) => {
                let fid = buf.get_u32_le();
                let flags = buf.get_u32_le();
                Ok(Message::Tlopen { tag, fid, flags })
            }
            Ok(MessageType::Rlopen) => {
                let qid = decode_qid(buf)?;
                let iounit = buf.get_u32_le();
                Ok(Message::Rlopen { tag, qid, iounit })
            }
            Ok(MessageType::Tlcreate) => {
                let fid = buf.get_u32_le();
                let name = decode_string(buf)?;
                let flags = buf.get_u32_le();
                let mode = buf.get_u32_le();
                let gid = buf.get_u32_le();
                Ok(Message::Tlcreate {
                    tag,
                    fid,
                    name,
                    flags,
                    mode,
                    gid,
                })
            }
            Ok(MessageType::Rlcreate) => {
                let qid = decode_qid(buf)?;
                let iounit = buf.get_u32_le();
                Ok(Message::Rlcreate { tag, qid, iounit })
            }
            Ok(MessageType::Tsymlink) => {
                let fid = buf.get_u32_le();
                let name = decode_string(buf)?;
                let symtgt = decode_string(buf)?;
                let gid = buf.get_u32_le();
                Ok(Message::Tsymlink {
                    tag,
                    fid,
                    name,
                    symtgt,
                    gid,
                })
            }
            Ok(MessageType::Rsymlink) => {
                let qid = decode_qid(buf)?;
                Ok(Message::Rsymlink { tag, qid })
            }
            Ok(MessageType::Tmknod) => {
                let dfid = buf.get_u32_le();
                let name = decode_string(buf)?;
                let mode = buf.get_u32_le();
                let major = buf.get_u32_le();
                let minor = buf.get_u32_le();
                let gid = buf.get_u32_le();
                Ok(Message::Tmknod {
                    tag,
                    dfid,
                    name,
                    mode,
                    major,
                    minor,
                    gid,
                })
            }
            Ok(MessageType::Rmknod) => {
                let qid = decode_qid(buf)?;
                Ok(Message::Rmknod { tag, qid })
            }
            Ok(MessageType::Trename) => {
                let fid = buf.get_u32_le();
                let dfid = buf.get_u32_le();
                let name = decode_string(buf)?;
                Ok(Message::Trename {
                    tag,
                    fid,
                    dfid,
                    name,
                })
            }
            Ok(MessageType::Rrename) => Ok(Message::Rrename { tag }),
            Ok(MessageType::Treadlink) => {
                let fid = buf.get_u32_le();
                Ok(Message::Treadlink { tag, fid })
            }
            Ok(MessageType::Rreadlink) => {
                let target = decode_string(buf)?;
                Ok(Message::Rreadlink { tag, target })
            }
            Ok(MessageType::Tgetattr) => {
                let fid = buf.get_u32_le();
                let request_mask = buf.get_u64_le();
                Ok(Message::Tgetattr {
                    tag,
                    fid,
                    request_mask,
                })
            }
            Ok(MessageType::Rgetattr) => {
                let valid = buf.get_u64_le();

                // Decode qid (13 bytes)
                let qid_type = buf.get_u8();
                let qid_version = buf.get_u32_le();
                let qid_path = buf.get_u64_le();
                let qid = Qid {
                    qtype: qid_type,
                    version: qid_version,
                    path: qid_path,
                };

                // Decode remaining attributes
                let mode = buf.get_u32_le();
                let uid = buf.get_u32_le();
                let gid = buf.get_u32_le();
                let nlink = buf.get_u64_le();
                let rdev = buf.get_u64_le();
                let size = buf.get_u64_le();
                let blksize = buf.get_u64_le();
                let blocks = buf.get_u64_le();
                let atime_sec = buf.get_u64_le();
                let atime_nsec = buf.get_u64_le();
                let mtime_sec = buf.get_u64_le();
                let mtime_nsec = buf.get_u64_le();
                let ctime_sec = buf.get_u64_le();
                let ctime_nsec = buf.get_u64_le();
                let btime_sec = buf.get_u64_le();
                let btime_nsec = buf.get_u64_le();
                let gen = buf.get_u64_le();
                let data_version = buf.get_u64_le();

                Ok(Message::Rgetattr {
                    tag,
                    valid,
                    qid,
                    mode,
                    uid,
                    gid,
                    nlink,
                    rdev,
                    size,
                    blksize: 4096, // Default block size, you can adjust as needed
                    blocks,
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
                })
            }
            Ok(MessageType::Tsetattr) => {
                let fid = buf.get_u32_le();
                let valid = buf.get_u32_le();
                let mode = buf.get_u32_le();
                let uid = buf.get_u32_le();
                let gid = buf.get_u32_le();
                let size = buf.get_u64_le();
                let atime_sec = buf.get_u64_le();
                let atime_nsec = buf.get_u64_le();
                let mtime_sec = buf.get_u64_le();
                let mtime_nsec = buf.get_u64_le();
                Ok(Message::Tsetattr {
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
                })
            }
            Ok(MessageType::Rsetattr) => Ok(Message::Rsetattr { tag }),
            Ok(MessageType::Txattrwalk) => {
                let fid = buf.get_u32_le();
                let newfid = buf.get_u32_le();
                let name = decode_string(buf)?;
                Ok(Message::Txattrwalk {
                    tag,
                    fid,
                    newfid,
                    name,
                })
            }
            Ok(MessageType::Rxattrwalk) => {
                let size = buf.get_u64_le();
                Ok(Message::Rxattrwalk { tag, size })
            }
            Ok(MessageType::Txattrcreate) => {
                let fid = buf.get_u32_le();
                let name = decode_string(buf)?;
                let attr_size = buf.get_u64_le();
                let flags = buf.get_u32_le();
                Ok(Message::Txattrcreate {
                    tag,
                    fid,
                    name,
                    attr_size,
                    flags,
                })
            }
            Ok(MessageType::Rxattrcreate) => Ok(Message::Rxattrcreate { tag }),
            Ok(MessageType::Treaddir) => {
                let fid = buf.get_u32_le();
                let offset = buf.get_u64_le();
                let count = buf.get_u32_le();
                Ok(Message::Treaddir {
                    tag,
                    fid,
                    offset,
                    count,
                })
            }
            Ok(MessageType::Rreaddir) => {
                let count = buf.get_u32_le() as usize;
                if buf.len() < count {
                    return Err(Error::BufferTooShort);
                }

                let mut entries_buf = buf.split_to(count);
                let mut data = Vec::new();

                while !entries_buf.is_empty() {
                    if let Ok(entry) = decode_dirent(&mut entries_buf) {
                        data.push(entry);
                    } else {
                        return Err(Error::InvalidFormat);
                    }
                }

                Ok(Message::Rreaddir { tag, data })
            }
            Ok(MessageType::Tfsync) => {
                let fid = buf.get_u32_le();
                Ok(Message::Tfsync { tag, fid })
            }
            Ok(MessageType::Rfsync) => Ok(Message::Rfsync { tag }),
            Ok(MessageType::Tlock) => {
                let fid = buf.get_u32_le();
                let lock = decode_lock(buf)?;
                Ok(Message::Tlock { tag, fid, lock })
            }
            Ok(MessageType::Rlock) => {
                let status = buf.get_u8();
                Ok(Message::Rlock { tag, status })
            }
            Ok(MessageType::Tgetlock) => {
                let fid = buf.get_u32_le();
                let lock = decode_lock(buf)?;
                Ok(Message::Tgetlock { tag, fid, lock })
            }
            Ok(MessageType::Rgetlock) => {
                let lock = decode_lock(buf)?;
                Ok(Message::Rgetlock { tag, lock })
            }
            Ok(MessageType::Tlink) => {
                let dfid = buf.get_u32_le();
                let fid = buf.get_u32_le();
                let name = decode_string(buf)?;
                Ok(Message::Tlink {
                    tag,
                    dfid,
                    fid,
                    name,
                })
            }
            Ok(MessageType::Rlink) => Ok(Message::Rlink { tag }),
            Ok(MessageType::Tmkdir) => {
                let dfid = buf.get_u32_le();
                let name = decode_string(buf)?;
                let mode = buf.get_u32_le();
                let gid = buf.get_u32_le();
                Ok(Message::Tmkdir {
                    tag,
                    dfid,
                    name,
                    mode,
                    gid,
                })
            }
            Ok(MessageType::Rmkdir) => {
                let qid = decode_qid(buf)?;
                Ok(Message::Rmkdir { tag, qid })
            }
            Ok(MessageType::Trenameat) => {
                let olddirfid = buf.get_u32_le();
                let oldname = decode_string(buf)?;
                let newdirfid = buf.get_u32_le();
                let newname = decode_string(buf)?;
                Ok(Message::Trenameat {
                    tag,
                    olddirfid,
                    oldname,
                    newdirfid,
                    newname,
                })
            }
            Ok(MessageType::Rrenameat) => Ok(Message::Rrenameat { tag }),
            Ok(MessageType::Tunlinkat) => {
                let dirfid = buf.get_u32_le();
                let name = decode_string(buf)?;
                let flags = buf.get_u32_le();
                Ok(Message::Tunlinkat {
                    tag,
                    dirfid,
                    name,
                    flags,
                })
            }
            Ok(MessageType::Runlinkat) => Ok(Message::Runlinkat { tag }),
            Ok(MessageType::Tstatfs) => {
                let fid = buf.get_u32_le();
                Ok(Message::Tstatfs { tag, fid })
            }
            Ok(MessageType::Rstatfs) => {
                let statfs = decode_statfs(buf)?;
                Ok(Message::Rstatfs { tag, statfs })
            }
            #[allow(deprecated)]
            Ok(MessageType::Terror) => Err(Error::InvalidMessageType(MessageType::Terror as u8)),
            Ok(MessageType::Tlerror) => Err(Error::InvalidMessageType(MessageType::Tlerror as u8)),
            Err(e) => Err(e),
        }
    }
}

fn encode_string(buf: &mut BytesMut, s: &str) {
    let bytes = s.as_bytes();
    buf.put_u16_le(bytes.len() as u16);
    buf.put_slice(bytes);
}

fn decode_string(buf: &mut BytesMut) -> Result<String> {
    if buf.len() < 2 {
        return Err(Error::BufferTooShort);
    }

    let len = buf.get_u16_le() as usize;
    if buf.len() < len {
        return Err(Error::BufferTooShort);
    }

    let bytes = buf.split_to(len);
    String::from_utf8(bytes.to_vec()).map_err(|_| Error::InvalidUtf8)
}

fn encode_qid(buf: &mut BytesMut, qid: &Qid) {
    buf.put_u8(qid.qtype);
    buf.put_u32_le(qid.version);
    buf.put_u64_le(qid.path);
}

fn decode_qid(buf: &mut BytesMut) -> Result<Qid> {
    if buf.len() < 13 {
        // 1 + 4 + 8 bytes
        return Err(Error::BufferTooShort);
    }

    let qtype = buf.get_u8();
    let version = buf.get_u32_le();
    let path = buf.get_u64_le();

    Ok(Qid {
        qtype,
        version,
        path,
    })
}

fn encode_attr(buf: &mut BytesMut, attr: &Attr) {
    buf.put_u32_le(attr.mode);
    buf.put_u32_le(attr.uid);
    buf.put_u32_le(attr.gid);
    buf.put_u64_le(attr.nlink);
    buf.put_u64_le(attr.rdev);
    buf.put_u64_le(attr.size);
    buf.put_u64_le(attr.blocks);
    buf.put_u64_le(attr.atime_sec);
    buf.put_u64_le(attr.atime_nsec);
    buf.put_u64_le(attr.mtime_sec);
    buf.put_u64_le(attr.mtime_nsec);
    buf.put_u64_le(attr.ctime_sec);
    buf.put_u64_le(attr.ctime_nsec);
    buf.put_u64_le(attr.btime_sec);
    buf.put_u64_le(attr.btime_nsec);
    buf.put_u64_le(attr.gen);
    buf.put_u64_le(attr.data_version);
}

fn decode_attr(buf: &mut BytesMut) -> Result<Attr> {
    if buf.len() < 136 {
        // 4*3 + 8*16 bytes
        return Err(Error::BufferTooShort);
    }

    let mode = buf.get_u32_le();
    let uid = buf.get_u32_le();
    let gid = buf.get_u32_le();
    let nlink = buf.get_u64_le();
    let rdev = buf.get_u64_le();
    let size = buf.get_u64_le();
    let blocks = buf.get_u64_le();
    let atime_sec = buf.get_u64_le();
    let atime_nsec = buf.get_u64_le();
    let mtime_sec = buf.get_u64_le();
    let mtime_nsec = buf.get_u64_le();
    let ctime_sec = buf.get_u64_le();
    let ctime_nsec = buf.get_u64_le();
    let btime_sec = buf.get_u64_le();
    let btime_nsec = buf.get_u64_le();
    let gen = buf.get_u64_le();
    let data_version = buf.get_u64_le();

    Ok(Attr {
        valid: 0, // This is set from the message's valid field
        mode,
        uid,
        gid,
        nlink,
        rdev,
        size,
        blocks,
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
    })
}

fn encode_dirent(buf: &mut BytesMut, dirent: &Dirent) {
    encode_qid(buf, &dirent.qid);
    buf.put_u64_le(dirent.offset);
    buf.put_u8(dirent.typ);
    encode_string(buf, &dirent.name);
}

fn decode_dirent(buf: &mut BytesMut) -> Result<Dirent> {
    if buf.len() < 13 + 8 + 1 {
        // qid + offset + type
        return Err(Error::BufferTooShort);
    }

    let qid = decode_qid(buf)?;
    let offset = buf.get_u64_le();
    let typ = buf.get_u8();
    let name = decode_string(buf)?;

    Ok(Dirent {
        qid,
        offset,
        typ,
        name,
    })
}

fn encode_lock(buf: &mut BytesMut, lock: &Lock) {
    buf.put_u8(lock.r#type);
    buf.put_u32_le(lock.flags);
    buf.put_u64_le(lock.start);
    buf.put_u64_le(lock.length);
    buf.put_u32_le(lock.proc_id);
    encode_string(buf, &lock.client_id);
}

fn decode_lock(buf: &mut BytesMut) -> Result<Lock> {
    if buf.len() < 1 + 4 + 8 + 8 + 4 {
        // min size without client_id
        return Err(Error::BufferTooShort);
    }

    let r#type = buf.get_u8();
    let flags = buf.get_u32_le();
    let start = buf.get_u64_le();
    let length = buf.get_u64_le();
    let proc_id = buf.get_u32_le();
    let client_id = decode_string(buf)?;

    Ok(Lock {
        r#type,
        flags,
        start,
        length,
        proc_id,
        client_id,
    })
}

fn encode_statfs(buf: &mut BytesMut, statfs: &StatFs) {
    buf.put_u32_le(statfs.r#type);
    buf.put_u32_le(statfs.bsize);
    buf.put_u64_le(statfs.blocks);
    buf.put_u64_le(statfs.bfree);
    buf.put_u64_le(statfs.bavail);
    buf.put_u64_le(statfs.files);
    buf.put_u64_le(statfs.ffree);
    buf.put_u64_le(statfs.fsid);
    buf.put_u32_le(statfs.namelen);
}

fn decode_statfs(buf: &mut BytesMut) -> Result<StatFs> {
    if buf.len() < 8 + 48 + 4 {
        // 2 u32s + 6 u64s + 1 u32
        return Err(Error::BufferTooShort);
    }

    let r#type = buf.get_u32_le();
    let bsize = buf.get_u32_le();
    let blocks = buf.get_u64_le();
    let bfree = buf.get_u64_le();
    let bavail = buf.get_u64_le();
    let files = buf.get_u64_le();
    let ffree = buf.get_u64_le();
    let fsid = buf.get_u64_le();
    let namelen = buf.get_u32_le();

    Ok(StatFs {
        r#type,
        bsize,
        blocks,
        bfree,
        bavail,
        files,
        ffree,
        fsid,
        namelen,
    })
}

fn encode_stat(buf: &mut BytesMut, stat: &Stat) {
    buf.put_u16_le(stat.qtype);
    buf.put_u32_le(stat.dev);
    encode_qid(buf, &stat.qid);
    buf.put_u32_le(stat.mode);
    buf.put_u32_le(stat.atime);
    buf.put_u32_le(stat.mtime);
    buf.put_u64_le(stat.length);
    encode_string(buf, &stat.name);
    encode_string(buf, &stat.uid);
    encode_string(buf, &stat.gid);
    encode_string(buf, &stat.muid);
}

fn decode_stat(buf: &mut BytesMut) -> Result<Stat> {
    if buf.len() < 2 + 4 + 13 + 4 + 4 + 4 + 8 {
        // minimum size without strings
        return Err(Error::BufferTooShort);
    }

    let qtype = buf.get_u16_le();
    let dev = buf.get_u32_le();
    let qid = decode_qid(buf)?;
    let mode = buf.get_u32_le();
    let atime = buf.get_u32_le();
    let mtime = buf.get_u32_le();
    let length = buf.get_u64_le();
    let name = decode_string(buf)?;
    let uid = decode_string(buf)?;
    let gid = decode_string(buf)?;
    let muid = decode_string(buf)?;

    Ok(Stat {
        qtype,
        dev,
        qid,
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

impl TryFrom<u8> for MessageType {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            // 9P2000.L specific message types
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

            // Classic 9P message types
            98 => Ok(MessageType::Topenfd),
            99 => Ok(MessageType::Ropenfd),
            100 => Ok(MessageType::Tversion),
            101 => Ok(MessageType::Rversion),
            102 => Ok(MessageType::Tauth),
            103 => Ok(MessageType::Rauth),
            104 => Ok(MessageType::Tattach),
            105 => Ok(MessageType::Rattach),
            #[allow(deprecated)]
            106 => Ok(MessageType::Terror),
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
}

impl Message {
    pub fn get_tag(&self) -> u16 {
        match self {
            Message::Tversion { tag, .. }
            | Message::Rversion { tag, .. }
            | Message::Tauth { tag, .. }
            | Message::Rauth { tag, .. }
            | Message::Tattach { tag, .. }
            | Message::Rattach { tag, .. }
            | Message::Rerror { tag, .. }
            | Message::Rlerror { tag, .. }
            | Message::Tflush { tag, .. }
            | Message::Rflush { tag, .. }
            | Message::Twalk { tag, .. }
            | Message::Rwalk { tag, .. }
            | Message::Topen { tag, .. }
            | Message::Ropen { tag, .. }
            | Message::Tcreate { tag, .. }
            | Message::Rcreate { tag, .. }
            | Message::Tread { tag, .. }
            | Message::Rread { tag, .. }
            | Message::Twrite { tag, .. }
            | Message::Rwrite { tag, .. }
            | Message::Tclunk { tag, .. }
            | Message::Rclunk { tag, .. }
            | Message::Tremove { tag, .. }
            | Message::Rremove { tag, .. }
            | Message::Tstat { tag, .. }
            | Message::Rstat { tag, .. }
            | Message::Twstat { tag, .. }
            | Message::Rwstat { tag, .. }
            | Message::Topenfd { tag, .. }
            | Message::Ropenfd { tag, .. }
            // Added 9P2000.L specific message types
            | Message::Tlopen { tag, .. }
            | Message::Rlopen { tag, .. }
            | Message::Tlcreate { tag, .. }
            | Message::Rlcreate { tag, .. }
            | Message::Tsymlink { tag, .. }
            | Message::Rsymlink { tag, .. }
            | Message::Tmknod { tag, .. }
            | Message::Rmknod { tag, .. }
            | Message::Trename { tag, .. }
            | Message::Rrename { tag, .. }
            | Message::Treadlink { tag, .. }
            | Message::Rreadlink { tag, .. }
            | Message::Tgetattr { tag, .. }
            | Message::Rgetattr { tag, .. }
            | Message::Tsetattr { tag, .. }
            | Message::Rsetattr { tag, .. }
            | Message::Txattrwalk { tag, .. }
            | Message::Rxattrwalk { tag, .. }
            | Message::Txattrcreate { tag, .. }
            | Message::Rxattrcreate { tag, .. }
            | Message::Treaddir { tag, .. }
            | Message::Rreaddir { tag, .. }
            | Message::Tfsync { tag, .. }
            | Message::Rfsync { tag, .. }
            | Message::Tlock { tag, .. }
            | Message::Rlock { tag, .. }
            | Message::Tgetlock { tag, .. }
            | Message::Rgetlock { tag, .. }
            | Message::Tlink { tag, .. }
            | Message::Rlink { tag, .. }
            | Message::Tmkdir { tag, .. }
            | Message::Rmkdir { tag, .. }
            | Message::Trenameat { tag, .. }
            | Message::Rrenameat { tag, .. }
            | Message::Tunlinkat { tag, .. }
            | Message::Runlinkat { tag, .. }
            | Message::Tstatfs { tag, .. }
            | Message::Rstatfs { tag, .. } => *tag,
        }
    }
}
