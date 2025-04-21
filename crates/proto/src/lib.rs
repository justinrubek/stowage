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

        // encode the message
        item.encode(dst);

        // calculate and write the actual size
        let message_size = dst.len() - start_pos;
        let size_bytes = u32::try_from(message_size)?.to_le_bytes();
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

#[derive(Debug, Clone)]
pub struct Qid {
    pub qtype: u8,
    pub version: u32,
    pub path: u64,
}

#[derive(Debug, Clone)]
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
            Message::Tauth {
                tag,
                afid,
                uname,
                aname,
            } => {
                buf.put_u8(MessageType::Tauth as u8);
                buf.put_u16(*tag);
                buf.put_u32(*afid);
                encode_string(buf, uname);
                encode_string(buf, aname);
            }
            Message::Rauth { tag, aqid } => {
                buf.put_u8(MessageType::Rauth as u8);
                buf.put_u16(*tag);
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
                buf.put_u16(*tag);
                buf.put_u32(*fid);
                buf.put_u32(*afid);
                encode_string(buf, uname);
                encode_string(buf, aname);
            }
            Message::Rattach { tag, qid } => {
                buf.put_u8(MessageType::Rattach as u8);
                buf.put_u16(*tag);
                encode_qid(buf, qid);
            }
            Message::Rerror { tag, ename } => {
                buf.put_u8(MessageType::Rerror as u8);
                buf.put_u16(*tag);
                encode_string(buf, ename);
            }
            Message::Tflush { tag, oldtag } => {
                buf.put_u8(MessageType::Tflush as u8);
                buf.put_u16(*tag);
                buf.put_u16(*oldtag);
            }
            Message::Rflush { tag } => {
                buf.put_u8(MessageType::Rflush as u8);
                buf.put_u16(*tag);
            }
            Message::Twalk {
                tag,
                fid,
                newfid,
                wnames,
            } => {
                buf.put_u8(MessageType::Twalk as u8);
                buf.put_u16(*tag);
                buf.put_u32(*fid);
                buf.put_u32(*newfid);

                // Number of walk elements
                buf.put_u16(wnames.len() as u16);

                // Encode each name
                for name in wnames {
                    encode_string(buf, name);
                }
            }
            Message::Rwalk { tag, wqids } => {
                buf.put_u8(MessageType::Rwalk as u8);
                buf.put_u16(*tag);

                // Number of qids
                buf.put_u16(wqids.len() as u16);

                // Encode each qid
                for qid in wqids {
                    encode_qid(buf, qid);
                }
            }
            Message::Topen { tag, fid, mode } => {
                buf.put_u8(MessageType::Topen as u8);
                buf.put_u16(*tag);
                buf.put_u32(*fid);
                buf.put_u8(*mode);
            }
            Message::Ropen { tag, qid, iounit } => {
                buf.put_u8(MessageType::Ropen as u8);
                buf.put_u16(*tag);
                encode_qid(buf, qid);
                buf.put_u32(*iounit);
            }
            Message::Tcreate {
                tag,
                fid,
                name,
                perm,
                mode,
            } => {
                buf.put_u8(MessageType::Tcreate as u8);
                buf.put_u16(*tag);
                buf.put_u32(*fid);
                encode_string(buf, name);
                buf.put_u32(*perm);
                buf.put_u8(*mode);
            }
            Message::Rcreate { tag, qid, iounit } => {
                buf.put_u8(MessageType::Rcreate as u8);
                buf.put_u16(*tag);
                encode_qid(buf, qid);
                buf.put_u32(*iounit);
            }
            Message::Tread {
                tag,
                fid,
                offset,
                count,
            } => {
                buf.put_u8(MessageType::Tread as u8);
                buf.put_u16(*tag);
                buf.put_u32(*fid);
                buf.put_u64(*offset);
                buf.put_u32(*count);
            }
            Message::Rread { tag, data } => {
                buf.put_u8(MessageType::Rread as u8);
                buf.put_u16(*tag);
                buf.put_u32(data.len() as u32);
                buf.put_slice(data);
            }
            Message::Twrite {
                tag,
                fid,
                offset,
                data,
            } => {
                buf.put_u8(MessageType::Twrite as u8);
                buf.put_u16(*tag);
                buf.put_u32(*fid);
                buf.put_u64(*offset);
                buf.put_u32(data.len() as u32);
                buf.put_slice(data);
            }
            Message::Rwrite { tag, count } => {
                buf.put_u8(MessageType::Rwrite as u8);
                buf.put_u16(*tag);
                buf.put_u32(*count);
            }
            Message::Tclunk { tag, fid } => {
                buf.put_u8(MessageType::Tclunk as u8);
                buf.put_u16(*tag);
                buf.put_u32(*fid);
            }
            Message::Rclunk { tag } => {
                buf.put_u8(MessageType::Rclunk as u8);
                buf.put_u16(*tag);
            }
            Message::Tremove { tag, fid } => {
                buf.put_u8(MessageType::Tremove as u8);
                buf.put_u16(*tag);
                buf.put_u32(*fid);
            }
            Message::Rremove { tag } => {
                buf.put_u8(MessageType::Rremove as u8);
                buf.put_u16(*tag);
            }
            Message::Tstat { tag, fid } => {
                buf.put_u8(MessageType::Tstat as u8);
                buf.put_u16(*tag);
                buf.put_u32(*fid);
            }
            Message::Rstat { tag, stat } => {
                buf.put_u8(MessageType::Rstat as u8);
                buf.put_u16(*tag);

                // Reserve space for stat size
                let stat_start = buf.len();
                buf.put_u16(0);

                // Encode stat structure
                encode_stat(buf, stat);

                // Update size field
                let stat_size = buf.len() - stat_start - 2;
                let size_bytes = (stat_size as u16).to_le_bytes();
                buf[stat_start..stat_start + 2].copy_from_slice(&size_bytes);
            }
            Message::Twstat { tag, fid, stat } => {
                buf.put_u8(MessageType::Twstat as u8);
                buf.put_u16(*tag);
                buf.put_u32(*fid);

                // Reserve space for stat size
                let stat_start = buf.len();
                buf.put_u16(0);

                // Encode stat structure
                encode_stat(buf, stat);

                // Update size field
                let stat_size = buf.len() - stat_start - 2;
                let size_bytes = (stat_size as u16).to_le_bytes();
                buf[stat_start..stat_start + 2].copy_from_slice(&size_bytes);
            }
            Message::Rwstat { tag } => {
                buf.put_u8(MessageType::Rwstat as u8);
                buf.put_u16(*tag);
            }
            Message::Topenfd { tag, fid, mode } => {
                buf.put_u8(MessageType::Topenfd as u8);
                buf.put_u16(*tag);
                buf.put_u32(*fid);
                buf.put_u8(*mode);
            }
            Message::Ropenfd {
                tag,
                qid,
                iounit,
                fd,
            } => {
                buf.put_u8(MessageType::Ropenfd as u8);
                buf.put_u16(*tag);
                encode_qid(buf, qid);
                buf.put_u32(*iounit);
                buf.put_u32(*fd);
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
            Ok(MessageType::Rversion) => {
                let msize = buf.get_u32();
                let version = decode_string(buf)?;
                Ok(Message::Rversion {
                    tag,
                    msize,
                    version,
                })
            }
            Ok(MessageType::Tauth) => {
                let afid = buf.get_u32();
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
                let fid = buf.get_u32();
                let afid = buf.get_u32();
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
            Ok(MessageType::Tflush) => {
                let oldtag = buf.get_u16();
                Ok(Message::Tflush { tag, oldtag })
            }
            Ok(MessageType::Rflush) => Ok(Message::Rflush { tag }),
            Ok(MessageType::Twalk) => {
                let fid = buf.get_u32();
                let newfid = buf.get_u32();
                let nwname = buf.get_u16() as usize;

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
                let nwqid = buf.get_u16() as usize;

                let mut wqids = Vec::with_capacity(nwqid);
                for _ in 0..nwqid {
                    wqids.push(decode_qid(buf)?);
                }

                Ok(Message::Rwalk { tag, wqids })
            }
            Ok(MessageType::Topen) => {
                let fid = buf.get_u32();
                let mode = buf.get_u8();
                Ok(Message::Topen { tag, fid, mode })
            }
            Ok(MessageType::Ropen) => {
                let qid = decode_qid(buf)?;
                let iounit = buf.get_u32();
                Ok(Message::Ropen { tag, qid, iounit })
            }
            Ok(MessageType::Tcreate) => {
                let fid = buf.get_u32();
                let name = decode_string(buf)?;
                let perm = buf.get_u32();
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
                let iounit = buf.get_u32();
                Ok(Message::Rcreate { tag, qid, iounit })
            }
            Ok(MessageType::Tread) => {
                let fid = buf.get_u32();
                let offset = buf.get_u64();
                let count = buf.get_u32();
                Ok(Message::Tread {
                    tag,
                    fid,
                    offset,
                    count,
                })
            }
            Ok(MessageType::Rread) => {
                let count = buf.get_u32() as usize;
                if buf.len() < count {
                    return Err(Error::BufferTooShort);
                }

                let data = buf.split_to(count).to_vec();
                Ok(Message::Rread { tag, data })
            }
            Ok(MessageType::Twrite) => {
                let fid = buf.get_u32();
                let offset = buf.get_u64();
                let count = buf.get_u32() as usize;

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
                let count = buf.get_u32();
                Ok(Message::Rwrite { tag, count })
            }
            Ok(MessageType::Tclunk) => {
                let fid = buf.get_u32();
                Ok(Message::Tclunk { tag, fid })
            }
            Ok(MessageType::Rclunk) => Ok(Message::Rclunk { tag }),
            Ok(MessageType::Tremove) => {
                let fid = buf.get_u32();
                Ok(Message::Tremove { tag, fid })
            }
            Ok(MessageType::Rremove) => Ok(Message::Rremove { tag }),
            Ok(MessageType::Tstat) => {
                let fid = buf.get_u32();
                Ok(Message::Tstat { tag, fid })
            }
            Ok(MessageType::Rstat) => {
                // Skip the stat size field since we decode the entire structure
                let _stat_size = buf.get_u16();
                let stat = decode_stat(buf)?;
                Ok(Message::Rstat { tag, stat })
            }
            Ok(MessageType::Twstat) => {
                let fid = buf.get_u32();
                // Skip the stat size field
                let _stat_size = buf.get_u16();
                let stat = decode_stat(buf)?;
                Ok(Message::Twstat { tag, fid, stat })
            }
            Ok(MessageType::Rwstat) => Ok(Message::Rwstat { tag }),
            Ok(MessageType::Topenfd) => {
                let fid = buf.get_u32();
                let mode = buf.get_u8();
                Ok(Message::Topenfd { tag, fid, mode })
            }
            Ok(MessageType::Ropenfd) => {
                let qid = decode_qid(buf)?;
                let iounit = buf.get_u32();
                let fd = buf.get_u32();
                Ok(Message::Ropenfd {
                    tag,
                    qid,
                    iounit,
                    fd,
                })
            }
            #[allow(deprecated)]
            Ok(MessageType::Terror) => Err(Error::InvalidMessageType(MessageType::Terror as u8)),
            Err(e) => Err(e),
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
    String::from_utf8(bytes.to_vec()).map_err(|_| Error::InvalidUtf8)
}

fn encode_qid(buf: &mut BytesMut, qid: &Qid) {
    buf.put_u8(qid.qtype);
    buf.put_u32(qid.version);
    buf.put_u64(qid.path);
}

fn decode_qid(buf: &mut BytesMut) -> Result<Qid> {
    if buf.len() < 13 {
        // 1 + 4 + 8 bytes
        return Err(Error::BufferTooShort);
    }

    let qtype = buf.get_u8();
    let version = buf.get_u32();
    let path = buf.get_u64();

    Ok(Qid {
        qtype,
        version,
        path,
    })
}

fn encode_stat(buf: &mut BytesMut, stat: &Stat) {
    buf.put_u16(stat.qtype);
    buf.put_u32(stat.dev);
    encode_qid(buf, &stat.qid);
    buf.put_u32(stat.mode);
    buf.put_u32(stat.atime);
    buf.put_u32(stat.mtime);
    buf.put_u64(stat.length);
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

    let qtype = buf.get_u16();
    let dev = buf.get_u32();
    let qid = decode_qid(buf)?;
    let mode = buf.get_u32();
    let atime = buf.get_u32();
    let mtime = buf.get_u32();
    let length = buf.get_u64();
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
            98 => Ok(MessageType::Topenfd),
            99 => Ok(MessageType::Ropenfd),
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
            | Message::Ropenfd { tag, .. } => *tag,
        }
    }
}
