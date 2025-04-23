pub const QID_TYPE_DIR: u8 = 0x80;
pub const QID_TYPE_SYMLINK: u8 = 0x02;
pub const QID_TYPE_FILE: u8 = 0x00;

pub const P9_NOFID: u32 = 0xFFFF_FFFF;

pub const O_RDONLY: u32 = 0;
pub const O_WRONLY: u32 = 1;
pub const O_RDWR: u32 = 2;
pub const O_NONBLOCK: u32 = 0x800;
pub const O_APPEND: u32 = 0x400;
pub const O_CREAT: u32 = 0x40;
pub const O_TRUNC: u32 = 0x200;
pub const O_EXCL: u32 = 0x80;

pub const P9_GETATTR_BASIC: u64 = 0x0000_07ff;
pub const P9_GETATTR_ALL: u64 = 0x0000_3fff;

pub const P9_SETATTR_MODE: u32 = 0x0000_0001;
pub const P9_SETATTR_UID: u32 = 0x0000_0002;
pub const P9_SETATTR_GID: u32 = 0x0000_0004;
pub const P9_SETATTR_SIZE: u32 = 0x0000_0008;
pub const P9_SETATTR_ATIME: u32 = 0x0000_0010;
pub const P9_SETATTR_MTIME: u32 = 0x0000_0020;
pub const P9_SETATTR_ATIME_SET: u32 = 0x0000_0080;
pub const P9_SETATTR_MTIME_SET: u32 = 0x0000_0100;

pub const EOPNOTSUPP: u8 = 2;
pub const ENOTDIR: u8 = 20;
pub const EIO: u8 = 5;
