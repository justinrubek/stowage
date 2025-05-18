use futures::{SinkExt, StreamExt};
use std::sync::Arc;
use stowage_proto::{
    consts::EOPNOTSUPP, Codec, Message, Rlerror, Rversion, Tattach, Tauth, Tclunk, Tflush, Tfsync,
    Tgetattr, Tgetlock, Tlcreate, Tlink, Tlock, Tlopen, Tmkdir, Tmknod, Tread, Treaddir, Treadlink,
    Tremove, Trename, Trenameat, Tsetattr, Tstat, Tstatfs, Tsymlink, Tunlinkat, Tversion, Twalk,
    Twrite, Twstat, Txattrcreate, Txattrwalk,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::{Framed, LengthDelimitedCodec};

pub trait MessageHandler {
    // 9P Classic messages
    async fn version(&self, message: Tversion) -> Message {
        Message::Rversion(Rversion {
            tag: message.tag,
            msize: message.msize.min(8192),
            version: match message.version.as_ref() {
                "9P2000.L" => message.version.to_string(),
                _ => "unknown".to_string(),
            },
        })
    }

    async fn auth(&self, msg: Tauth) -> Message {
        Message::Rlerror(Rlerror {
            tag: msg.tag,
            ecode: EOPNOTSUPP as u32,
        })
    }

    async fn attach(&self, msg: Tattach) -> Message {
        Message::Rlerror(Rlerror {
            tag: msg.tag,
            ecode: EOPNOTSUPP as u32,
        })
    }

    async fn flush(&self, msg: Tflush) -> Message {
        Message::Rlerror(Rlerror {
            tag: msg.tag,
            ecode: EOPNOTSUPP as u32,
        })
    }

    async fn walk(&self, msg: Twalk) -> Message {
        Message::Rlerror(Rlerror {
            tag: msg.tag,
            ecode: EOPNOTSUPP as u32,
        })
    }

    async fn open(&self, msg: Tlopen) -> Message {
        Message::Rlerror(Rlerror {
            tag: msg.tag,
            ecode: EOPNOTSUPP as u32,
        })
    }

    async fn read(&self, msg: Tread) -> Message {
        Message::Rlerror(Rlerror {
            tag: msg.tag,
            ecode: EOPNOTSUPP as u32,
        })
    }

    async fn write(&self, msg: Twrite) -> Message {
        Message::Rlerror(Rlerror {
            tag: msg.tag,
            ecode: EOPNOTSUPP as u32,
        })
    }

    async fn clunk(&self, msg: Tclunk) -> Message {
        Message::Rlerror(Rlerror {
            tag: msg.tag,
            ecode: EOPNOTSUPP as u32,
        })
    }

    async fn remove(&self, msg: Tremove) -> Message {
        Message::Rlerror(Rlerror {
            tag: msg.tag,
            ecode: EOPNOTSUPP as u32,
        })
    }

    async fn stat(&self, msg: Tstat) -> Message {
        Message::Rlerror(Rlerror {
            tag: msg.tag,
            ecode: EOPNOTSUPP as u32,
        })
    }

    async fn wstat(&self, msg: Twstat) -> Message {
        Message::Rlerror(Rlerror {
            tag: msg.tag,
            ecode: EOPNOTSUPP as u32,
        })
    }

    // 9P2000.L specific messages
    async fn lopen(&self, msg: Tlopen) -> Message {
        Message::Rlerror(Rlerror {
            tag: msg.tag,
            ecode: EOPNOTSUPP as u32,
        })
    }

    async fn lcreate(&self, msg: Tlcreate) -> Message {
        Message::Rlerror(Rlerror {
            tag: msg.tag,
            ecode: EOPNOTSUPP as u32,
        })
    }

    async fn symlink(&self, msg: Tsymlink) -> Message {
        Message::Rlerror(Rlerror {
            tag: msg.tag,
            ecode: EOPNOTSUPP as u32,
        })
    }

    async fn mknod(&self, msg: Tmknod) -> Message {
        Message::Rlerror(Rlerror {
            tag: msg.tag,
            ecode: EOPNOTSUPP as u32,
        })
    }

    async fn rename(&self, msg: Trename) -> Message {
        Message::Rlerror(Rlerror {
            tag: msg.tag,
            ecode: EOPNOTSUPP as u32,
        })
    }

    async fn readlink(&self, msg: Treadlink) -> Message {
        Message::Rlerror(Rlerror {
            tag: msg.tag,
            ecode: EOPNOTSUPP as u32,
        })
    }

    async fn getattr(&self, msg: Tgetattr) -> Message {
        Message::Rlerror(Rlerror {
            tag: msg.tag,
            ecode: EOPNOTSUPP as u32,
        })
    }

    async fn setattr(&self, msg: Tsetattr) -> Message {
        Message::Rlerror(Rlerror {
            tag: msg.tag,
            ecode: EOPNOTSUPP as u32,
        })
    }

    async fn xattrwalk(&self, msg: Txattrwalk) -> Message {
        Message::Rlerror(Rlerror {
            tag: msg.tag,
            ecode: EOPNOTSUPP as u32,
        })
    }

    async fn xattrcreate(&self, msg: Txattrcreate) -> Message {
        Message::Rlerror(Rlerror {
            tag: msg.tag,
            ecode: EOPNOTSUPP as u32,
        })
    }

    async fn readdir(&self, msg: Treaddir) -> Message {
        Message::Rlerror(Rlerror {
            tag: msg.tag,
            ecode: EOPNOTSUPP as u32,
        })
    }

    async fn fsync(&self, msg: Tfsync) -> Message {
        Message::Rlerror(Rlerror {
            tag: msg.tag,
            ecode: EOPNOTSUPP as u32,
        })
    }

    async fn lock(&self, msg: Tlock) -> Message {
        Message::Rlerror(Rlerror {
            tag: msg.tag,
            ecode: EOPNOTSUPP as u32,
        })
    }

    async fn getlock(&self, msg: Tgetlock) -> Message {
        Message::Rlerror(Rlerror {
            tag: msg.tag,
            ecode: EOPNOTSUPP as u32,
        })
    }

    async fn link(&self, msg: Tlink) -> Message {
        Message::Rlerror(Rlerror {
            tag: msg.tag,
            ecode: EOPNOTSUPP as u32,
        })
    }

    async fn mkdir(&self, msg: Tmkdir) -> Message {
        Message::Rlerror(Rlerror {
            tag: msg.tag,
            ecode: EOPNOTSUPP as u32,
        })
    }

    async fn renameat(&self, msg: Trenameat) -> Message {
        Message::Rlerror(Rlerror {
            tag: msg.tag,
            ecode: EOPNOTSUPP as u32,
        })
    }

    async fn unlinkat(&self, msg: Tunlinkat) -> Message {
        Message::Rlerror(Rlerror {
            tag: msg.tag,
            ecode: EOPNOTSUPP as u32,
        })
    }

    async fn statfs(&self, msg: Tstatfs) -> Message {
        Message::Rlerror(Rlerror {
            tag: msg.tag,
            ecode: EOPNOTSUPP as u32,
        })
    }

    // Dispatcher method that routes messages to specific handlers
    async fn handle_message(&self, message: Message) -> Message {
        println!("message: {:?}", message);
        match message {
            Message::Tversion(msg) => self.version(msg).await,
            Message::Tauth(msg) => self.auth(msg).await,
            Message::Tattach(msg) => self.attach(msg).await,
            Message::Tflush(msg) => self.flush(msg).await,
            Message::Twalk(msg) => self.walk(msg).await,
            Message::Tread(msg) => self.read(msg).await,
            Message::Twrite(msg) => self.write(msg).await,
            Message::Tclunk(msg) => self.clunk(msg).await,
            Message::Tremove(msg) => self.remove(msg).await,
            Message::Tstat(msg) => self.stat(msg).await,
            Message::Twstat(msg) => self.wstat(msg).await,

            // 9P2000.L messages
            Message::Tlopen(msg) => self.lopen(msg).await,
            Message::Tlcreate(msg) => self.lcreate(msg).await,
            Message::Tsymlink(msg) => self.symlink(msg).await,
            Message::Tmknod(msg) => self.mknod(msg).await,
            Message::Trename(msg) => self.rename(msg).await,
            Message::Treadlink(msg) => self.readlink(msg).await,
            Message::Tgetattr(msg) => self.getattr(msg).await,
            Message::Tsetattr(msg) => self.setattr(msg).await,
            Message::Txattrwalk(msg) => self.xattrwalk(msg).await,
            Message::Txattrcreate(msg) => self.xattrcreate(msg).await,
            Message::Treaddir(msg) => self.readdir(msg).await,
            Message::Tfsync(msg) => self.fsync(msg).await,
            Message::Tlock(msg) => self.lock(msg).await,
            Message::Tgetlock(msg) => self.getlock(msg).await,
            Message::Tlink(msg) => self.link(msg).await,
            Message::Tmkdir(msg) => self.mkdir(msg).await,
            Message::Trenameat(msg) => self.renameat(msg).await,
            Message::Tunlinkat(msg) => self.unlinkat(msg).await,
            Message::Tstatfs(msg) => self.statfs(msg).await,

            // Reply messages should not be received by the handler
            _ => Message::Rlerror(Rlerror {
                tag: 0, // No tag available for reply messages
                ecode: EOPNOTSUPP as u32,
            }),
        }
    }
}

pub struct Plan9<T, F>
where
    T: AsyncRead + AsyncWrite + Unpin,
    F: MessageHandler,
{
    connection: Framed<T, Codec>,
    handler: Arc<F>,
}

impl<T, H> Plan9<T, H>
where
    T: AsyncRead + AsyncWrite + Unpin,
    H: MessageHandler,
{
    pub fn new(connection: T, handler: Arc<H>) -> Self {
        let ldc = LengthDelimitedCodec::builder()
            .length_field_offset(0)
            .length_field_length(4)
            .length_adjustment(-4)
            .little_endian()
            .new_framed(connection)
            .map_codec(|_| Codec);

        Self {
            connection: ldc,
            handler,
        }
    }

    pub async fn run(mut self) -> stowage_proto::error::Result<()> {
        while let Some(message_result) = self.connection.next().await {
            match message_result {
                Ok(request) => {
                    let response = self.handler.handle_message(request).await;
                    self.connection.send(response).await?;
                }
                Err(e) => {
                    return Err(e);
                }
            }
        }

        Ok(())
    }
}
