use futures::{SinkExt, StreamExt};
use std::sync::Arc;
use stowage_proto::{
    consts::EOPNOTSUPP, Message, MessageCodec, Rerror, Rversion, TaggedMessage, Tattach, Tauth,
    Tclunk, Tcreate, Tflush, Topen, Tread, Tremove, Tstat, Tversion, Twalk, Twrite, Twstat,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::{Framed, LengthDelimitedCodec};

pub trait MessageHandler {
    async fn version(&self, message: &Tversion) -> Message {
        Message::Rversion(Rversion {
            msize: message.msize.min(8192),
            version: match message.version.as_ref() {
                "9P2000" => message.version.to_string(),
                _ => "unknown".to_string(),
            },
        })
    }

    async fn auth(&self, msg: &Tauth) -> Message {
        Message::Rerror(Rerror {
            ename: "Operation not supported".to_string(),
        })
    }

    async fn attach(&self, msg: &Tattach) -> Message {
        Message::Rerror(Rerror {
            ename: "Operation not supported".to_string(),
        })
    }

    async fn flush(&self, msg: &Tflush) -> Message {
        Message::Rerror(Rerror {
            ename: "Operation not supported".to_string(),
        })
    }

    async fn walk(&self, msg: &Twalk) -> Message {
        Message::Rerror(Rerror {
            ename: "Operation not supported".to_string(),
        })
    }

    async fn open(&self, msg: &Topen) -> Message {
        Message::Rerror(Rerror {
            ename: "Operation not supported".to_string(),
        })
    }

    async fn create(&self, msg: &Tcreate) -> Message {
        Message::Rerror(Rerror {
            ename: "Operation not supported".to_string(),
        })
    }

    async fn read(&self, msg: &Tread) -> Message {
        Message::Rerror(Rerror {
            ename: "Operation not supported".to_string(),
        })
    }

    async fn write(&self, msg: &Twrite) -> Message {
        Message::Rerror(Rerror {
            ename: "Operation not supported".to_string(),
        })
    }

    async fn clunk(&self, msg: &Tclunk) -> Message {
        Message::Rerror(Rerror {
            ename: "Operation not supported".to_string(),
        })
    }

    async fn remove(&self, msg: &Tremove) -> Message {
        Message::Rerror(Rerror {
            ename: "Operation not supported".to_string(),
        })
    }

    async fn stat(&self, msg: &Tstat) -> Message {
        Message::Rerror(Rerror {
            ename: "Operation not supported".to_string(),
        })
    }

    async fn wstat(&self, msg: &Twstat) -> Message {
        Message::Rerror(Rerror {
            ename: "Operation not supported".to_string(),
        })
    }

    /// Dispatcher method that routes messages to specific handlers
    async fn handle_message(&self, message: &Message) -> Message {
        println!("message: {:?}", message);
        match message {
            Message::Tversion(msg) => self.version(msg).await,
            Message::Tauth(msg) => self.auth(msg).await,
            Message::Tattach(msg) => self.attach(msg).await,
            Message::Tflush(msg) => self.flush(msg).await,
            Message::Twalk(msg) => self.walk(msg).await,
            Message::Topen(msg) => self.open(msg).await,
            Message::Tcreate(msg) => self.create(msg).await,
            Message::Tread(msg) => self.read(msg).await,
            Message::Twrite(msg) => self.write(msg).await,
            Message::Tclunk(msg) => self.clunk(msg).await,
            Message::Tremove(msg) => self.remove(msg).await,
            Message::Tstat(msg) => self.stat(msg).await,
            Message::Twstat(msg) => self.wstat(msg).await,

            // reply messages should not be received by the handler
            _ => Message::Rerror(Rerror {
                ename: "Unexpected message type".to_string(),
            }),
        }
    }
}

pub struct Plan9<T, F>
where
    T: AsyncRead + AsyncWrite + Unpin,
    F: MessageHandler,
{
    connection: Framed<T, MessageCodec>,
    handler: Arc<F>,
}

impl<T, H> Plan9<T, H>
where
    T: AsyncRead + AsyncWrite + Unpin,
    H: MessageHandler,
{
    pub fn new(connection: T, handler: Arc<H>) -> Self {
        let codec = MessageCodec::new();
        let connection = Framed::new(connection, codec);

        Self {
            connection,
            handler,
        }
    }

    pub async fn run(mut self) -> stowage_proto::error::Result<()> {
        while let Some(message_result) = self.connection.next().await {
            match message_result {
                Ok(request) => {
                    let response = self.handler.handle_message(&request.message).await;
                    let tagged = response.to_tagged(request.tag);
                    self.connection.send(tagged).await?;
                }
                Err(e) => {
                    return Err(e);
                }
            }
        }

        Ok(())
    }
}
