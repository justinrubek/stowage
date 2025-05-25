use futures::{SinkExt, StreamExt};
use std::sync::Arc;
use stowage_proto::{
    Message, MessageCodec, Rerror, Rversion, Tattach, Tauth, Tclunk, Tcreate, Tflush, Topen, Tread,
    Tremove, Tstat, Tversion, Twalk, Twrite, Twstat,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::Framed;

pub trait MessageHandler {
    fn version(&self, message: &Tversion) -> impl std::future::Future<Output = Message> {
        async {
            Message::Rversion(Rversion {
                msize: message.msize.min(8192),
                version: match message.version.as_ref() {
                    "9P2000" => message.version.to_string(),
                    _ => "unknown".to_string(),
                },
            })
        }
    }

    fn auth(&self, _msg: &Tauth) -> impl std::future::Future<Output = Message> {
        async {
            Message::Rerror(Rerror {
                ename: "Operation not supported".to_string(),
            })
        }
    }

    fn attach(&self, __msg: &Tattach) -> impl std::future::Future<Output = Message> {
        async {
            Message::Rerror(Rerror {
                ename: "Operation not supported".to_string(),
            })
        }
    }

    fn flush(&self, __msg: &Tflush) -> impl std::future::Future<Output = Message> {
        async {
            Message::Rerror(Rerror {
                ename: "Operation not supported".to_string(),
            })
        }
    }

    fn walk(&self, _msg: &Twalk) -> impl std::future::Future<Output = Message> {
        async {
            Message::Rerror(Rerror {
                ename: "Operation not supported".to_string(),
            })
        }
    }

    fn open(&self, _msg: &Topen) -> impl std::future::Future<Output = Message> {
        async {
            Message::Rerror(Rerror {
                ename: "Operation not supported".to_string(),
            })
        }
    }

    fn create(&self, _msg: &Tcreate) -> impl std::future::Future<Output = Message> {
        async {
            Message::Rerror(Rerror {
                ename: "Operation not supported".to_string(),
            })
        }
    }

    fn read(&self, _msg: &Tread) -> impl std::future::Future<Output = Message> {
        async {
            Message::Rerror(Rerror {
                ename: "Operation not supported".to_string(),
            })
        }
    }

    fn write(&self, _msg: &Twrite) -> impl std::future::Future<Output = Message> {
        async {
            Message::Rerror(Rerror {
                ename: "Operation not supported".to_string(),
            })
        }
    }

    fn clunk(&self, _msg: &Tclunk) -> impl std::future::Future<Output = Message> {
        async {
            Message::Rerror(Rerror {
                ename: "Operation not supported".to_string(),
            })
        }
    }

    fn remove(&self, _msg: &Tremove) -> impl std::future::Future<Output = Message> {
        async {
            Message::Rerror(Rerror {
                ename: "Operation not supported".to_string(),
            })
        }
    }

    fn stat(&self, _msg: &Tstat) -> impl std::future::Future<Output = Message> {
        async {
            Message::Rerror(Rerror {
                ename: "Operation not supported".to_string(),
            })
        }
    }

    fn wstat(&self, _msg: &Twstat) -> impl std::future::Future<Output = Message> {
        async {
            Message::Rerror(Rerror {
                ename: "Operation not supported".to_string(),
            })
        }
    }

    /// Dispatcher method that routes messages to specific handlers
    fn handle_message(&self, message: &Message) -> impl std::future::Future<Output = Message> {
        println!("message: {message:?}");
        async {
            let m = message.clone();
            match m {
                Message::Tversion(msg) => self.version(&msg).await,
                Message::Tauth(msg) => self.auth(&msg).await,
                Message::Tattach(msg) => self.attach(&msg).await,
                Message::Tflush(msg) => self.flush(&msg).await,
                Message::Twalk(msg) => self.walk(&msg).await,
                Message::Topen(msg) => self.open(&msg).await,
                Message::Tcreate(msg) => self.create(&msg).await,
                Message::Tread(msg) => self.read(&msg).await,
                Message::Twrite(msg) => self.write(&msg).await,
                Message::Tclunk(msg) => self.clunk(&msg).await,
                Message::Tremove(msg) => self.remove(&msg).await,
                Message::Tstat(msg) => self.stat(&msg).await,
                Message::Twstat(msg) => self.wstat(&msg).await,

                // reply messages should not be received by the handler
                _ => Message::Rerror(Rerror {
                    ename: "Unexpected message type".to_string(),
                }),
            }
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

    /// # Errors
    /// - failure sending a message to the server
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
