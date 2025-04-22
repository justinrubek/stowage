use futures::{SinkExt, StreamExt};
use std::sync::Arc;
use stowage_proto::{Codec, Message};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::Framed;

pub trait MessageHandler {
    fn handle_message(&self, message: Message) -> impl std::future::Future<Output = Message>;
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
        Self {
            connection: Framed::new(connection, Codec),
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
