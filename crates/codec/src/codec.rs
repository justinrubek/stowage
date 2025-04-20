use crate::proto::{Message, ProtocolError};
use bytes::{Buf, BufMut, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

pub struct Plan9;

impl Decoder for Plan9 {
    type Item = Message;
    type Error = ProtocolError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
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

impl Encoder<Message> for Plan9 {
    type Error = ProtocolError;

    fn encode(&mut self, item: Message, dst: &mut BytesMut) -> Result<(), Self::Error> {
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
