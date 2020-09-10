use crate::encode::Encode;
use crate::session_key_components::Decode;
use cookie_factory::{GenResult, WriteContext};
use nom::IResult;
use std::io::Write;
use crate::ChunkContent;

#[derive(Debug, Clone)]
pub struct PingReplyBody {
    pub message_echo: Vec<u8>,
}

impl<T: Write> Encode<T> for PingReplyBody {
    fn encode(&self, w: WriteContext<T>) -> GenResult<T> {
        self.message_echo.encode(w)
    }
}
impl Decode for PingReplyBody {
    fn decode(i: &[u8]) -> IResult<&[u8], Self> {
        Ok((
            &[],
            Self {
                message_echo: i.to_vec(),
            },
        ))
    }
}
impl From<PingReplyBody> for ChunkContent {
    fn from(s: PingReplyBody) -> Self {
        ChunkContent::PingReply(s)
    }
}
