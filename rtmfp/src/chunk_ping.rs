use crate::encode::Encode;
use crate::session_key_components::Decode;
use crate::ChunkContent;
use crate::StaticEncode;
use cookie_factory::{GenResult, WriteContext};
use nom::IResult;
use std::io::Write;

#[derive(Debug, Clone)]
pub struct PingBody {
    pub message: Vec<u8>,
}

impl<T: Write> Encode<T> for PingBody {
    fn encode(&self, w: WriteContext<T>) -> GenResult<T> {
        self.message.encode(w)
    }
}
static_encode!(PingBody);
impl Decode for PingBody {
    fn decode(i: &[u8]) -> IResult<&[u8], Self> {
        Ok((
            &[],
            Self {
                message: i.to_vec(),
            },
        ))
    }
}
impl From<PingBody> for ChunkContent {
    fn from(s: PingBody) -> Self {
        ChunkContent::Ping(s)
    }
}
