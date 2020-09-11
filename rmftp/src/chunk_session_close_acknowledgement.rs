use crate::encode::Encode;
use crate::session_key_components::Decode;
use crate::ChunkContent;
use crate::StaticEncode;
use cookie_factory::{GenResult, WriteContext};
use nom::IResult;
use std::io::Write;

#[derive(Debug, Clone, Default)]
pub struct SessionCloseAcknowledgementBody;

impl<T: Write> Encode<T> for SessionCloseAcknowledgementBody {
    fn encode(&self, w: WriteContext<T>) -> GenResult<T> {
        Ok(w)
    }
}
static_encode!(SessionCloseAcknowledgementBody);
impl Decode for SessionCloseAcknowledgementBody {
    fn decode(i: &[u8]) -> IResult<&[u8], Self> {
        Ok((i, Self::default()))
    }
}
impl From<SessionCloseAcknowledgementBody> for ChunkContent {
    fn from(s: SessionCloseAcknowledgementBody) -> Self {
        ChunkContent::SessionCloseAcknowledgement(s)
    }
}
