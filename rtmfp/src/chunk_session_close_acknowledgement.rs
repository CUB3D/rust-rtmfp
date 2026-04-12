use crate::session_key_components::Decode;
use crate::ChunkContent;
use nom::IResult;
use parse::{GenerateBytes, SliceWriter};

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct SessionCloseAcknowledgementBody;

impl GenerateBytes for SessionCloseAcknowledgementBody {
    fn generate<'b>(&'b self, _sw: &'b mut impl SliceWriter) {}
}

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
