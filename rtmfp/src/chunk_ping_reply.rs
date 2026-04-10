use crate::encode::Encode;
use crate::session_key_components::Decode;
use crate::ChunkContent;
use cookie_factory::{GenResult, WriteContext};
use nom::IResult;
use std::io::Write;
use parse::ParseBytes;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PingReplyBody {
    pub message_echo: Vec<u8>,
}

impl<T: Write> Encode<T> for PingReplyBody {
    fn encode(&self, w: WriteContext<T>) -> GenResult<T> {
        self.message_echo.encode(w)
    }
}
static_encode!(PingReplyBody);

//TODO: support errors
impl ParseBytes<'_> for PingReplyBody {
    fn parse(i: &[u8]) -> Result<(&[u8], Self), ()>
    where
        Self: Sized
    {
        Ok((&[], PingReplyBody { message_echo: i.to_vec() }))
    }
}

impl From<PingReplyBody> for ChunkContent {
    fn from(s: PingReplyBody) -> Self {
        ChunkContent::PingReply(s)
    }
}

#[cfg(test)]
pub mod test {
    use parse::ParseBytes;
    use crate::{Decode, PingReplyBody, StaticEncode};

    #[test]
    pub fn pingreply_round_trip() {
        let packet = PingReplyBody {
            message_echo: vec![1, 2, 3, 4],
        };
        let enc = packet.encode_static();
        let (i, dec) = PingReplyBody::parse(&enc).unwrap();
        assert_eq!(dec, packet);
        assert_eq!(i, &[]);
    }
}
