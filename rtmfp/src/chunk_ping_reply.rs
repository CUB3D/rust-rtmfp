use crate::error::RtmfpError;
use crate::ChunkContent;
use parse::{GenerateBytes, ParseBytes, SliceWriter};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PingReplyBody {
    pub message_echo: Vec<u8>,
}

impl GenerateBytes for PingReplyBody {
    fn generate(&self, sw: &mut impl SliceWriter) {
        sw.put(self.message_echo.as_slice());
    }
}

impl ParseBytes<'_> for PingReplyBody {
    type Error = RtmfpError;

    fn parse(i: &[u8]) -> Result<(&[u8], Self), Self::Error>
    where
        Self: Sized
    {
        Ok((&[], Self { message_echo: i.to_vec() }))
    }
}

impl From<PingReplyBody> for ChunkContent {
    fn from(s: PingReplyBody) -> Self {
        ChunkContent::PingReply(s)
    }
}

#[cfg(test)]
pub mod test {
    use crate::error::RtmfpError;
    use crate::{PingReplyBody};
    use parse::{GenerateBytes, ParseBytes, SliceWriter, VecSliceWriter};

    #[test]
    pub fn pingreply_round_trip() -> Result<(), RtmfpError> {
        let packet = PingReplyBody {
            message_echo: vec![1, 2, 3, 4],
        };
        let mut sw = VecSliceWriter::default();
        packet.generate(&mut sw);
        let (i, dec) = PingReplyBody::parse(sw.as_slice())?;
        assert_eq!(dec, packet);
        assert_eq!(i, &[]);
        Ok(())
    }
}
