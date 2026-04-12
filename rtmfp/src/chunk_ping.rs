use crate::error::RtmfpError;
use crate::ChunkContent;
use parse::{GenerateBytes, ParseBytes, SliceWriter, VecSliceWriter};
use crate::encode::StaticEncode;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PingBody {
    pub message: Vec<u8>,
}

impl StaticEncode for PingBody {
    //TODO: drop
    fn encode_static(&self) -> Vec<u8> {
        let mut sw = VecSliceWriter::default();
        self.generate(&mut sw);
        sw.as_slice().to_vec()
    }
}

impl GenerateBytes for PingBody {
    fn generate<'b>(&'b self, sw: &'b mut impl SliceWriter) {
        sw.put(self.message.as_slice());
    }
}

impl ParseBytes<'_> for PingBody {
    type Error = RtmfpError;

    fn parse(i: &[u8]) -> Result<(&[u8], Self), Self::Error>
    where
        Self: Sized
    {
        Ok((&[], Self { message: i.to_vec() }))
    }
}


impl From<PingBody> for ChunkContent {
    fn from(s: PingBody) -> Self {
        ChunkContent::Ping(s)
    }
}

#[cfg(test)]
pub mod test {
    use crate::error::RtmfpError;
    use crate::PingBody;
    use parse::{GenerateBytes, ParseBytes, SliceWriter, VecSliceWriter};

    #[test]
    pub fn ping_round_trip() -> Result<(), RtmfpError> {
        let packet = PingBody {
            message: vec![1, 2, 3, 4],
        };

        let mut sw = VecSliceWriter::default();
        packet.generate(&mut sw);
        let (i, dec) = PingBody::parse(sw.as_slice())?;
        assert_eq!(dec, packet);
        assert_eq!(i, &[]);
        Ok(())
    }
}
