use crate::encode::{StaticEncode};
use crate::endpoint_discriminator::EndpointDiscriminator;
use crate::error::RtmfpError;
use crate::vlu::VLU;
use crate::ChunkContent;
use parse::{take, GenerateBytes, ParseBytes, SliceWriter, VecSliceWriter};

/// RFC7016[2.3.2] IHello
/// Sent by the initiator of a session to begin the handshake
/// Must be in a packet with session id 0, encrypted with the default session key, with pack mode startup
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct IHelloChunkBody {
    //TODO: don't store vlu
    pub epd_length: VLU,
    pub endpoint_discriminator: EndpointDiscriminator,
    pub tag: Vec<u8>,
}

impl StaticEncode for IHelloChunkBody {
    //TODO: drop
    fn encode_static(&self) -> Vec<u8> {
        let mut sw = VecSliceWriter::default();
        self.generate(&mut sw);
        sw.as_slice().to_vec()
    }
}

impl ParseBytes<'_> for IHelloChunkBody {
    type Error = RtmfpError;

    fn parse(i: &[u8]) -> Result<(&[u8], Self), Self::Error>
    where
        Self: Sized
    {
        let (i, epd_length) = VLU::parse(i)?;
        let (i, epd_data) = take(i, epd_length.value as _)?;
        let (_remaining, epd) = EndpointDiscriminator::parse(epd_data)?;

        Ok((i, Self {
            tag: i.to_vec(),
            epd_length,
            endpoint_discriminator: epd,
        }))
    }
}

impl GenerateBytes for IHelloChunkBody {
    fn generate<'b>(&'b self, sw: &'b mut impl SliceWriter) {
        self.epd_length.generate(sw);
        self.endpoint_discriminator.generate(sw);
        sw.put(self.tag.as_slice());
    }
}

impl From<IHelloChunkBody> for ChunkContent {
    fn from(s: IHelloChunkBody) -> Self {
        ChunkContent::IHello(s)
    }
}

#[cfg(test)]
pub mod test {
    use crate::endpoint_discriminator::{AncillaryDataBody, EndpointDiscriminator};
    use crate::error::RtmfpError;
    use crate::IHelloChunkBody;
    use parse::{GenerateBytes, ParseBytes, SliceWriter, VecSliceWriter};

    #[test]
    pub fn ihello_round_trip() -> Result<(), RtmfpError> {
        let packet = IHelloChunkBody {
            epd_length: 2.into(),
            endpoint_discriminator: EndpointDiscriminator(vec![AncillaryDataBody {
                ancillary_data: Vec::new(),
            }
            .into()]),
            tag: Vec::new(),
        };
        let mut sw = VecSliceWriter::default();
        packet.generate(&mut sw);
        let (i, dec) = IHelloChunkBody::parse(sw.as_slice())?;
        assert_eq!(dec, packet);
        assert_eq!(i, &[]);
        Ok(())
    }
}
