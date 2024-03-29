use crate::encode::Encode;
use crate::endpoint_discriminator::EndpointDiscriminator;
use crate::session_key_components::Decode;
use crate::vlu::VLU;
use crate::{encode_raw, ChunkContent};
use cookie_factory::sequence::tuple;
use cookie_factory::{GenResult, WriteContext};
use nom::IResult;
use std::io::Write;

#[derive(Debug, Clone, Eq, PartialEq)]
/// RFC7016[2.3.2] IHello
/// Sent by the initiator of a session to begin the handshake
/// Must be in a packed with session id 0, encrypted with the default session key, with pack mode startup
pub struct IHelloChunkBody {
    pub epd_length: VLU,
    pub endpoint_descriminator: EndpointDiscriminator,
    pub tag: Vec<u8>,
}

impl Decode for IHelloChunkBody {
    fn decode(i: &[u8]) -> IResult<&[u8], Self> {
        let (i, epd_length) = VLU::decode(i)?;

        let epd_data = &i[..epd_length.value as usize];
        let (_remaining, epd) = EndpointDiscriminator::decode(epd_data)?;

        let tag = &i[epd_length.value as usize..];

        Ok((
            &[],
            Self {
                epd_length,
                endpoint_descriminator: epd,
                tag: tag.to_vec(),
            },
        ))
    }
}

impl<W: Write> Encode<W> for IHelloChunkBody {
    fn encode(&self, w: WriteContext<W>) -> GenResult<W> {
        tuple((
            self.epd_length.encode(),
            move |out| self.endpoint_descriminator.encode(out),
            encode_raw(&self.tag),
        ))(w)
    }
}
static_encode!(IHelloChunkBody);

impl From<IHelloChunkBody> for ChunkContent {
    fn from(s: IHelloChunkBody) -> Self {
        ChunkContent::IHello(s)
    }
}

#[cfg(test)]
pub mod test {
    use crate::endpoint_discriminator::AncillaryDataBody;
    use crate::{Decode, IHelloChunkBody, StaticEncode};

    #[test]
    pub fn ihello_roundtrip() {
        let packet = IHelloChunkBody {
            epd_length: 2.into(),
            endpoint_descriminator: vec![AncillaryDataBody {
                ancillary_data: vec![],
            }
            .into()],
            tag: vec![],
        };
        let enc = packet.encode_static();
        let (i, dec) = IHelloChunkBody::decode(&enc).unwrap();
        assert_eq!(dec, packet);
        assert_eq!(i, &[]);
    }
}
