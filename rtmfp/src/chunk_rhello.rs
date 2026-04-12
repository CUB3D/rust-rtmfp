use crate::encode::{StaticEncode};

use crate::flash_certificate::FlashCertificate;
use crate::session_key_components::Decode;

use crate::ChunkContent;
use nom::IResult;
use parse::{GenerateBytes, SliceWriter, VecSliceWriter};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RHelloChunkBody {
    pub tag_length: u8,
    pub tag_echo: Vec<u8>,
    pub cookie_length: u8,
    pub cookie: Vec<u8>,
    pub responder_certificate: FlashCertificate,
}

impl Decode for RHelloChunkBody {
    fn decode(i: &[u8]) -> IResult<&[u8], Self> {
        let (j, tag_length) = nom::number::complete::be_u8(i)?;
        let (j, tag_echo) = nom::bytes::complete::take(tag_length)(j)?;

        let (j, cookie_length) = nom::number::complete::be_u8(j)?;
        let (j, cookie) = nom::bytes::complete::take(cookie_length)(j)?;

        // let cert_len =
        //     (chunk_length - tag_length as u16 - cookie_length as u16 - 1 - 1) as usize;

        // let cropped = j&j[..cert_len];
        let cropped = j;
        let (_cropped_rem, certificate) = FlashCertificate::decode(cropped)?;
        // let j = &j[cert_len..];

        Ok((
            &[],
            Self {
                tag_length,
                tag_echo: tag_echo.to_vec(),
                cookie_length,
                cookie: cookie.to_vec(),
                responder_certificate: certificate,
            },
        ))
    }
}

impl GenerateBytes for RHelloChunkBody {
    fn generate<'b>(&'b self, sw: &'b mut impl SliceWriter) {
        sw.ne_u8(self.tag_length);
        sw.put(self.tag_echo.as_slice());
        sw.ne_u8(self.cookie_length);
        sw.put(self.cookie.as_slice());
        self.responder_certificate.generate(sw);
    }
}

impl StaticEncode for RHelloChunkBody {
    //TODO: drop
    fn encode_static(&self) -> Vec<u8> {
        let mut sw = VecSliceWriter::default();
        self.generate(&mut sw);
        sw.as_slice().to_vec()
    }
}

impl From<RHelloChunkBody> for ChunkContent {
    fn from(body: RHelloChunkBody) -> Self {
        ChunkContent::RHello(body)
    }
}

#[cfg(test)]
pub mod test {
    use crate::flash_certificate::FlashCertificate;
    use crate::{RHelloChunkBody, StaticEncode};
    use crate::session_key_components::Decode;

    #[test]
    pub fn rhello_round_trip() {
        let packet = RHelloChunkBody {
            tag_length: 0,
            tag_echo: Vec::new(),
            cookie_length: 0,
            cookie: Vec::new(),
            responder_certificate: FlashCertificate {
                canonical: Vec::new(),
                remainder: Vec::new(),
            },
        };
        let enc = packet.encode_static();
        let (i, dec) = RHelloChunkBody::decode(&enc).unwrap();
        assert_eq!(dec, packet);
        assert_eq!(i, &[]);
    }
}
