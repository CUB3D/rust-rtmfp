use crate::encode::Encode;
use crate::endpoint_discriminator::EndpointDiscriminator;
use crate::flash_certificate::FlashCertificate;
use crate::session_key_components::Decode;
use crate::vlu::VLU;
use crate::StaticEncode;
use crate::{encode_raw, ChunkContent};
use cookie_factory::bytes::be_u8;
use cookie_factory::sequence::tuple;
use cookie_factory::{GenResult, WriteContext};
use nom::IResult;
use std::io::Write;

#[derive(Debug, Clone)]
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

impl<T: Write> Encode<T> for RHelloChunkBody {
    fn encode(&self, w: WriteContext<T>) -> GenResult<T> {
        tuple((
            be_u8(self.tag_length),
            move |out| self.tag_echo.encode(out),
            be_u8(self.cookie_length),
            move |out| self.cookie.encode(out),
            move |out| self.responder_certificate.encode(out),
        ))(w)
    }
}
static_encode!(RHelloChunkBody);
impl From<RHelloChunkBody> for ChunkContent {
    fn from(body: RHelloChunkBody) -> Self {
        ChunkContent::RHello(body)
    }
}
