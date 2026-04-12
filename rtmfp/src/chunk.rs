use crate::chunk_content::ChunkContent;
use crate::chunk_rikeying::ResponderInitialKeyingChunkBody;
use crate::chunk_session_close_acknowledgement::SessionCloseAcknowledgementBody;
use crate::chunk_session_close_request::SessionCloseRequestBody;
use crate::chunk_type::ChunkType;
use crate::encode::StaticEncode;
use crate::session_key_components::Decode;
use crate::{IHelloChunkBody, IIKeyingChunkBody, PingBody, PingReplyBody, RHelloChunkBody};
use parse::{GenerateBytes, ParseBytes, SliceWriter, VecSliceWriter};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Chunk {
    pub chunk_type: u8,
    pub chunk_length: u16,
    pub payload: ChunkContent,
}

impl GenerateBytes for Chunk {
    fn generate<'b>(&'b self, sw: &'b mut impl SliceWriter) {
        let mut sw1 = VecSliceWriter::default();
        self.payload.generate(&mut sw1);

        let bytes = sw1.as_slice().to_vec();
        let size = bytes.len();

        sw.ne_u8(self.chunk_type);
        sw.be_u16(size as u16);
        sw.put(bytes.as_slice());
    }
}
impl Chunk {
    pub fn decode(i: &[u8]) -> nom::IResult<&[u8], Self> {
        let (i, chunk_type) = nom::number::complete::be_u8(i)?;
        let (i, chunk_length) = nom::number::complete::be_u16(i)?;


        let i = i;

        if chunk_type == ChunkType::ResponderInitialKeying as u8 {
            let chunk_bytes = &i[..chunk_length as usize];

            let (_empty, chunk) = ResponderInitialKeyingChunkBody::decode(chunk_bytes)?;

            Ok((
                &i[chunk_length as usize..],
                Self {
                    chunk_type,
                    chunk_length,
                    payload: ChunkContent::RIKeying(chunk),
                },
            ))
        // } else if chunk_type == ChunkType::ResponderHello as u8 {
        //     let (j, tag_length) = nom::number::complete::be_u8(i)?;
        //     let (j, tag_echo) = nom::bytes::complete::take(tag_length)(j)?;
        //
        //     let (j, cookie_length) = nom::number::complete::be_u8(j)?;
        //     let (j, cookie) = nom::bytes::complete::take(cookie_length)(j)?;
        //
        //     let cert_len =
        //         (chunk_length - tag_length as u16 - cookie_length as u16 - 1 - 1) as usize;
        //     // let (j, certificate) = nom::bytes::complete::take(cert_len)(j)?;
        //
        //     let cropped = &j[..cert_len];
        //     let (_cropped_rem, certificate) = FlashCertificate::decode(cropped)?;
        //     let j = &j[cert_len..];
        //
        //     i = j;
        //
        //     Ok((
        //         i,
        //         Self {
        //             chunk_type,
        //             chunk_length,
        //             payload: ChunkContent::RHello(RHelloChunkBody {
        //                 tag_length,
        //                 tag_echo: tag_echo.to_vec(),
        //                 cookie_length,
        //                 cookie: cookie.to_vec(),
        //                 responder_certificate: certificate,
        //             }),
        //         },
        //     ))
        } else {
            let chunk_type_x: ChunkType = chunk_type.try_into().expect(&format!("Unknown chunk type 0x{:X?}", chunk_type));
            let (i, payload) = nom::bytes::complete::take(chunk_length)(i)?;

            //TODO: handle incomplete parsing
            let payload: ChunkContent = match chunk_type_x {
                ChunkType::SessionCloseRequest => SessionCloseRequestBody::decode(payload)?.1.into(),
                ChunkType::Ping => PingBody::parse(payload)?.1.into(),
                ChunkType::PingReply => PingReplyBody::parse(payload)?.1.into(),
                ChunkType::SessionCloseAcknowledgement => SessionCloseAcknowledgementBody::decode(payload)?.1.into(),
                ChunkType::InitiatorHello => IHelloChunkBody::parse(payload)?.1.into(),
                ChunkType::ResponderHello => RHelloChunkBody::decode(payload)?.1.into(),
                ChunkType::InitiatorInitialKeying => IIKeyingChunkBody::decode(payload)?.1.into(),
                _ => ChunkContent::Raw(payload.to_vec()),
            };

            Ok((
                i,
                Self {
                    chunk_type,
                    chunk_length,
                    payload,
                },
            ))
        }
    }
}

impl<T: Into<ChunkContent> + StaticEncode + Clone> From<T> for Chunk {
    fn from(t: T) -> Self {
        let payload: ChunkContent = t.clone().into();
        let chunk_type: ChunkType = payload.clone().into();
        let len = t.encode_static().len();
        Self {
            chunk_type: chunk_type as u8,
            chunk_length: len as u16,
            payload,
        }
    }
}

#[cfg(test)]
pub mod test {
    use crate::chunk::Chunk;
    use crate::ChunkContent;
    use parse::{GenerateBytes, SliceWriter, VecSliceWriter};

    #[test]
    pub fn chunk_round_trip() {
        let m = Chunk {
            chunk_type: 0,
            chunk_length: 0,
            payload: ChunkContent::Raw(Vec::new()),
        };

        let mut sw = VecSliceWriter::default();
        m.generate(&mut sw);
        let (i, dec) = Chunk::decode(sw.as_slice()).unwrap();

        println!("{:#?}", m);
        println!("{:#?}", dec);

        assert_eq!(dec, m);
        assert_eq!(i, &[]);
    }
}
