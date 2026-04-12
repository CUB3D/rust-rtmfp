extern crate core;
#[macro_use]
extern crate derive_try_from_primitive;
#[macro_use]
extern crate enumset;

pub use crate::chunk_ihello::IHelloChunkBody;
pub use crate::chunk_iikeying::IIKeyingChunkBody;
pub use crate::chunk_ping::PingBody;
pub use crate::chunk_ping_reply::PingReplyBody;
pub use crate::chunk_rhello::RHelloChunkBody;
use crate::chunk_rikeying::ResponderInitialKeyingChunkBody;
use crate::chunk_session_close_acknowledgement::SessionCloseAcknowledgementBody;
use crate::chunk_session_close_request::SessionCloseRequestBody;
use crate::chunk_user_data::UserDataChunk;
use crate::encode::StaticEncode;

use crate::flash_profile_plain_packet::FlashProfilePlainPacket;

use crate::packet::{PacketFlag, PacketFlags};
use crate::rtmfp_option::OptionType;
use crate::rtmfp_option::RTMFPOption;
use crate::session_key_components::Decode;

use aes::cipher::block_padding::NoPadding;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use parse::{GenerateBytes, ParseBytes, SliceWriter, VecSliceWriter};
use std::convert::TryInto;

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

#[macro_export]
macro_rules! optionable {
    ($name: ident, $type_: expr) => {
        static_encode!($name);

        impl OptionType for $name {
            fn option_type(&self) -> u8 {
                $type_ as u8
            }
        }
    };
}

pub mod checksum;
pub mod chunk_ihello;
pub mod chunk_iikeying;
pub mod chunk_ping;
pub mod chunk_ping_reply;
pub mod chunk_rhello;
pub mod chunk_rikeying;
pub mod chunk_session_close_acknowledgement;
pub mod chunk_session_close_request;
pub mod chunk_user_data;
//TODO: restore
// pub mod connection_state_machine;
pub mod encode;
pub mod endpoint_discriminator;
pub mod flash_certificate;
pub mod flash_profile_plain_packet;
pub mod packet;
pub mod rtmfp_option;
pub mod rtmfp_stream;
pub mod session_key_components;
pub mod vlu;
mod error;

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


#[repr(u8)]
#[derive(TryFromPrimitive)]
pub enum ChunkType {
    PacketFragment = 0x7f,
    InitiatorHello = 0x30,
    ForwardedInitiatorHello = 0x0f,
    ResponderHello = 0x70,
    ResponderRedirect = 0x71,
    RHelloCookieChange = 0x79,
    InitiatorInitialKeying = 0x38,
    ResponderInitialKeying = 0x78,
    Ping = 0x01,
    PingReply = 0x41,
    UserData = 0x10,
    NextUserData = 0x11,
    DataAcknowledgementBitmap = 0x50,
    DataAcknowledgementRanges = 0x51,
    BufferProbe = 0x18,
    FlowExceptionReport = 0x5e,
    SessionCloseRequest = 0x0c,
    SessionCloseAcknowledgement = 0x4c,
    Padding = 0x00,
    Padding2 = 0xff,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ChunkContent {
    Raw(Vec<u8>),
    IHello(IHelloChunkBody),
    RHello(RHelloChunkBody),
    IIKeying(IIKeyingChunkBody),
    RIKeying(ResponderInitialKeyingChunkBody),
    Ping(PingBody),
    PingReply(PingReplyBody),
    SessionCloseRequest(SessionCloseRequestBody),
    SessionCloseAcknowledgement(SessionCloseAcknowledgementBody),
    UserData(UserDataChunk),
}
// static_encode!(ChunkContent);
impl From<ChunkContent> for ChunkType {
    fn from(s: ChunkContent) -> Self {
        match s {
            ChunkContent::Raw(_) => unimplemented!(),
            ChunkContent::RHello(_) => ChunkType::ResponderHello,
            ChunkContent::IHello(_) => ChunkType::InitiatorHello,
            ChunkContent::IIKeying(_) => ChunkType::InitiatorInitialKeying,
            ChunkContent::RIKeying(_) => ChunkType::ResponderInitialKeying,
            ChunkContent::Ping(_) => ChunkType::Ping,
            ChunkContent::PingReply(_) => ChunkType::PingReply,
            ChunkContent::SessionCloseRequest(_) => ChunkType::SessionCloseRequest,
            ChunkContent::SessionCloseAcknowledgement(_) => ChunkType::SessionCloseAcknowledgement,
            ChunkContent::UserData(_) => ChunkType::UserData,
        }
    }
}

impl GenerateBytes for ChunkContent {
    fn generate<'b>(&'b self, sw: &'b mut impl SliceWriter) {
        match self {
            ChunkContent::Raw(v) => {
                sw.put(v.as_slice());
            },
            ChunkContent::RHello(body) => {
                body.generate(sw);
            }
            ChunkContent::IIKeying(body) => {
                body.generate(sw);
            }
            ChunkContent::IHello(body) => {
                body.generate(sw);
            }
            ChunkContent::RIKeying(body) => {
                body.generate(sw);
            }
            ChunkContent::Ping(body) => {
                body.generate(sw);
            },
            ChunkContent::PingReply(body) => {
                body.generate(sw);
            },
            ChunkContent::SessionCloseRequest(body) => {
                body.generate(sw);
            },
            ChunkContent::SessionCloseAcknowledgement(body) => {
                body.generate(sw);
            },
            ChunkContent::UserData(body) => {
                body.generate(sw);
            },
        }
    }
}

impl ChunkContent {
    pub fn get_rhello(&self) -> Option<RHelloChunkBody> {
        match self {
            ChunkContent::RHello(body) => Some(body.clone()),
            _ => None,
        }
    }

    pub fn get_rikeying(&self) -> Option<ResponderInitialKeyingChunkBody> {
        match self {
            ChunkContent::RIKeying(body) => Some(body.clone()),
            _ => None,
        }
    }
}

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

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Packet {
    pub flags: PacketFlags,
    pub timestamp: Option<u16>,
    pub timestamp_echo: Option<u16>,
    pub chunks: Vec<Chunk>,
}
impl GenerateBytes for Packet {
    fn generate<'b>(&'b self, sw: &'b mut impl SliceWriter) {
        self.flags.generate(sw);
        if let Some(ts) = self.timestamp {
            sw.be_u16(ts);
        }
        if let Some(ts) = self.timestamp_echo {
            sw.be_u16(ts);
        }
        sw.gen_many(self.chunks.as_slice());
    }
}
impl Packet {
    pub fn decode(i: &[u8]) -> nom::IResult<&[u8], Self> {
        let (i, flags) = PacketFlags::decode(i)?;

        let mut i = i;

        let mut timestamp = None;
        let mut timestamp_echo = None;

        if flags.flags.contains(PacketFlag::TimestampPresent) {
            let (j, ts) = nom::number::complete::be_u16(i)?;
            timestamp = Some(ts);
            i = j;
        }

        if flags.flags.contains(PacketFlag::TimestampEchoPresent) {
            let (j, ts) = nom::number::complete::be_u16(i)?;
            timestamp_echo = Some(ts);
            i = j;
        }

        println!("i = {:?}", i);

        let (i, chunks) = nom::multi::many0(Chunk::decode)(i)?;

        println!("chunks = {:?}", chunks);

        if chunks.len() > 1 {
            eprintln!(
                "Did not expect more than one chunk, got: {:?}",
                chunks.len()
            )
        }

        Ok((
            i,
            Self {
                flags,
                timestamp,
                timestamp_echo,
                chunks,
            },
        ))
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Multiplex {
    pub session_id: u32,
    pub packet: FlashProfilePlainPacket,
    //TODO: no
    pub encryption_key: Option<Vec<u8>>,
}
impl GenerateBytes for Multiplex {
    fn generate<'b>(&'b self, sw: &'b mut impl SliceWriter) {
        let bytes = self.packet.encode();
        tracing::debug!("Bytes before encrypt = {:X?}", bytes);

        let mut bytes: Vec<u8> = bytes.to_vec();

        while !bytes.len().is_multiple_of(16) {
            bytes.push(0);
        }

        if let Some(keyv) = &self.encryption_key {
            let mut key: [u8; 16] = [0u8; 16];
            key.copy_from_slice(keyv);

            let iv = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            let cipher = Aes128CbcEnc::new(&key.into(), &iv.into());

            let l = bytes.len();
            let encrypted = cipher.encrypt_padded_mut::<NoPadding>(&mut bytes, l).unwrap();
            bytes = encrypted.to_vec();
        }

        let first_word: u32 = ((bytes[0] as u32) << 24)
            | ((bytes[1] as u32) << 16)
            | ((bytes[2] as u32) << 8)
            | (bytes[3] as u32);
        let second_word: u32 = ((bytes[4] as u32) << 24)
            | ((bytes[5] as u32) << 16)
            | ((bytes[6] as u32) << 8)
            | (bytes[7] as u32);

        let scrambled_session_id = (self.session_id) ^ (first_word ^ second_word);

        sw.be_u32(scrambled_session_id);
        sw.put(bytes.as_slice());
    }
}
impl Multiplex {
    pub fn decode<'a>(i: &'a [u8], decryption_key: &[u8]) -> nom::IResult<&'a [u8], Self> {
        let (i, scrambled_session_id) = nom::number::complete::be_u32(i)?;

        let first_word: u32 =
            ((i[0] as u32) << 24) | ((i[1] as u32) << 16) | ((i[2] as u32) << 8) | (i[3] as u32);
        let second_word: u32 =
            ((i[4] as u32) << 24) | ((i[5] as u32) << 16) | ((i[6] as u32) << 8) | (i[7] as u32);

        let session_id = scrambled_session_id ^ (first_word ^ second_word);

        let mut mut_i = i.to_vec();

        // i must be decrypted

        let mut key: [u8; 16] = [0u8; 16];
        key.copy_from_slice(decryption_key);

        let iv = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let cipher = Aes128CbcDec::new(&key.into(), &iv.into());
        let decrypted = cipher.decrypt_padded_mut::<NoPadding>(&mut mut_i).unwrap().to_vec();

        tracing::debug!("Decrypted packet = {:X?}", decrypted);

        let (_, flash_packet) = FlashProfilePlainPacket::decode(&decrypted).unwrap();

        Ok((
            i,
            Self {
                packet: flash_packet,
                session_id,
                encryption_key: None,
            },
        ))
    }
}

#[cfg(test)]
pub mod test {
    use crate::endpoint_discriminator::{AncillaryDataBody, EndpointDiscriminator};
    use crate::packet::PacketMode;
    use crate::{
        Chunk, ChunkContent, FlashProfilePlainPacket, IHelloChunkBody, Multiplex,
        Packet, PacketFlag, PacketFlags,
    };
    use parse::{GenerateBytes, SliceWriter, VecSliceWriter};

    #[test]
    #[ignore]
    pub fn multiplex_round_trip() {
        let mut m = Multiplex {
            session_id: 0,
            packet: FlashProfilePlainPacket {
                session_sequence_number: 0,
                checksum: 59579,
                packet: Packet {
                    flags: PacketFlags::new(
                        PacketMode::Startup,
                        PacketFlag::TimestampPresent.into(),
                    ),
                    timestamp: Some(0),
                    timestamp_echo: None,
                    chunks: vec![IHelloChunkBody {
                        epd_length: 2.into(),
                        endpoint_discriminator: EndpointDiscriminator(vec![AncillaryDataBody {
                            ancillary_data: Vec::new(),
                        }
                        .into()]),
                        tag: vec![0u8; 16],
                    }
                    .into()],
                },
            },
            encryption_key: None,
        };

        let mut sw = VecSliceWriter::default();
        m.encryption_key = Some(b"Adobe Systems 02".to_vec());
        m.generate(&mut sw);

        let (i, dec) = Multiplex::decode(sw.as_slice(), b"Adobe Systems 02").unwrap();

        println!("{:#?}", m);
        println!("{:#?}", dec);

        assert_eq!(dec, m);
        assert_eq!(i, &[]);
    }

    #[test]
    pub fn packet_round_trip() {
        let m = Packet {
            flags: PacketFlags {
                flags: PacketFlag::TimeCritical.into(),
                mode: PacketMode::Initiator,
            },
            timestamp: None,
            timestamp_echo: None,
            chunks: Vec::new(),
        };

        let mut sw = VecSliceWriter::default();
        m.generate(&mut sw);
        let (i, dec) = Packet::decode(sw.as_slice()).unwrap();

        println!("{:#?}", m);
        println!("{:#?}", dec);

        assert_eq!(dec, m);
        assert_eq!(i, &[]);
    }

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
