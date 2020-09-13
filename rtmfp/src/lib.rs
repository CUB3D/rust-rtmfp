use cookie_factory::bytes::{be_u16, be_u32, be_u8};
use cookie_factory::multi::all;
use cookie_factory::sequence::tuple;
use cookie_factory::{gen, GenResult, SerializeFn, WriteContext};
use std::io::Write;
use std::net::{SocketAddr, UdpSocket};

use crate::chunk_ihello::IHelloChunkBody;
use crate::chunk_iikeying::IIKeyingChunkBody;
use crate::chunk_ping::PingBody;
use crate::chunk_ping_reply::PingReplyBody;
use crate::chunk_rhello::RHelloChunkBody;
use crate::chunk_rikeying::ResponderInitialKeyingChunkBody;
use crate::chunk_session_close_acknowledgement::SessionCloseAcknowledgementBody;
use crate::chunk_session_close_request::SessionCloseRequestBody;
use crate::chunk_user_data::{
    UserDataChunk, UserDataChunkFlags, UserDataChunkFragmentControl, UserDataChunkOptionType,
};
use crate::encode::{Encode, StaticEncode};
use crate::endpoint_discriminator::{AncillaryDataBody, EndpointDiscriminator};
use crate::flash_certificate::FlashCertificate;
use crate::flash_profile_plain_packet::FlashProfilePlainPacket;
use crate::keypair::KeyPair;
use crate::packet::{PacketFlag, PacketFlags, PacketMode};
use crate::rtmfp_option::OptionType;
use crate::rtmfp_option::RTMFPOption;
use crate::session_key_components::{
    get_epehemeral_diffie_hellman_public_key, get_extra_randomness, Decode,
    EphemeralDiffieHellmanPublicKeyBody,
};
use crate::session_key_components::{ExtraRandomnessBody, SessionKeyingComponent};
use crate::vlu::VLU;
use crate::ChunkType::SessionCloseAcknowledgement;
use aes::Aes128;
use block_modes::block_padding::NoPadding;
use block_modes::{BlockMode, Cbc};
use cookie_factory::combinator::cond;
use enumset::EnumSet;
use enumset::__internal::core_export::time::Duration;
use nom::{AsBytes, IResult};
use rand::{thread_rng, Rng};
use std::convert::TryInto;

type Aes128Cbc = Cbc<Aes128, NoPadding>;

#[macro_use]
extern crate derive_try_from_primitive;
#[macro_use]
extern crate enumset;

#[macro_export]
macro_rules! static_encode {
    ($name: ident) => {
        impl StaticEncode for $name {
            fn encode_static(&self) -> Vec<u8> {
                let v = vec![];
                let (bytes, _size) = cookie_factory::gen(move |out| self.encode(out), v).unwrap();
                bytes
            }
        }
    };
}

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
pub mod connection_state_machine;
pub mod encode;
pub mod endpoint_discriminator;
pub mod flash_certificate;
pub mod flash_profile_plain_packet;
pub mod keypair;
pub mod packet;
pub mod rtmfp_option;
pub mod session_key_components;
pub mod vlu;

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

#[derive(Debug, Clone)]
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

pub fn encode_raw<'a, 'b: 'a, W: Write + 'a>(v: &'b [u8]) -> impl SerializeFn<W> + 'a {
    all(v.iter().map(move |p| be_u8(*p)))
}

impl<T: Write> Encode<T> for ChunkContent {
    fn encode(&self, w: WriteContext<T>) -> GenResult<T> {
        match self {
            ChunkContent::Raw(v) => encode_raw(v)(w),
            ChunkContent::RHello(body) => body.encode(w),
            ChunkContent::IIKeying(body) => body.encode(w),
            ChunkContent::IHello(body) => body.encode(w),
            ChunkContent::RIKeying(body) => body.encode(w),
            ChunkContent::Ping(body) => body.encode(w),
            ChunkContent::PingReply(body) => body.encode(w),
            ChunkContent::SessionCloseRequest(body) => body.encode(w),
            ChunkContent::SessionCloseAcknowledgement(body) => body.encode(w),
            ChunkContent::UserData(body) => body.encode(w),
        }
    }
}
static_encode!(ChunkContent);

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

#[derive(Debug, Clone)]
pub struct Chunk {
    pub chunk_type: u8,
    pub chunk_length: u16,
    pub payload: ChunkContent,
}

impl Chunk {
    fn encode<'a, W: Write + 'a>(&'a self) -> impl SerializeFn<W> + 'a {
        let bytes = self.payload.encode_static();
        let size = bytes.len();

        move |out| {
            tuple((
                be_u8(self.chunk_type),
                be_u16(size as u16),
                encode_raw(&bytes),
            ))(out)
        }
    }

    pub fn decode(i: &[u8]) -> nom::IResult<&[u8], Self> {
        let (i, chunk_type) = nom::number::complete::be_u8(i)?;
        let (i, chunk_length) = nom::number::complete::be_u16(i)?;

        let mut i = i;

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
            let chunk_type_x: ChunkType = chunk_type.try_into().unwrap();
            let (i, payload) = nom::bytes::complete::take(chunk_length)(i)?;

            let payload: ChunkContent = match chunk_type_x {
                ChunkType::SessionCloseRequest => {
                    SessionCloseRequestBody::decode(payload)?.1.into()
                }
                ChunkType::Ping => PingBody::decode(payload)?.1.into(),
                ChunkType::PingReply => PingReplyBody::decode(payload)?.1.into(),
                ChunkType::SessionCloseAcknowledgement => {
                    SessionCloseAcknowledgementBody::decode(payload)?.1.into()
                }
                ChunkType::InitiatorHello => IHelloChunkBody::decode(payload)?.1.into(),
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

#[derive(Debug, Clone)]
pub struct Packet {
    pub flags: PacketFlags,
    pub timestamp: Option<u16>,
    pub timestamp_echo: Option<u16>,
    pub chunks: Vec<Chunk>,
}

impl Packet {
    pub fn encode<'a, W: Write + 'a>(&'a self) -> impl SerializeFn<W> + 'a {
        tuple((
            move |out| self.flags.encode(out),
            cond(self.timestamp.is_some(), move |out| {
                be_u16(self.timestamp.unwrap())(out)
            }),
            cond(self.timestamp_echo.is_some(), move |out| {
                be_u16(self.timestamp_echo.unwrap())(out)
            }),
            all(self.chunks.iter().map(move |c| c.encode())),
        ))
    }

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

        let (i, chunks) = nom::multi::many0(Chunk::decode)(i)?;
        if chunks.len() > 1 {
            panic!("Did not expect more than one chunk")
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

#[derive(Debug, Clone)]
pub struct Multiplex {
    pub session_id: u32,
    pub packet: FlashProfilePlainPacket,
}

impl Multiplex {
    fn encode<'a, 'b: 'a, W: Write + 'a>(
        &'a self,
        encryption_key: &'b Option<Vec<u8>>,
    ) -> impl SerializeFn<W> + 'a {
        let v = vec![];
        let (bytes, _size) = gen(move |out| self.packet.encode(out), v).unwrap();

        move |out| {
            let mut bytes: Vec<u8> = bytes.to_vec();

            if let Some(key) = encryption_key {
                while bytes.len() % 16 != 0 {
                    bytes.push(0);
                }

                println!("Bytes = {:?}", bytes);

                let iv = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
                let cipher = Aes128Cbc::new_var(key, &iv).unwrap();

                let encrypted = cipher.encrypt_vec(&bytes);
                bytes = encrypted;
            }

            let first_word: u32 = ((bytes[0] as u32) << 24)
                | ((bytes[1] as u32) << 16)
                | ((bytes[2] as u32) << 8)
                | (bytes[3] as u32);
            let second_word: u32 = ((bytes[4] as u32) << 24)
                | ((bytes[5] as u32) << 16)
                | ((bytes[6] as u32) << 8)
                | (bytes[7] as u32);

            let scrambled_session_id = (self.session_id as u32) ^ (first_word ^ second_word);

            let x = tuple((be_u32(scrambled_session_id), encode_raw(&bytes)))(out);

            x
        }
    }

    pub fn decode<'a>(i: &'a [u8], decryption_key: &[u8]) -> nom::IResult<&'a [u8], Self> {
        let (i, scrambled_session_id) = nom::number::complete::be_u32(i)?;

        let first_word: u32 =
            ((i[0] as u32) << 24) | ((i[1] as u32) << 16) | ((i[2] as u32) << 8) | (i[3] as u32);
        let second_word: u32 =
            ((i[4] as u32) << 24) | ((i[5] as u32) << 16) | ((i[6] as u32) << 8) | (i[7] as u32);

        let session_id = scrambled_session_id ^ (first_word ^ second_word);

        let mut mut_i = i.to_vec();

        // i must be decrypted

        let iv = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let cipher = Aes128Cbc::new_var(decryption_key, &iv).unwrap();
        let decrypted = cipher.decrypt(&mut mut_i).unwrap().to_vec();

        let (_, flash_packet) = FlashProfilePlainPacket::decode(&decrypted).unwrap();

        Ok((
            i,
            Self {
                packet: flash_packet,
                session_id,
            },
        ))
    }
}

pub struct RTMFPStream {
    socket: UdpSocket,
    encryption_key: Option<Vec<u8>>,
    decryption_key: Vec<u8>,
}

impl RTMFPStream {
    pub fn new_server() -> Self {
        let socket = UdpSocket::bind("127.0.0.1:1935").unwrap();

        Self {
            socket,
            encryption_key: Some(b"Adobe Systems 02".to_vec()),
            decryption_key: b"Adobe Systems 02".to_vec(),
        }
    }

    pub fn new_client() -> Self {
        let socket = UdpSocket::bind("127.0.0.1:2020").unwrap();

        socket.connect("127.0.0.1:1935").unwrap();

        Self {
            socket,
            encryption_key: Some(b"Adobe Systems 02".to_vec()),
            decryption_key: b"Adobe Systems 02".to_vec(),
        }
    }

    pub fn send(&self, m: Multiplex, dest: SocketAddr) {
        let v = vec![];
        let (bytes, _s2) = gen(m.encode(&self.encryption_key), v).unwrap();
        println!("Bytes = {:?}", bytes);
        self.socket.send_to(&bytes, dest).unwrap();
    }

    pub fn read(&self) -> Option<(Multiplex, SocketAddr)> {
        let mut buf = [0; 1024];

        if let Ok((amt, src)) = self.socket.recv_from(&mut buf) {
            // Crop the buffer to the size of the packet
            let buf = &buf[..amt];
            let (_i, m) = Multiplex::decode(buf, &self.decryption_key).unwrap();
            Some((m, src))
        } else {
            None
        }
    }

    pub fn set_timeout(&self) {
        self.socket
            .set_read_timeout(Some(Duration::from_millis(250)));
    }

    pub fn set_encrypt_key(&mut self, key: Vec<u8>) {
        self.encryption_key = Some(key)
    }

    pub fn set_decrypt_key(&mut self, key: Vec<u8>) {
        self.decryption_key = key
    }
}

// fn main() -> std::io::Result<()> {
//     {
//         let mut stream = RTMFPStream::new();
//         let encrypt_key = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
//         let decrypt_key = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
//         stream.set_encrypt_key(encrypt_key.to_vec());
//         stream.set_decrypt_key(decrypt_key.to_vec());
//
//         let mut our_tag = [0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
//         thread_rng().fill(&mut our_tag);
//
//         let m = Multiplex {
//             session_id: 0,
//             packet: FlashProfilePlainPacket {
//                 session_sequence_number: 0,
//                 checksum: 0,
//                 packet: Packet {
//                     flags: PacketFlags::new(
//                         PacketMode::Startup,
//                         PacketFlag::TimestampPresent.into(),
//                     ),
//                     timestamp: Some(0),
//                     timestamp_echo: None,
//                     chunks: vec![IHelloChunkBody {
//                         epd_length: 2.into(),
//                         endpoint_descriminator: vec![AncillaryDataBody {
//                             ancillary_data: vec![],
//                         }
//                         .into()],
//                         tag: our_tag.to_vec(),
//                     }
//                     .into()],
//                 },
//             },
//         };
//
//         stream.send(m);
//
//         let m2 = stream.read().unwrap();
//
//         let their_nonce = get_extra_randomness(
//             m2.clone()
//                 .packet
//                 .packet
//                 .chunks
//                 .first()
//                 .unwrap()
//                 .payload
//                 .get_rhello()
//                 .unwrap()
//                 .responder_certificate
//                 .cannonical,
//         )
//         .unwrap()
//         .extra_randomness;
//
//         println!("Got multiplex response: {:?}", m2);
//
//         let rec_body = m2
//             .packet
//             .packet
//             .chunks
//             .first()
//             .unwrap()
//             .payload
//             .get_rhello()
//             .unwrap();
//
//         let keypair = KeyPair::new();
//
//         //TODO: sending wrong public key size here
//
//         let our_nonce = b"AAAAAAAA".to_vec();
//
//         // skic must only have a ephemeral public key and extra randomness, cert must be empty
//         let m = Multiplex {
//             session_id: 0,
//             packet: FlashProfilePlainPacket {
//                 session_sequence_number: 0,
//                 checksum: 0,
//                 packet: Packet {
//                     flags: PacketFlags::new(
//                         PacketMode::Startup,
//                         PacketFlag::TimestampPresent.into(),
//                     ),
//                     timestamp: Some(0),
//                     timestamp_echo: None,
//                     chunks: vec![IIKeyingChunkBody::new(
//                         0,
//                         rec_body.cookie,
//                         FlashCertificate {
//                             cannonical: vec![],
//                             remainder: vec![],
//                         },
//                         vec![
//                             EphemeralDiffieHellmanPublicKeyBody {
//                                 group_id: 2.into(),
//                                 public_key: keypair.public_key.clone(),
//                             }
//                             .into(),
//                             ExtraRandomnessBody {
//                                 extra_randomness: our_nonce.clone(),
//                             }
//                             .into(),
//                         ],
//                     )
//                     .into()],
//                 },
//             },
//         };
//
//         stream.send(m);
//
//         let stage_4 = stream.read().unwrap();
//
//         println!("Got stage4: {:?}", stage_4);
//
//         let their_key_bytes = get_epehemeral_diffie_hellman_public_key(
//             stage_4
//                 .packet
//                 .packet
//                 .chunks
//                 .first()
//                 .unwrap()
//                 .payload
//                 .get_rikeying()
//                 .unwrap()
//                 .session_key_responder_component,
//         )
//         .unwrap()
//         .public_key;
//
//         let responder_session_id = stage_4
//             .clone()
//             .packet
//             .packet
//             .chunks
//             .first()
//             .unwrap()
//             .payload
//             .get_rikeying()
//             .unwrap()
//             .responder_session_id;
//
//         let shared_key = keypair.derive_shared_key(their_key_bytes);
//         // Compute packet keys
//         let encrypt_key = &hmac_sha256::HMAC::mac(
//             hmac_sha256::HMAC::mac(their_nonce.as_bytes(), our_nonce.as_bytes()).as_bytes(),
//             &shared_key,
//         )[..16];
//         let decrypt_key = &hmac_sha256::HMAC::mac(
//             hmac_sha256::HMAC::mac(our_nonce.as_bytes(), their_nonce.as_bytes()).as_bytes(),
//             &shared_key,
//         )[..16];
//         let encrypt_key = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
//         let decrypt_key = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
//         stream.set_encrypt_key(encrypt_key.to_vec());
//         stream.set_decrypt_key(decrypt_key.to_vec());
//
//         println!("Handshake done\n\n\n");
//         stream.set_timeout();
//
//         let flow_start_packet = Multiplex {
//             session_id: responder_session_id,
//             packet: FlashProfilePlainPacket {
//                 session_sequence_number: 0,
//                 checksum: 0,
//                 packet: Packet {
//                     flags: PacketFlags::new(
//                         PacketMode::Initiator,
//                         PacketFlag::TimestampPresent.into(),
//                     ),
//                     timestamp: Some(0),
//                     timestamp_echo: None,
//                     chunks: vec![UserDataChunk {
//                         flags: UserDataChunkFlags {
//                             flags: EnumSet::empty(),
//                             fragment_control: UserDataChunkFragmentControl::Begin,
//                         },
//                         flow_id: 1.into(),
//                         sequence_number: 1.into(),
//                         forward_sequence_number_offset: 0.into(),
//                         options: vec![RTMFPOption::Option {
//                             type_: (UserDataChunkOptionType::PerFlowMetadata as u8).into(),
//                             length: 0.into(),
//                             value: vec![],
//                         }],
//                         user_data: vec![],
//                     }
//                     .into()],
//                 },
//             },
//         };
//         stream.send(flow_start_packet);
//
//         loop {
//             if let Some(packet) = stream.read() {
//                 println!("Got new packet {:?}", packet);
//
//                 let chunks = packet.packet.packet.chunks;
//
//                 for chunk in &chunks {
//                     match chunk.payload {
//                         ChunkContent::SessionCloseRequest(_) => {
//                             let ack = Multiplex {
//                                 session_id: responder_session_id,
//                                 packet: FlashProfilePlainPacket {
//                                     session_sequence_number: 0,
//                                     checksum: 0,
//                                     packet: Packet {
//                                         flags: PacketFlags::new(
//                                             PacketMode::Initiator,
//                                             PacketFlag::TimestampPresent.into(),
//                                         ),
//                                         timestamp: Some(0),
//                                         timestamp_echo: None,
//                                         chunks: vec![SessionCloseAcknowledgementBody {}.into()],
//                                     },
//                                 },
//                             };
//                             stream.send(ack);
//                         }
//                         _ => {}
//                     }
//                 }
//             } else {
//                 println!("Timeout");
//
//                 let m = Multiplex {
//                     session_id: responder_session_id,
//                     packet: FlashProfilePlainPacket {
//                         session_sequence_number: 0,
//                         checksum: 0,
//                         packet: Packet {
//                             flags: PacketFlags::new(
//                                 PacketMode::Initiator,
//                                 PacketFlag::TimestampPresent.into(),
//                             ),
//                             timestamp: Some(0),
//                             timestamp_echo: None,
//                             chunks: vec![PingBody {
//                                 message: "Hello".as_bytes().to_vec(),
//                             }
//                             .into()],
//                         },
//                     },
//                 };
//
//                 // stream.send(m);
//             }
//         }
//     }
//     Ok(())
// }
