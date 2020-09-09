use cookie_factory::bytes::{be_u16, be_u32, be_u8};
use cookie_factory::multi::all;
use cookie_factory::sequence::tuple;
use cookie_factory::{gen, GenResult, SerializeFn, WriteContext};
use std::io::Write;
use std::net::UdpSocket;

use crate::endpoint_discriminator::{AncillaryDataBody, EndpointDiscriminator};
use crate::flash_certificate::{FlashCertificate, AcceptsAncillaryDataBody, SupportedEphemeralDiffieHellmanGroupBody};
use crate::packet::{PacketFlag, PacketFlags, PacketMode};
use crate::rtmfp_option::OptionType;
use crate::rtmfp_option::RTMFPOption;
use crate::session_key_components::{Decode, Encode, EphemeralDiffieHellmanPublicKeyBody, get_epehemeral_diffie_hellman_public_key};
use crate::session_key_components::{ExtraRandomnessBody, SessionKeyingComponent};
use crate::vlu::VLU;
use aes::Aes128;
use block_modes::block_padding::NoPadding;
use block_modes::{BlockMode, Cbc};
use cookie_factory::combinator::cond;
use enumset::EnumSet;
use nom::lib::std::convert::TryFrom;
use nom::IResult;
use rand::rngs::OsRng;
use std::convert::TryInto;
use x448::{Secret, PublicKey};
use crate::flash_certificate::CertificateOptions::AcceptsAncillaryData;
use nom::bits::complete::take;

type Aes128Cbc = Cbc<Aes128, NoPadding>;

pub trait StaticEncode {
    fn encode_static(&self) -> Vec<u8>;
}

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
pub mod endpoint_discriminator;
pub mod flash_certificate;
pub mod packet;
pub mod rtmfp_option;
pub mod session_key_components;
pub mod vlu;
pub mod connection_state_machine;

#[repr(u8)]
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
pub struct ResponderInitialKeyingChunkBody {
    pub responder_session_id: u32,
    pub skrc_length: VLU,
    pub session_key_responder_component: SessionKeyingComponent,
    pub signature: Vec<u8>
}

impl Decode for ResponderInitialKeyingChunkBody {
    fn decode(i: &[u8]) -> IResult<&[u8], Self> {
        let (i, responder_session_id) = nom::number::complete::be_u32(i)?;
        let (i, skrc_length) = VLU::decode(i)?;

        let skrc_bytes = &i[..skrc_length.value as usize];
        let (_empty, session_key_responder_component) = SessionKeyingComponent::decode(i)?;
        let signature = i[skrc_length.value as usize..].to_vec();

        Ok((&[], Self {
            responder_session_id,
            skrc_length,
            session_key_responder_component: session_key_responder_component.to_vec(),
            signature,
        }))
    }
}

#[derive(Debug)]
pub struct IIKeyingChunkBody {
    pub initiator_session_id: u32,
    pub cookie_length: VLU,
    pub cookie_echo: Vec<u8>,
    pub cert_length: VLU,
    pub initiator_certificate: FlashCertificate,
    pub skic_length: VLU,
    pub session_key_initiator_component: SessionKeyingComponent,
    pub signature: Vec<u8>,
}

impl IIKeyingChunkBody {
    fn new(
        session_id: u32,
        cookie: Vec<u8>,
        certificate: FlashCertificate,
        skic: SessionKeyingComponent,
    ) -> Self {
        let cert_size = certificate.encode_static().len();
        let skic_length = skic.encode_static().len();

        Self {
            initiator_session_id: session_id,
            cookie_length: cookie.len().into(),
            cookie_echo: cookie,
            cert_length: cert_size.into(),
            initiator_certificate: certificate,
            skic_length: skic_length.into(),
            session_key_initiator_component: skic,
            signature: vec![],
        }
    }

    fn encode<'a, W: Write + 'a>(&'a self) -> impl SerializeFn<W> + 'a {
        tuple((
            be_u32(self.initiator_session_id),
            self.cookie_length.encode(),
            encode_raw(&self.cookie_echo),
            self.cert_length.encode(),
            //TODO: compute above length
            move |out| self.initiator_certificate.encode(out),
            self.skic_length.encode(),
            move |out| self.session_key_initiator_component.encode(out),
            encode_raw(&self.signature),
        ))
    }
}

#[derive(Debug, Clone)]
pub struct IHelloChunkBody {
    pub epd_length: VLU,
    pub endpoint_descriminator: EndpointDiscriminator,
    pub tag: Vec<u8>,
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

#[derive(Debug, Clone)]
pub struct RHelloChunkBody {
    pub tag_length: u8,
    pub tag_echo: Vec<u8>,
    pub cookie_length: u8,
    pub cookie: Vec<u8>,
    pub responder_certificate: FlashCertificate,
}

#[derive(Debug)]
pub enum ChunkContent {
    Raw(Vec<u8>),
    IHello(IHelloChunkBody),
    RHello(RHelloChunkBody),
    IIKeying(IIKeyingChunkBody),
    RIKeying(ResponderInitialKeyingChunkBody),
}

pub fn encode_raw<'a, 'b: 'a, W: Write + 'a>(v: &'b [u8]) -> impl SerializeFn<W> + 'a {
    all(v.iter().map(move |p| be_u8(*p)))
}

impl<T: Write> Encode<T> for ChunkContent {
    fn encode(&self, w: WriteContext<T>) -> GenResult<T> {
        match self {
            ChunkContent::Raw(v) => encode_raw(v)(w),
            ChunkContent::RHello(body) => unimplemented!(),
            ChunkContent::IIKeying(body) => body.encode()(w),
            ChunkContent::IHello(body) => body.encode(w),
            ChunkContent::RIKeying(body) => unimplemented!(),
        }
    }
}
static_encode!(ChunkContent);

impl ChunkContent {
    fn get_rhello(&self) -> Option<RHelloChunkBody> {
        match self {
            ChunkContent::RHello(body) => Some(body.clone()),
            _ => None,
        }
    }

    fn get_rikeying(&self) -> Option<ResponderInitialKeyingChunkBody> {
        match self {
            ChunkContent::RIKeying(body) => Some(body.clone()),
            _ => None,
        }
    }
}

#[derive(Debug)]
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

            Ok((&i[chunk_length as usize..], Self {
                chunk_type,
                chunk_length,
                payload: ChunkContent::RIKeying(chunk)
            }))
        }
        else if chunk_type == ChunkType::ResponderHello as u8 {
            let (j, tag_length) = nom::number::complete::be_u8(i)?;
            let (j, tag_echo) = nom::bytes::complete::take(tag_length)(j)?;

            let (j, cookie_length) = nom::number::complete::be_u8(j)?;
            let (j, cookie) = nom::bytes::complete::take(cookie_length)(j)?;

            let cert_len =
                (chunk_length - tag_length as u16 - cookie_length as u16 - 1 - 1) as usize;
            // let (j, certificate) = nom::bytes::complete::take(cert_len)(j)?;

            let cropped = &j[..cert_len];
            let (cropped_rem, certificate) = FlashCertificate::decode(cropped)?;
            let j = &j[cert_len..];

            i = j;

            Ok((
                i,
                Self {
                    chunk_type,
                    chunk_length,
                    payload: ChunkContent::RHello(RHelloChunkBody {
                        tag_length,
                        tag_echo: tag_echo.to_vec(),
                        cookie_length,
                        cookie: cookie.to_vec(),
                        responder_certificate: certificate,
                    }),
                },
            ))
        } else {
            let (i, payload) = nom::bytes::complete::take(chunk_length)(i)?;

            Ok((
                i,
                Self {
                    chunk_type,
                    chunk_length,
                    payload: ChunkContent::Raw(payload.to_vec()),
                },
            ))
        }
    }
}

#[derive(Debug)]
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

        let (i, chunk) = Chunk::decode(i)?;

        Ok((
            i,
            Self {
                flags,
                timestamp,
                timestamp_echo,
                chunks: vec![chunk],
            },
        ))
    }
}

#[derive(Debug)]
pub struct FlashProfilePlainPacket {
    pub session_sequence_number: u8,
    pub checksum: u16,
    pub packet: Packet,
}

impl FlashProfilePlainPacket {
    fn encode<'a, W: Write + 'a>(&'a self) -> impl SerializeFn<W> + 'a {
        let v = vec![];
        let (mut bytes, _size): (Vec<u8>, u64) = gen(self.packet.encode(), v).unwrap();

        let checksum = checksum::checksum(&bytes);

        tuple((be_u16(checksum), self.packet.encode()))
    }

    fn decode(i: &[u8]) -> nom::IResult<&[u8], Self> {
        let (i, checksum) = nom::number::complete::be_u16(i)?;
        let (i, packet) = Packet::decode(i)?;

        Ok((
            i,
            Self {
                checksum,
                packet,
                session_sequence_number: 0,
            },
        ))
    }
}

#[derive(Debug)]
pub struct Multiplex {
    pub session_id: u32,
    pub packet: Vec<FlashProfilePlainPacket>,
}

impl Multiplex {
    fn encode<'a, W: Write + 'a>(&'a self, encrypted: bool) -> impl SerializeFn<W> + 'a {
        let v = vec![];
        let (bytes, _size) = gen(all(self.packet.iter().map(move |p| p.encode())), v).unwrap();

        move |out| {
            let mut bytes: Vec<u8> = bytes.to_vec();

            if encrypted {
                while bytes.len() % 16 != 0 {
                    bytes.push(0);
                }

                println!("Sending: {:?}", &bytes);

                let key = b"Adobe Systems 02";
                let iv = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
                let cipher = Aes128Cbc::new_var(key, &iv).unwrap();

                let encrypted = cipher.encrypt_vec(&bytes);
                bytes = encrypted;
            }

            let first_word: u32 = ((bytes[0] as u32) << 24)
                | ((bytes[1] as u32) << 16)
                | ((bytes[2] as u32) << 8)
                | ((bytes[3] as u32) << 0);
            let second_word: u32 = ((bytes[4] as u32) << 24)
                | ((bytes[5] as u32) << 16)
                | ((bytes[6] as u32) << 8)
                | ((bytes[7] as u32) << 0);

            let scrambled_session_id = (self.session_id as u32) ^ (first_word ^ second_word);

            let x = tuple((be_u32(scrambled_session_id), encode_raw(&bytes)))(out);

            x
        }
    }

    pub fn decode(i: &[u8]) -> nom::IResult<&[u8], Self> {
        let (i, scrambled_session_id) = nom::number::complete::be_u32(i)?;

        let mut mut_i = i.to_vec();

        // i must be decrypted

        let key = b"Adobe Systems 02";
        let iv = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let cipher = Aes128Cbc::new_var(key, &iv).unwrap();
        let decrypted = cipher.decrypt(&mut mut_i).unwrap().to_vec();

        let (_, flash_packet) = FlashProfilePlainPacket::decode(&decrypted).unwrap();

        // let (i, flash_packet) = FlashProfilePlainPacket::decode(i)?;

        Ok((
            i,
            Self {
                packet: vec![flash_packet],
                session_id: 0, //scrambled_session_id,
            },
        ))
    }
}

struct RTMFPStream {
    socket: UdpSocket,
}

impl RTMFPStream {
    fn new() -> Self {
        let socket = UdpSocket::bind("127.0.0.1:2020").unwrap();

        socket.connect("127.0.0.1:1935").unwrap();

        Self { socket }
    }

    pub fn send(&self, m: Multiplex, encypted: bool) {
        // println!("Sending {:?}", m);
        let v = vec![];
        let (bytes, _s2) = gen(m.encode(encypted), v).unwrap();
        self.socket.send(&bytes).unwrap();
    }

    pub fn read(&self) -> Multiplex {
        let mut buf = [0; 1024];
        let (amt, src) = self.socket.recv_from(&mut buf).unwrap();
        // println!("Got response of size {} = {:?}", amt, buf);
        // Crop the buffer to the size of the packet
        let buf = &buf[..amt];
        let (_i, m) = Multiplex::decode(buf).unwrap();

        m
    }
}

fn main() -> std::io::Result<()> {
    {
        let stream = RTMFPStream::new();

        let m = Multiplex {
            session_id: 0,
            packet: vec![FlashProfilePlainPacket {
                session_sequence_number: 0,
                checksum: 0,
                packet: Packet {
                    flags: PacketFlags::new(
                        PacketMode::Startup,
                        PacketFlag::TimestampPresent.into(),
                    ),
                    timestamp: Some(0),
                    timestamp_echo: None,
                    chunks: vec![Chunk {
                        chunk_type: 0x30,
                        chunk_length: 7,
                        payload: ChunkContent::IHello(IHelloChunkBody {
                            epd_length: 2.into(),
                            endpoint_descriminator: vec![AncillaryDataBody {
                                ancillary_data: vec![],
                            }
                            .into()],
                            tag: "ABCDEF".into(),
                        }),
                    }],
                },
            }],
        };

        stream.send(m, true);

        let m2 = stream.read();

        println!("Got multiplex response: {:?}", m2);

        // let public_key

        let rec_body = m2
            .packet
            .first()
            .unwrap()
            .packet
            .chunks
            .first()
            .unwrap()
            .payload
            .get_rhello()
            .unwrap();

        let alice_secret = Secret::new(&mut OsRng);
        let alice_public = PublicKey::from(&alice_secret);

        // skic must only have a ephemeral public key and extra randomness, cert must be empty
        let m = Multiplex {
            session_id: 0,
            packet: vec![FlashProfilePlainPacket {
                session_sequence_number: 0,
                checksum: 0,
                packet: Packet {
                    flags: PacketFlags::new(
                        PacketMode::Startup,
                        PacketFlag::TimestampPresent.into(),
                    ),
                    timestamp: Some(0),
                    timestamp_echo: None,
                    chunks: vec![Chunk {
                        chunk_type: ChunkType::InitiatorInitialKeying as u8,
                        chunk_length: 0,
                        payload: ChunkContent::IIKeying(IIKeyingChunkBody::new(
                            0,
                            rec_body.cookie,
                            FlashCertificate {
                                cannonical: vec![
                                ],
                                remainder: vec![],
                            },
                            vec![
                                EphemeralDiffieHellmanPublicKeyBody {
                                    group_id: 14.into(),
                                    public_key: alice_public.as_bytes().to_vec(),
                                }
                                .into(),
                                ExtraRandomnessBody {
                                    extra_randomness: b"AAAAAAAA".to_vec(),
                                }
                                .into(),
                            ],
                        )),
                    }],
                },
            }],
        };

        stream.send(m, true);


        let stage_4 = stream.read();

        println!("Got stage4: {:?}", stage_4);

        let epehemeral_key = get_epehemeral_diffie_hellman_public_key(stage_4.packet.first().unwrap().packet.chunks.first().unwrap().payload.get_rikeying().unwrap().session_key_responder_component).unwrap();

        println!("len = {}", epehemeral_key.public_key.len());

        let server_public = PublicKey::from_bytes(&epehemeral_key.public_key).expect("Loading public key");

        let secret = alice_secret.to_diffie_hellman(&server_public).expect("Shared secret");

        // println!("Got key = {:?}", epehemeral_key);

        println!("Got shared secret = {:?}", secret.as_bytes())


    }
    Ok(())
}
