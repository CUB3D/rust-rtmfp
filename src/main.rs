use cookie_factory::bytes::{be_u16, be_u32, be_u8};
use cookie_factory::multi::all;
use cookie_factory::sequence::tuple;
use cookie_factory::{gen, SerializeFn};
use std::io::Write;
use std::net::UdpSocket;

use aes::Aes128;
use block_modes::block_padding::NoPadding;
use block_modes::{BlockMode, Cbc};
use cookie_factory::combinator::cond;
use enumset::EnumSet;

type Aes128Cbc = Cbc<Aes128, NoPadding>;

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

#[derive(Debug)]
pub struct VLU {
    pub length: u8,
    pub value: u64,
}

impl VLU {
    fn from(d: &[u8]) -> Self {
        let mut value: u64 = 0;
        let mut pos = 0;

        loop {
            let v = d[pos];

            value *= 128;
            value += (v & 0b01111111) as u64;

            if v & 0b10000000 == 0b10000000 {
                break;
            }
            pos += 1;
        }

        Self {
            length: pos as u8,
            value,
        }
    }

    fn encode<'a, W: Write + 'a>(&'a self) -> impl SerializeFn<W> + 'a {
        be_u8((self.value & 0xFF) as u8)
    }
}

impl From<u8> for VLU {
    fn from(value: u8) -> Self {
        Self {
            length: 1,
            value: value as u64,
        }
    }
}

#[derive(Debug)]
pub struct IIKeyingChunkBody {
    pub initiator_session_id: u32,
    pub cookie_length: VLU,
    pub cookie_echo: Vec<u8>,
    pub cert_length: VLU,
    pub initiator_certificate: Vec<u8>,
    pub skic_length: VLU,
    pub session_key_initiator_component: Vec<u8>,
    pub signature: Vec<u8>,
}

impl IIKeyingChunkBody {
    fn encode<'a, W: Write + 'a>(&'a self) -> impl SerializeFn<W> + 'a {
        tuple((
            be_u32(self.initiator_session_id),
            self.cookie_length.encode(),
            encode_raw(&self.cookie_echo),
            self.cert_length.encode(),
            encode_raw(&self.initiator_certificate),
            self.skic_length.encode(),
            encode_raw(&self.session_key_initiator_component),
            encode_raw(&self.signature),
        ))
    }
}

#[derive(Debug)]
pub struct RHelloChunkBody {
    pub tag_length: u8,
    pub tag_echo: Vec<u8>,
    pub cookie_length: u8,
    pub cookie: Vec<u8>,
    pub responder_certificate: Vec<u8>,
}

#[derive(Debug)]
pub enum ChunkContent {
    Raw(Vec<u8>),
    RHello(RHelloChunkBody),
    IIKeying(IIKeyingChunkBody),
}

fn encode_raw<'a, 'b: 'a, W: Write + 'a>(v: &'b [u8]) -> impl SerializeFn<W> + 'a {
    all(v.iter().map(move |p| be_u8(*p)))
}

impl ChunkContent {
    fn encode<'a, W: Write + 'a>(&'a self) -> impl SerializeFn<W> + 'a {
        move |out| match self {
            ChunkContent::Raw(v) => encode_raw(v)(out),
            ChunkContent::RHello(body) => unimplemented!(),
            ChunkContent::IIKeying(body) => body.encode()(out),
            _ => unimplemented!(),
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
        let v = vec![];
        let (bytes, size) = gen(self.payload.encode(), v).unwrap();

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
        if chunk_type == ChunkType::ResponderHello as u8 {
            let (j, tag_length) = nom::number::complete::be_u8(i)?;
            let (j, tag_echo) = nom::bytes::complete::take(tag_length)(j)?;

            let (j, cookie_length) = nom::number::complete::be_u8(j)?;
            let (j, cookie) = nom::bytes::complete::take(cookie_length)(j)?;

            let cert_len = chunk_length - tag_length as u16 - cookie_length as u16 - 1 - 1;
            let (j, certificate) = nom::bytes::complete::take(cert_len)(j)?;

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
                        responder_certificate: certificate.to_vec(),
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

// pub enum PacketFlag {
//     TimeCritical,
//     TimeCriticalReverse,
//     TimestampPresent,
//     TimestampEchoPresent,
// }
//
// #[derive(Debug)]
// pub struct PacketFlags {
//     pub flags: EnumSet<PacketFlag>,
//     pub reserved: u8,
//     pub mode: u8,
// }

#[derive(Debug)]
pub struct Packet {
    pub flags: u8,
    pub timestamp: Option<u16>,
    pub timestamp_echo: Option<u16>,
    pub chunks: Vec<Chunk>,
}

impl Packet {
    pub fn encode<'a, W: Write + 'a>(&'a self) -> impl SerializeFn<W> + 'a {
        //TODO: only send timestamp when TS is set
        tuple((
            be_u8(self.flags),
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
        let (i, flags) = nom::number::complete::be_u8(i)?;

        let mut i = i;

        let mut timestamp = None;
        let mut timestamp_echo = None;

        if flags & 0b0000_1000 == 0b0000_1000 {
            let (j, ts) = nom::number::complete::be_u16(i)?;
            timestamp = Some(ts);
            i = j;
        }

        if flags & 0b0000_0100 == 0b0000_0100 {
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

        let mut simple_checksum: i32 = bytes
            .chunks(2)
            .map(|pair| {
                let first = pair[0] as u16;

                let val = if let Some(second) = pair.get(1).map(|v| *v as u16) {
                    (first << 8) | second
                } else {
                    first
                } as i32;

                val
            })
            .sum::<i32>();

        let combined: u16 = !((simple_checksum >> 16) as u16 + (simple_checksum & 0xFFFF) as u16);

        tuple((be_u16(combined), self.packet.encode()))
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

                let key = "Adobe Systems 02".as_bytes();
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
            println!("ssid {}", scrambled_session_id);

            let x = tuple((be_u32(scrambled_session_id), encode_raw(&bytes)))(out);

            x
        }
    }

    pub fn decode(i: &[u8]) -> nom::IResult<&[u8], Self> {
        let (i, scrambled_session_id) = nom::number::complete::be_u32(i)?;

        let mut mut_i = i.to_vec();

        // i must be decrypted

        use block_modes::BlockMode;
        let key = "Adobe Systems 02".as_bytes();
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
        let v = vec![];
        let (bytes, _s2) = gen(m.encode(encypted), v).unwrap();
        self.socket.send(&bytes).unwrap();
    }

    pub fn read(&self) -> Multiplex {
        let mut buf = [0; 1024];
        let (amt, src) = self.socket.recv_from(&mut buf).unwrap();
        println!("Got response of size {} = {:?}", amt, buf);
        // Crop the buffer to the size of the packet
        let buf = &buf[..amt];
        let (_i, m) = Multiplex::decode(buf).unwrap();

        m
    }
}

fn main() -> std::io::Result<()> {
    {
        let stream = RTMFPStream::new();

        // let socket = UdpSocket::bind("127.0.0.1:2020")?;
        //
        // socket.connect("127.0.0.1:1935").unwrap();

        let m = Multiplex {
            session_id: 0,
            packet: vec![FlashProfilePlainPacket {
                session_sequence_number: 0,
                checksum: 0,
                packet: Packet {
                    flags: 0b0_0_00_1_0_11,
                    timestamp: Some(0),
                    timestamp_echo: None,
                    chunks: vec![Chunk {
                        chunk_type: 0x30,
                        chunk_length: 7,
                        payload: ChunkContent::Raw(vec![2, 0xa, 0xa, 65, 66, 67, 68]),
                    }],
                },
            }],
        };

        stream.send(m, false);

        let m2 = stream.read();

        let m = Multiplex {
            session_id: 0,
            packet: vec![FlashProfilePlainPacket {
                session_sequence_number: 0,
                checksum: 0,
                packet: Packet {
                    flags: 0b0_0_00_1_0_11,
                    timestamp: Some(0),
                    timestamp_echo: None,
                    chunks: vec![Chunk {
                        chunk_type: ChunkType::InitiatorInitialKeying as u8,
                        chunk_length: 7,
                        payload: ChunkContent::IIKeying(IIKeyingChunkBody {
                            initiator_session_id: 0,
                            cookie_length: 64.into(),
                            cookie_echo:
                                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                                    .as_bytes()
                                    .to_vec(),
                            cert_length: 0.into(),
                            initiator_certificate: vec![],
                            skic_length: 0.into(),
                            session_key_initiator_component: vec![],
                            signature: vec![],
                        }),
                    }],
                },
            }],
        };

        stream.send(m, true);

        println!("Got multiplex response: {:?}", m2);
    }
    Ok(())
}
