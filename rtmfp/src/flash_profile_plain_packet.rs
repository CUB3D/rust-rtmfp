use crate::encode::Encode;
use crate::session_key_components::Decode;
use crate::{checksum, Packet};
use cookie_factory::bytes::be_u16;
use cookie_factory::gen;
use cookie_factory::sequence::tuple;
use cookie_factory::{GenResult, WriteContext};
use std::io::Write;

#[derive(Debug, Clone)]
pub struct FlashProfilePlainPacket {
    pub session_sequence_number: u8,
    pub checksum: u16,
    pub packet: Packet,
}

impl<T: Write> Encode<T> for FlashProfilePlainPacket {
    fn encode(&self, w: WriteContext<T>) -> GenResult<T> {
        let v = vec![];
        let (bytes, _size): (Vec<u8>, u64) = gen(self.packet.encode(), v).unwrap();

        let checksum = checksum::checksum(&bytes);

        tuple((be_u16(checksum), self.packet.encode()))(w)
    }
}

impl Decode for FlashProfilePlainPacket {
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
