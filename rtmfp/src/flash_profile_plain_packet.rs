use crate::encode::Encode;
use crate::session_key_components::Decode;
use crate::{checksum, Packet};
use cookie_factory::bytes::be_u16;
use cookie_factory::gen;
use cookie_factory::sequence::tuple;
use cookie_factory::{GenResult, WriteContext};
use std::io::Write;

#[derive(Debug, Clone, Eq, PartialEq)]
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

        println!("CHK = {}", checksum);

        tuple((be_u16(checksum), self.packet.encode()))(w)
    }
}
static_encode!(FlashProfilePlainPacket);
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

#[cfg(test)]
pub mod test {
    use crate::endpoint_discriminator::AncillaryDataBody;
    use crate::flash_certificate::FlashCertificate;
    use crate::packet::PacketMode;
    use crate::session_key_components::SessionKeyingComponent;
    use crate::{
        Decode, FlashProfilePlainPacket, Packet, PacketFlag, PacketFlags,
        ResponderInitialKeyingChunkBody, StaticEncode,
    };

    #[test]
    pub fn flash_profiler_plain_packet_roundtrip() {
        let packet = FlashProfilePlainPacket {
            session_sequence_number: 0,
            checksum: 32511,
            packet: Packet {
                flags: PacketFlags {
                    flags: PacketFlag::TimeCritical.into(),
                    mode: PacketMode::Initiator,
                },
                timestamp: None,
                timestamp_echo: None,
                chunks: vec![],
            },
        };
        let enc = packet.encode_static();
        let (i, dec) = FlashProfilePlainPacket::decode(&enc).unwrap();
        assert_eq!(dec, packet);
        assert_eq!(i, &[]);
    }
}
