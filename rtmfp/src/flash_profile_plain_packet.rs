use crate::session_key_components::Decode;
use crate::{checksum};
use parse::{GenerateBytes, SliceWriter, VecSliceWriter};
use crate::packet::Packet;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct FlashProfilePlainPacket {
    pub session_sequence_number: u8,
    pub checksum: u16,
    pub packet: Packet,
}
impl FlashProfilePlainPacket {
    pub fn encode(&self) -> Vec<u8> {
        let mut sw1 = VecSliceWriter::default();
        self.packet.generate(&mut sw1);

        let checksum = checksum::checksum(sw1.as_slice());

        tracing::debug!("checksum = {}", checksum);

        let mut sw = VecSliceWriter::default();
        sw.be_u16(checksum);
        sw.put(sw1.as_slice());
        //TODO: helper for this
        sw.as_slice().to_vec()
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

#[cfg(test)]
pub mod test {
    use crate::flash_profile_plain_packet::FlashProfilePlainPacket;
    use crate::packet::Packet;
    use crate::packet_flags::{PacketFlag, PacketFlags, PacketMode};
    use crate::session_key_components::Decode;

    #[test]
    pub fn flash_profiler_plain_packet_round_trip() {
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
                chunks: Vec::new(),
            },
        };
        let enc = packet.encode();
        let (i, dec) = FlashProfilePlainPacket::decode(&enc).unwrap();
        assert_eq!(dec, packet);
        assert_eq!(i, &[]);
    }
}
