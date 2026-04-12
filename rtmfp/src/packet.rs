use crate::chunk::Chunk;
use crate::packet_flags::{PacketFlag, PacketFlags};
use crate::session_key_components::Decode;
use parse::{GenerateBytes, SliceWriter};

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

#[cfg(test)]
pub mod test {
    use crate::packet_flags::{PacketFlag, PacketFlags, PacketMode};
    use parse::{GenerateBytes, SliceWriter, VecSliceWriter};
    use crate::packet::Packet;

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
}