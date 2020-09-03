use crate::session_key_components::{Decode, Encode};
use cookie_factory::bytes::be_u8;
use cookie_factory::{GenResult, WriteContext};
use enumset::EnumSet;
use nom::IResult;
use std::convert::TryInto;
use std::io::Write;

#[derive(Debug, EnumSetType)]
pub enum PacketFlag {
    TimeCritical,
    TimeCriticalReverse,
    TimestampPresent,
    TimestampEchoPresent,
}

#[repr(u8)]
#[derive(Debug, TryFromPrimitive, Copy, Clone)]
pub enum PacketMode {
    Initiator = 1,
    Responder = 2,
    Startup = 3,
}

#[derive(Debug)]
pub struct PacketFlags {
    pub flags: EnumSet<PacketFlag>,
    // pub reserved: u8,
    pub mode: PacketMode,
}

impl PacketFlags {
    pub fn new(mode: PacketMode, flags: EnumSet<PacketFlag>) -> Self {
        Self {
            flags,
            mode,
            // reserved: 0
        }
    }
}

impl<T: Write> Encode<T> for PacketFlags {
    fn encode(&self, w: WriteContext<T>) -> GenResult<T> {
        let mut flags = 0u8;

        if self.flags.contains(PacketFlag::TimeCritical) {
            flags |= 0b1000_0000;
        }

        if self.flags.contains(PacketFlag::TimeCriticalReverse) {
            flags |= 0b0100_0000;
        }

        if self.flags.contains(PacketFlag::TimestampPresent) {
            flags |= 0b0000_1000;
        }

        if self.flags.contains(PacketFlag::TimestampEchoPresent) {
            flags |= 0b0000_0100;
        }

        let mode = self.mode as u8;
        flags |= (mode & 0b0000_0011);

        println!("Flags = {}", flags);

        be_u8(flags)(w)
    }
}

impl Decode for PacketFlags {
    fn decode(i: &[u8]) -> IResult<&[u8], Self> {
        let (i, packed_flags) = nom::number::complete::be_u8(i)?;

        let mode: PacketMode = (packed_flags & 0b0000_0011).try_into().unwrap();
        let mut flags = EnumSet::empty();

        if packed_flags & 0b1000_0000 != 0 {
            flags |= PacketFlag::TimeCritical;
        }

        if packed_flags & 0b0100_0000 != 0 {
            flags |= PacketFlag::TimeCriticalReverse;
        }

        if packed_flags & 0b0000_1000 != 0 {
            flags |= PacketFlag::TimestampPresent;
        }

        if packed_flags & 0b0000_0100 != 0 {
            flags |= PacketFlag::TimestampEchoPresent;
        }

        let pf = Self { mode, flags };

        Ok((i, pf))
    }
}
