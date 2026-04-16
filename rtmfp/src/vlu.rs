use crate::error::RtmfpError;
use parse::{ne_u8, GenerateBytes, ParseBytes, SliceWriter};

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
/// RFC7016[2.1.2], Variable Length Unsigned Integer
pub struct VLU {
    /// The number of bytes in the VLU
    pub length: u8,
    /// The value of the VLU
    pub value: u64,
}

impl ParseBytes<'_> for VLU {
    type Error = RtmfpError;

    fn parse(i: &[u8]) -> Result<(&[u8], Self), Self::Error>
    where
        Self: Sized
    {
        let mut value: u64 = 0;
        let mut pos = 0;

        let mut i = i;
        loop {
            let (j, v) = ne_u8(i)?;
            i = j;

            value *= 128;
            value += (v & 0b0111_1111) as u64;
            pos += 1;
            if v & 0b1000_0000 == 0 {
                break;
            }
        }

        let vlu = Self {
            length: pos as u8,
            value,
        };

        Ok((i, vlu))
    }
}

impl GenerateBytes for VLU {
    fn generate<'b>(&'b self, sw: &'b mut impl SliceWriter) {

        if self.value < 0x80 {
            sw.ne_u8(self.value as u8);
        } else if self.value >= 0x80 && self.value < 0x2000 {
            sw.ne_u8((((self.value >> 7) & 0b0111_1111) | 0b1000_0000) as u8);
            sw.ne_u8((self.value & 0b0111_1111) as u8);
        } else {
            panic!()
        };
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

impl From<usize> for VLU {
    fn from(value: usize) -> Self {
        if value < 0xFF {
            (value as u8).into()
        } else {
            unimplemented!()
        }
    }
}

impl From<i32> for VLU {
    fn from(value: i32) -> Self {
        if value < 0xFF {
            (value as u8).into()
        } else {
            unimplemented!()
        }
    }
}

impl From<VLU> for u64 {
    fn from(value: VLU) -> Self {
        value.value
    }
}
