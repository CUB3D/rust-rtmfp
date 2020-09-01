use cookie_factory::bytes::be_u8;
use cookie_factory::SerializeFn;
use std::io::Write;

#[derive(Debug, Copy, Clone)]
pub struct VLU {
    pub length: u8,
    pub value: u64,
}

impl VLU {
    pub fn decode(i: &[u8]) -> nom::IResult<&[u8], Self> {
        let mut value: u64 = 0;
        let mut pos = 0;

        let mut i = i;
        loop {
            let (j, v) = nom::number::complete::be_u8(i)?;
            i = j;

            value *= 128;
            value += (v & 0b01111111) as u64;
            pos += 1;

            if v & 0b10000000 == 0 {
                break;
            }
        }

        let vlu = Self {
            length: pos as u8,
            value,
        };

        Ok((i, vlu))
    }

    pub fn encode<'a, W: Write + 'a>(&'a self) -> impl SerializeFn<W> + 'a {
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

impl From<VLU> for u64 {
    fn from(value: VLU) -> Self {
        value.value
    }
}
