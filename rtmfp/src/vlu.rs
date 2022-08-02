use cookie_factory::bytes::be_u8;
use cookie_factory::SerializeFn;
use std::io::Write;
use cookie_factory::sequence::tuple;
use crate::encode_raw;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
/// RFC7016[2.1.2], Variable Length Unsigned Integer
pub struct VLU {
    /// The number of bytes in the VLU
    pub length: u8,
    /// The value of the VLU
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

    pub fn encode<'a, W: Write + 'a>(&'a self) -> impl SerializeFn<W> + 'a {

        let mut bytes = Vec::new();

        if self.value < 0x80 {
            bytes.push(self.value as u8);
        } else if self.value >= 0x80 && self.value < 8192 {
            bytes.push((((self.value >> 7) & 0b0111_1111) | 0b1000_0000) as u8);
            bytes.push((self.value & 0b0111_1111) as u8);
        } else {
            panic!()
        };

        // printlnt!("bytes of {} = {:?}", self.value, bytes);
        let (_, x) = Self::decode(bytes.as_slice()).unwrap();
        assert_eq!(x.value, self.value);

        return move |out| {
            encode_raw(&bytes)(out)
        }

        /*return move |out| {
            if self.value & 0b1000_0000 != 0 {
                let t = &[(self.value & 0b1111_1111) as u8, ((self.value >> 7) & 0b0111_1111) as u8];
                let x = Self::decode(t.as_slice()).unwrap();
                println!("{} = {}", self.value, x.1.value);

                tuple((be_u8(((self.value & 0b0111_1111) | 0b1000_0000) as u8), be_u8(((self.value >> 8) & 0b0111_1111) as u8)))(out)
            } else {
                be_u8((self.value & 0b0111_1111) as u8)(out)
            }
        };*/


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
