use cookie_factory::bytes::be_u8;
use cookie_factory::{GenResult, WriteContext};
use std::io::Write;

pub trait Encode<W> {
    fn encode(&self, w: WriteContext<W>) -> GenResult<W>;
}
impl<W: Write, T: Encode<W>> Encode<W> for Vec<T> {
    fn encode(&self, w: WriteContext<W>) -> GenResult<W> {
        cookie_factory::multi::all(self.iter().map(|t| move |out| t.encode(out)))(w)
    }
}
impl<T: Write> Encode<T> for u8 {
    fn encode(&self, w: WriteContext<T>) -> GenResult<T> {
        be_u8(*self)(w)
    }
}

pub trait StaticEncode {
    fn encode_static(&self) -> Vec<u8>;
}
