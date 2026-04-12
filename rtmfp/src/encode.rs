pub trait StaticEncode {
    fn encode_static(&self) -> Vec<u8>;
}
