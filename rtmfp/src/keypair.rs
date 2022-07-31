use std::convert::TryInto;
use std::ffi::CStr;
use std::ptr::null_mut;
use openssl::bn::BigNum;
use openssl::dh::Dh;
use openssl::pkey::{Params, Private};

pub struct KeyPair {
    dh: Dh<Private>,
    pub public_key: Vec<u8>,
}

impl KeyPair {
    /// Generate a new diffie-hellman keypair
    pub fn new() -> Self {
        let dh = Dh::get_1024_160().unwrap();
        let dh = dh.generate_key().unwrap();
        let public_key = dh.public_key();
        let public_key_bytes = public_key.to_vec();

        Self {
            dh,
            public_key: public_key_bytes,
        }
    }

    /// Construct the shared key, using the public key from the other party
    pub fn derive_shared_key(self, their_key_bytes: Vec<u8>) -> Vec<u8> {
        let public_key_bignum = BigNum::from_slice(&their_key_bytes).unwrap();
        let shared_key = self.dh.compute_key(&public_key_bignum).unwrap();
        shared_key
    }
}
