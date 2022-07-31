/*use openssl_sys::{
    BN_bin2bn, BN_bn2bin, BN_num_bits, DH_compute_key, DH_free, DH_generate_key, DH_get0_pub_key,
    ERR_get_error, ERR_reason_error_string, DH,
};*/
use std::convert::TryInto;
use std::ffi::CStr;
use std::ptr::null_mut;
use openssl::bn::BigNum;
use openssl::dh::Dh;
use openssl::pkey::{Params, Private};

//TODO: not send/sync
pub struct KeyPair {
    dh: Dh<Private>,
    pub public_key: Vec<u8>,
}

impl KeyPair {
    pub fn new() -> Self {
        // Gen our key pair
        let dh = Dh::get_1024_160().unwrap();
        let dh = dh.generate_key().unwrap();
        let public_key = dh.public_key();
        let public_key_bytes = public_key.to_vec();



       /* openssl_sys::init();

        // Gen our key pair
        let (dh, public_key) = unsafe {
            use openssl_sys::DH_get_1024_160;
            let dh = DH_get_1024_160();

            chk(DH_generate_key(dh)).expect("generate key");

            let our_public_key = chk2(DH_get0_pub_key(dh)).expect("Get public key");

            (dh, our_public_key)
        };*/

        // Convert our public key to a byte array
        /*let public_key_bytes = unsafe {
            let public_key_size = (BN_num_bits(public_key) + 7) / 8;

            let mut output_buffer = Vec::new();
            output_buffer.resize(public_key_size.try_into().unwrap(), 0u8);
            chk(BN_bn2bin(public_key, output_buffer.as_mut_ptr())).expect("public key -> bytes");

            output_buffer
        };*/

        Self {
            dh,
            public_key: public_key_bytes,
        }
    }

    // Move self so that DH instance can't be reused
    pub fn derive_shared_key(self, their_key_bytes: Vec<u8>) -> Vec<u8> {
        // load their key

        let public_key_bignum = BigNum::from_slice(&their_key_bytes).unwrap();
        let shared_key = self.dh.compute_key(&public_key_bignum).unwrap();
        println!("Shared key = {:?}", shared_key);


        /*let shared_key = unsafe {
            let len = their_key_bytes.len();
            let their_pub_key = BN_bin2bn(their_key_bytes.as_ptr(), len as i32, null_mut());

            let mut out = Vec::new();
            out.resize(0x80, 0u8);
            DH_compute_key(out.as_mut_ptr(), their_pub_key, self.dh);
            DH_free(self.dh);

            println!("Shared key = {:?}", out);

            out
        };*/

        shared_key
    }
}

/*fn chk2<T>(rval: *mut T) -> Result<*mut T, String> {
    unsafe {
        if rval.is_null() {
            println!("RVal is null");
            let x = ERR_get_error();
            println!("Got err = {}", x);
            let y = ERR_reason_error_string(x);
            println!("Got err str = {}", x);
            let z = CStr::from_ptr(y);
            println!("err = {}", z.to_string_lossy());

            return Err(z.to_string_lossy().to_string());
        }
    }

    Ok(rval)
}*/

/*fn chk(rval: i32) -> Result<(), String> {
    unsafe {
        if rval <= 0 {
            println!("RVal {} is <= 0", rval);
            let x = ERR_get_error();
            println!("Got err = {}", x);
            let y = ERR_reason_error_string(x);
            println!("Got err str = {}", x);
            if !y.is_null() {
                let z = CStr::from_ptr(y);
                println!("err = {}", z.to_string_lossy());
                return Err(z.to_string_lossy().to_string());
            }

            return Err("No error message available".to_string());
        }
    }

    Ok(())
}*/
