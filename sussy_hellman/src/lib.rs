//! DO NOT USE THIS LIBRARY!
//!
//! (No, I'm serious!)
//!
//! This is an intentionally vulnerable implementation of Diffie-Hellman for use within RTMFP
//! It is buggy, insecure and SHOULD NOT BE USED, EVER
//! ... Except when you want to communicate with ancient, buggy, insecure servers
//!
//! The primary use-case for this library is to generate the shared secret as part of the RTMFP
//! handshake, which when using the Flash Profile requires the use of a specific set of
//! Diffie-Hellman parameters.
//!
//! While it is possible to use {open,boring,etc}SSL, these often prevent the use of insecure public
//! keys for key generation, such as the ones often provided by RTMFP server implementations
//! (see ossl_ffc_validate_public_key_partial in openSSL for some examples).
//! Hence, this library exists
//!

#![deny(missing_docs)]

extern crate core;

use num_bigint::BigUint;
use num_traits::{Num, ToPrimitive};
use rand::prelude::StdRng;
use rand::{Rng, SeedableRng};

#[derive(Clone)]
/// The shared parameters used to generate the keys
pub struct KeyPairParams {
    /// The group order
    group_order: BigUint,
    /// The prime modulus
    prime_modulus: BigUint,
}

impl KeyPairParams {
    /// Generate the keypair params used by flash for RTMFP communication
    pub fn new_flash() -> Self {
        let p = BigUint::from_str_radix("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF", 16).unwrap();
        let g = BigUint::from(2_u8);

        Self {
            group_order: g,
            prime_modulus: p,
        }
    }
}

#[derive(Clone)]
/// A Diffie-Hellman keypair
pub struct KeyPair {
    /// The shared parameters
    params: KeyPairParams,
    /// The secret key
    secret: BigUint,
    /// The public key
    pub public: BigUint,
}

impl KeyPair {
    /// Generate a Diffie-Hellman keypair
    /// Note that the upper bound for secret generation is [u128::MAX] due to limitations in `rand`
    pub fn generate(params: KeyPairParams) -> KeyPair {
        // Get a cryptographically secure source of randomness
        let mut rng = StdRng::from_entropy();

        // The secret in DH must be [1..p-2]
        let secret_upper_bound: BigUint = &params.prime_modulus - BigUint::from(2u8);
        // This is technically bad because we will be limiting our upper bound to u128::MAX
        // But seeing as this entire implementation isn't secure anyway (see module level docs for why this exists)
        // This should be fine
        let secret_upper_bound = secret_upper_bound
            .min(BigUint::from(u128::MAX))
            .to_u128()
            .unwrap();

        // Generate a random secret
        let random_secret = rng.gen_range(1u128..secret_upper_bound);
        let secret = BigUint::from(random_secret);

        Self::generate_with_secret(params, secret)
    }

    /// Internal version of [generate] for use in tests
    pub(crate) fn generate_with_secret(params: KeyPairParams, secret: BigUint) -> KeyPair {
        // Generate the public key (A = (g^a) % p)
        let public = params.group_order.modpow(&secret, &params.prime_modulus);

        // Produce a generated keypair
        KeyPair {
            params,
            secret,
            public,
        }
    }

    /// Compute the shared secret
    pub fn compute_key(&self, other_public_key: &BigUint) -> BigUint {
        // Compute the shared key (k_AB = (B^a) % p)
        other_public_key.modpow(&self.secret, &self.params.prime_modulus)
    }
}

#[cfg(test)]
mod tests {
    use crate::{KeyPair, KeyPairParams};
    use num_bigint::{BigUint as Number, BigUint};
    use num_traits::Num;

    #[test]
    fn it_works() {
        let params = KeyPairParams::new_flash();
        let keypair = KeyPair::generate_with_secret(params, BigUint::from(10u8));

        println!("Our public key hex = {}", keypair.public.to_str_radix(16));

        let other_key = Number::from_str_radix("9B32965DCFE21D6372CEB3DA4B8341B0851CE32910770734CD91D82CB628ED5730B2EF68E83B75A5C74E93D5CA263629B3348E904AEF395C6D74A5F6C33495F20D1A2953059493C5B6C4E8A447190D73D8C904B091145E64BBA6C5DEB4B86E8E85DA133CC67DFC167AFA839A360BEC1E54FAE1B157CB26EF80B192DF8F7679B0", 16).unwrap();

        let k_ab = keypair.compute_key(&other_key);

        println!("Secret hex = {}", k_ab.to_str_radix(16));

        let expected_key = Number::from_str_radix("04A7E608DEA1B1F36CFD5AFF62DAC7C36820891D484897261DF258910C63ECC8596980778090B2B16C2563373B4635BA8372483A4945C4B06BE85A20C928472ADFCD7901EA405A62BB2FFD1D151DA036D4AC7F0A700DFF93A3DDC1701B7CE17681042B97AE53065667DF8A5E9F7438218846D823FAB2D839F009A6B630A67898", 16).unwrap();
        assert_eq!(expected_key, k_ab);
    }
}
