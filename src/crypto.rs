pub mod crypto {
    use aes::cipher::{
        block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, InvalidLength, KeyIvInit,
    };
    use hkdf::Hkdf;
    use hmac::{Hmac, Mac};
    use rand::rngs::OsRng;
    use sha2::Sha512;
    use std::fmt;
    pub use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};
    use zeroize::Zeroize;

    const BLOCK_SIZE: usize = 32;
    type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
    type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
    type Key32 = [u8; 32];
    type Key16 = [u8; 16];

    #[derive(Debug, Clone, PartialEq)]
    pub struct CryptoError;
    impl fmt::Display for CryptoError {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "crypto error")
        }
    }

    // Curve25519 key pair
    pub struct KeyPair {
        private: StaticSecret,
        public: PublicKey,
    }

    impl KeyPair {
        // generate a random key pair
        pub fn generate() -> Self {
            let sk = StaticSecret::new(OsRng);
            Self {
                public: PublicKey::from(&sk),
                private: sk,
            }
        }

        #[inline]
        // dump public key
        pub fn public(&self) -> PublicKey {
            self.public
        }

        #[inline]
        // zero private key
        pub fn zero(&mut self) {
            self.private.zeroize();
        }

        #[inline]
        // run x25519 ECDH key exchange
        // see: https://datatracker.ietf.org/doc/html/rfc7748
        pub fn dh(&self, pk: PublicKey) -> SharedSecret {
            self.private.diffie_hellman(&pk)
        }
    }

    // derive a 32 byte root key and chain key
    pub fn kdf_rk(rk: &Key32, dh_out: &Key32) -> Result<(Key32, Key32), hkdf::InvalidLength> {
        let mut okm = [0u8; 64];

        let hk = Hkdf::<Sha512>::new(Some(rk), dh_out);
        hk.expand(b"ratchet-hkdf-sha512", &mut okm)?;

        let (root_key, chain_key) = okm.split_at(32);

        Ok((root_key.try_into().unwrap(), chain_key.try_into().unwrap()))
    }

    // derive a 32 byte chain key and message key
    pub fn kdf_ck(ck: &Key32) -> Result<(Key32, Key32), InvalidLength> {
        let mut mac = Hmac::<Sha512>::new_from_slice(ck)?;
        mac.update(b"ratchet-hmac-sha512");

        let res = mac.finalize().into_bytes();
        let (chain_key, msg_key) = res.split_at(32);

        Ok((chain_key.try_into().unwrap(), msg_key.try_into().unwrap()))
    }

    // derive a 32 byte encryption key, authentication key, and a 16 byte IV
    pub fn kdf_aes(mk: &[u8]) -> Result<(Key32, Key32, Key16), hkdf::InvalidLength> {
        let salt = [0u8; 64];
        let mut okm = [0u8; 80];

        let hk = Hkdf::<Sha512>::new(Some(&salt), mk);
        hk.expand(b"ratchet-hkdf-sha512-aes256", &mut okm)?;

        let (enc_key, rest) = okm.split_at(32);
        let (auth_key, iv) = rest.split_at(32);

        Ok((
            enc_key.try_into().unwrap(),  // 32 byte enc key
            auth_key.try_into().unwrap(), // 32 byte auth key
            iv.try_into().unwrap(),       // 16 byte IV
        ))
    }

    // encrypt pt under mk and append an auth tag
    pub fn encrypt(mk: &[u8], pt: &[u8], data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let (enc_key, auth_key, iv) = kdf_aes(mk).or_else(|e| Err(CryptoError))?;
        let pt_len = pt.len();
        let mut buf = vec![0u8; pt_len + (BLOCK_SIZE - pt_len % BLOCK_SIZE)];
        buf[..pt_len].copy_from_slice(&pt);

        let ct = Aes256CbcEnc::new(&enc_key.into(), &iv.into())
            .encrypt_padded_mut::<Pkcs7>(&mut buf, pt_len)
            .or_else(|e| Err(CryptoError))?;

        let mut mac = Hmac::<Sha512>::new_from_slice(&auth_key).or_else(|e| Err(CryptoError))?;
        mac.update(data);
        let auth_tag: [u8; 64] = mac.finalize().into_bytes().try_into().unwrap();

        Ok([ct, &auth_tag].concat())
    }

    // decrypt ct under mk and verify auth tag
    pub fn decrypt(mk: &[u8], ct: &mut [u8], data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let payload_len = ct.len() - 64;
        let (payload, auth_tag) = ct.split_at_mut(payload_len);
        let (enc_key, auth_key, iv) = kdf_aes(mk).or_else(|e| Err(CryptoError))?;

        let mut mac = Hmac::<Sha512>::new_from_slice(&auth_key).or_else(|e| Err(CryptoError))?;
        mac.update(data);
        mac.verify_slice(auth_tag).unwrap();

        let pt = Aes256CbcDec::new(&enc_key.into(), &iv.into())
            .decrypt_padded_mut::<Pkcs7>(payload)
            .or_else(|e| Err(CryptoError))?;

        Ok(pt.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand::RngCore;

    #[test]
    fn test_keygen() {
        let k1 = crypto::KeyPair::generate();
        let k2 = crypto::KeyPair::generate();

        let k1_pub = k1.public();
        let shared_secret_1 = k1.dh(k2.public());
        let shared_secret_2 = k2.dh(k1_pub);
        assert_eq!(shared_secret_1.as_bytes(), shared_secret_2.as_bytes());
    }

    #[test]
    fn test_enc_valid() {
        for _ in 0..(1 << 10) {
            let size = rand::random::<usize>() % (1 << 10) + 1;
            let mut payload = vec![0u8; size];
            rand::thread_rng().fill_bytes(&mut payload);

            let mut mk = vec![0u8; 32];
            rand::thread_rng().fill_bytes(&mut mk);

            let mut data = vec![0u8; 32];
            rand::thread_rng().fill_bytes(&mut data);

            let mut ct = crypto::encrypt(&mut mk, &mut payload, &mut data).unwrap();
            let pt = crypto::decrypt(&mut mk, &mut ct, &mut data).unwrap();
            assert_eq!(pt, payload);
        }
    }

    #[test]
    #[should_panic]
    fn test_enc_invalid_auth_tag() {
        for _ in 0..(1 << 10) {
            let size = rand::random::<usize>() % (1 << 10) + 1;
            let mut payload = vec![0u8; size];
            rand::thread_rng().fill_bytes(&mut payload);

            let mut mk = vec![0u8; 32];
            rand::thread_rng().fill_bytes(&mut mk);

            let mut data = vec![0u8; 32];
            rand::thread_rng().fill_bytes(&mut data);

            let mut ct = crypto::encrypt(&mut mk, &mut payload, &mut data).unwrap();
            let pt = crypto::decrypt(&mut mk, &mut ct, &mut data).unwrap();
            assert_eq!(pt, payload);

            let ct_len = ct.len();
            let offset = rand::random::<usize>() % 64;
            ct[ct_len - offset - 1] ^= 0xff; // flip a random byte
            crypto::decrypt(&mut mk, &mut ct, &mut data).unwrap(); // auth should fail
        }
    }
}
