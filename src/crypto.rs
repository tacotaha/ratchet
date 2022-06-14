pub mod crypto {
    use aes_gcm_siv::aead::{Aead, NewAead};
    use aes_gcm_siv::{Aes256GcmSiv, Key, Nonce};
    use hkdf::Hkdf;
    use hmac::{Hmac, Mac};
    use rand::RngCore;
    use sha2::Sha512;
    use std::fmt;
    pub use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};
    use zeroize::Zeroize;

    type Key32 = [u8; 32];

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
            let sk = StaticSecret::new(rand::thread_rng());
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

    // derive a 32 byte root key, chain key, and next header key
    pub fn kdf_rk(
        rk: &Key32,
        dh_out: &Key32,
    ) -> Result<(Key32, Key32, Key32), hkdf::InvalidLength> {
        let mut okm = [0u8; 0x60];
        let hk = Hkdf::<Sha512>::new(Some(rk), dh_out);
        hk.expand(b"ratchet-hkdf-sha512", &mut okm)?;
        let (root_key, rest) = okm.split_at(32);
        let (chain_key, next_header_key) = rest.split_at(32);
        Ok((
            root_key.try_into().unwrap(),
            chain_key.try_into().unwrap(),
            next_header_key.try_into().unwrap(),
        ))
    }

    // derive a 32 byte chain key and message key
    pub fn kdf_ck(ck: &Key32) -> Result<(Key32, Key32), hmac::digest::InvalidLength> {
        let mut mac = Hmac::<Sha512>::new_from_slice(ck)?;
        mac.update(b"ratchet-hmac-sha512");
        let res = mac.finalize().into_bytes();
        let (chain_key, msg_key) = res.split_at(32);
        Ok((chain_key.try_into().unwrap(), msg_key.try_into().unwrap()))
    }

    // encrypt pt under hk and append a 96 bit nonce
    pub fn encrypt(hk: &[u8], pt: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut nonce = [0u8; 12]; // 96-bit nonce
        rand::thread_rng().fill_bytes(&mut nonce);
        let key = Key::from_slice(hk);
        let cipher = Aes256GcmSiv::new(key);
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce), pt)
            .or_else(|_| Err(CryptoError))?;
        Ok([ct, nonce.to_vec()].concat())
    }

    // decrypt ct under hk
    pub fn decrypt(hk: &[u8], ct: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let (payload, nonce) = ct.split_at(ct.len() - 12); // parse 96-bit nonce
        let key = Key::from_slice(hk);
        let cipher = Aes256GcmSiv::new(key);
        let pt = cipher
            .decrypt(Nonce::from_slice(&nonce), payload)
            .or_else(|_| Err(CryptoError))?;
        Ok(pt.to_vec())
    }
}
