pub mod crypto {
    use hex_literal::hex;
    use hkdf::Hkdf;
    use rand::rngs::OsRng;
    use sha2::Sha512;
    use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};

    pub struct KeyPair {
        private: EphemeralSecret,
        public: PublicKey,
    }

    impl KeyPair {
        pub fn generate() -> Self {
            let sk = EphemeralSecret::new(OsRng);
            Self {
                public: PublicKey::from(&sk),
                private: sk,
            }
        }

        pub fn public(&self) -> PublicKey {
            self.public
        }

        pub fn dh(self, pk: PublicKey) -> SharedSecret {
            self.private.diffie_hellman(&pk)
        }
    }

    pub fn kdf_rk(rk: [u8; 32], dh_out: [u8; 32]) -> [u8; 64] {
        let info = hex!("f0f1f2f3f4f5f6f7f8f9");
        let hk = Hkdf::<Sha512>::new(Some(&rk[..]), &dh_out);
        let mut okm = [0u8; 64];
        hk.expand(&info, &mut okm).unwrap();
        okm
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dh() {
        let k1 = crypto::KeyPair::generate();
        let k1_pub = k1.public();
        let k2 = crypto::KeyPair::generate();

        let shared_secret_1 = k1.dh(k2.public());
        let shared_secret_2 = k2.dh(k1_pub);
        assert_eq!(shared_secret_1.as_bytes(), shared_secret_2.as_bytes());
    }
}
