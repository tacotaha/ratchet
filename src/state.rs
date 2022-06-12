pub mod state {
    use crate::crypto::crypto::{kdf_rk, KeyPair, PublicKey};
    use std::collections::HashMap;

    pub struct State {
        root_key: [u8; 32],
        dh_self: KeyPair,
        ck_self: [u8; 32],
        n_send: u32,
        dh_remote: Option<PublicKey>,
        ck_remote: [u8; 32],
        n_recv: u32,
        n_prev: u32,
        skipped: HashMap<[u8; 32], u32>,
    }

    impl State {
        const MAX_SKIP: u8 = 0x20;

        pub fn init_sender(sk: &[u8; 32], pk: [u8; 32]) -> Self {
            let key_pair = KeyPair::generate();
            let remote_pk = PublicKey::from(pk);
            let shared_key = key_pair.dh(remote_pk);
            let (root_key, chain_key) = kdf_rk(sk, shared_key.as_bytes());
            Self {
                root_key,
                dh_self: key_pair,
                ck_self: chain_key,
                n_send: 0,
                dh_remote: Some(remote_pk),
                ck_remote: [0u8; 32],
                n_recv: 0,
                n_prev: 0,
                skipped: HashMap::new(),
            }
        }

        pub fn init_receiver(sk: [u8; 32], kp: KeyPair) -> Self {
            Self {
                root_key: sk,
                dh_self: kp,
                ck_self: [0u8; 32],
                n_send: 0,
                dh_remote: None,
                ck_remote: [0u8; 32],
                n_recv: 0,
                n_prev: 0,
                skipped: HashMap::new(),
            }
        }

        #[inline]
        pub fn dh_self(self) -> KeyPair {
            self.dh_self
        }

        #[inline]
        pub fn dh_remote(self) -> Option<PublicKey> {
            self.dh_remote
        }
    }
}

#[cfg(test)]
mod tests {
    use super::state::State;
    use crate::crypto::crypto;

    #[test]
    fn test_init() {
        let alice_kp = crypto::KeyPair::generate();
        let bob_kp = crypto::KeyPair::generate();
        let sk = alice_kp.dh(bob_kp.public());
        let alice = State::init_sender(sk.as_bytes(), bob_kp.public().to_bytes());
        let bob = State::init_receiver(sk.to_bytes(), bob_kp);
        assert_eq!(alice.dh_remote().unwrap(), bob.dh_self().public());
    }
}
