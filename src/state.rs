pub mod state {
    use crate::crypto::crypto;
    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;
    use std::fmt;

    const MAX_SKIP: u32 = 1 << 10;

    #[derive(Debug, Clone)]
    pub struct MsgOverflowError;
    impl fmt::Display for MsgOverflowError {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "message overflow error")
        }
    }

    #[derive(Serialize, Deserialize)]
    pub struct Header {
        pub public_key: [u8; 32],
        pub prev_chain_len: u32,
        pub msg_num: u32,
    }

    #[derive(Serialize, Deserialize)]
    pub struct Message {
        pub header: Header,
        pub payload: Vec<u8>,
        pub auth: Vec<u8>,
    }

    pub struct State {
        root_key: [u8; 32],
        dh_self: crypto::KeyPair,
        ck_self: [u8; 32],
        n_send: u32,
        dh_remote: Option<crypto::PublicKey>,
        ck_remote: [u8; 32],
        n_recv: u32,
        n_prev: u32,
        skipped: HashMap<([u8; 32], u32), [u8; 32]>,
    }

    impl State {
        #[inline]
        pub fn dh_self(self) -> crypto::KeyPair {
            self.dh_self
        }

        #[inline]
        pub fn dh_remote(self) -> Option<crypto::PublicKey> {
            self.dh_remote
        }

        pub fn header(&self) -> Header {
            Header {
                public_key: self.dh_self.public().to_bytes(),
                prev_chain_len: self.n_prev,
                msg_num: self.n_send,
            }
        }

        pub fn init_sender(sk: &[u8; 32], pk: [u8; 32]) -> Self {
            let key_pair = crypto::KeyPair::generate();
            let remote_pk = crypto::PublicKey::from(pk);
            let shared_key = key_pair.dh(remote_pk);
            let (root_key, chain_key) = crypto::kdf_rk(sk, shared_key.as_bytes()).unwrap();
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

        pub fn init_receiver(sk: [u8; 32], kp: crypto::KeyPair) -> Self {
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

        pub fn encrypt(&mut self, pt: &[u8], ad: &[u8]) -> Message {
            let (ck, mk) = crypto::kdf_ck(&self.ck_self).unwrap();
            let header = self.header();
            let encoded = serde_json::to_vec(&header).unwrap();
            self.ck_self = ck;
            self.n_send += 1;
            let auth = [ad, &encoded].concat();
            Message {
                payload: crypto::encrypt(&mk, pt, &auth).unwrap(),
                header,
                auth,
            }
        }

        pub fn decrypt(&mut self, msg: &mut Message) -> Vec<u8> {
            let pt = self.try_skip(msg);
            if pt.is_some() {
                return pt.unwrap();
            }

            if self.dh_remote.is_none()
                || msg.header.public_key.ne(self.dh_remote.unwrap().as_bytes())
            {
                self.skip(msg.header.msg_num).unwrap();
                self.ratchet(&msg.header);
            }

            self.skip(msg.header.msg_num).unwrap();
            let (ck_r, mk) = crypto::kdf_ck(&self.ck_remote).unwrap();
            self.ck_remote = ck_r;
            self.n_recv += 1;
            crypto::decrypt(&mk, &mut msg.payload, &msg.auth).unwrap()
        }

        pub fn try_skip(&mut self, msg: &mut Message) -> Option<Vec<u8>> {
            let key = (msg.header.public_key, msg.header.msg_num);
            let val = self.skipped.remove_entry(&key);
            if val.is_some() {
                let (_, mk) = val.unwrap();
                let pt = crypto::decrypt(&mk, &mut msg.payload.as_mut_slice(), &msg.auth);
                return Some(pt.unwrap());
            }
            None
        }

        pub fn skip(&mut self, until: u32) -> Result<(), MsgOverflowError> {
            if until > self.n_recv + MAX_SKIP {
                return Err(MsgOverflowError);
            }

            if self.dh_remote.is_some() {
                while self.n_recv < until {
                    let (ck_r, mk) = crypto::kdf_ck(&self.ck_remote).unwrap();
                    self.ck_remote = ck_r;
                    let key = (self.dh_remote.unwrap().to_bytes(), self.n_recv);
                    self.skipped.insert(key, mk);
                    self.n_recv += 1
                }
            }

            Ok(())
        }

        pub fn ratchet(&mut self, header: &Header) {
            self.n_prev = self.n_send;
            self.n_send = 0;
            self.n_prev = 0;
            self.dh_remote = Some(crypto::PublicKey::from(header.public_key));

            let shared_key = self.dh_self.dh(self.dh_remote.unwrap());
            let (rk, ck_r) = crypto::kdf_rk(&self.root_key, shared_key.as_bytes()).unwrap();
            self.root_key = rk;
            self.ck_remote = ck_r;

            self.dh_self.zero(); // zero ephemeral key
            self.dh_self = crypto::KeyPair::generate(); // update key

            let shared_key = self.dh_self.dh(self.dh_remote.unwrap());
            let (rk, ck_s) = crypto::kdf_rk(&self.root_key, shared_key.as_bytes()).unwrap();
            self.root_key = rk;
            self.ck_self = ck_s;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::state::{Header, Message, State};
    use crate::crypto::crypto;
    use rand::{seq::SliceRandom, RngCore};
    use std::collections::HashMap;

    #[test]
    fn test_init() {
        let alice_kp = crypto::KeyPair::generate();
        let bob_kp = crypto::KeyPair::generate();
        let sk = alice_kp.dh(bob_kp.public());
        let alice = State::init_sender(sk.as_bytes(), bob_kp.public().to_bytes());
        let bob = State::init_receiver(sk.to_bytes(), bob_kp);
        assert_eq!(alice.dh_remote().unwrap(), bob.dh_self().public());
    }

    #[test]
    fn test_header_serde() {
        for _ in 0..(1 << 10) {
            let h = Header {
                public_key: rand::random::<[u8; 32]>(),
                prev_chain_len: rand::random::<u32>(),
                msg_num: rand::random::<u32>(),
            };
            let encoded = serde_json::to_vec(&h).unwrap();
            let decoded: Option<Header> = serde_json::from_slice(&encoded).unwrap();
            let header = decoded.unwrap();
            assert_eq!(header.public_key, h.public_key);
            assert_eq!(header.prev_chain_len, h.prev_chain_len);
            assert_eq!(header.msg_num, h.msg_num);
        }
    }

    #[test]
    fn test_in_order() {
        let alice_kp = crypto::KeyPair::generate();
        let bob_kp = crypto::KeyPair::generate();
        let sk = alice_kp.dh(bob_kp.public());
        let mut alice = State::init_sender(sk.as_bytes(), bob_kp.public().to_bytes());
        let mut bob = State::init_receiver(sk.to_bytes(), bob_kp);

        for i in 0..(1 << 10) {
            let size = rand::random::<usize>() % (1 << 10) + 1;
            let mut payload = vec![0u8; size];
            rand::thread_rng().fill_bytes(&mut payload);
            let mut ad = vec![0u8; 32];
            rand::thread_rng().fill_bytes(&mut ad);

            let mut msg = alice.encrypt(&payload, ad.as_slice());
            assert_eq!(msg.header.msg_num, i);

            let pt = bob.decrypt(&mut msg);
            assert_eq!(pt, payload);
        }
    }

    #[test]
    fn test_out_of_order() {
        let n_msg = 1 << 10;
        let alice_kp = crypto::KeyPair::generate();
        let bob_kp = crypto::KeyPair::generate();
        let sk = alice_kp.dh(bob_kp.public());
        let mut alice = State::init_sender(sk.as_bytes(), bob_kp.public().to_bytes());
        let mut bob = State::init_receiver(sk.to_bytes(), bob_kp);
        let mut messages: Vec<Message> = Vec::with_capacity(n_msg);
        let mut payloads = HashMap::<u32, Vec<u8>>::new();

        for i in 0..n_msg {
            let size = rand::random::<usize>() % (1 << 10) + 1;
            let mut payload = vec![0u8; size];
            rand::thread_rng().fill_bytes(&mut payload);
            let mut ad = vec![0u8; 32];
            rand::thread_rng().fill_bytes(&mut ad);
            messages.push(alice.encrypt(&payload, ad.as_slice()));
            payloads.insert(i as u32, payload);
        }

        messages.shuffle(&mut rand::thread_rng());

        for msg in &mut messages {
            let pt = bob.decrypt(msg);
            assert_eq!(&pt, payloads.get(&msg.header.msg_num).unwrap());
        }
    }

    #[test]
    fn test_ping_pong() {
        let alice_kp = crypto::KeyPair::generate();
        let bob_kp = crypto::KeyPair::generate();
        let sk = alice_kp.dh(bob_kp.public());
        let mut alice = State::init_sender(sk.as_bytes(), bob_kp.public().to_bytes());
        let mut bob = State::init_receiver(sk.to_bytes(), bob_kp);

        for _ in 0..(1 << 10) {
            let size = rand::random::<usize>() % (1 << 10) + 1;
            let mut payload = vec![0u8; size];
            rand::thread_rng().fill_bytes(&mut payload);
            let mut ad = vec![0u8; 32];
            rand::thread_rng().fill_bytes(&mut ad);

            let mut msg = alice.encrypt(&payload, ad.as_slice());
            let pt = bob.decrypt(&mut msg);
            assert_eq!(pt, payload);

            let size = rand::random::<usize>() % (1 << 10) + 1;
            let mut payload = vec![0u8; size];
            rand::thread_rng().fill_bytes(&mut payload);

            msg = bob.encrypt(&payload, ad.as_slice());
            let pt = alice.decrypt(&mut msg);
            assert_eq!(pt, payload);
        }
    }
}
