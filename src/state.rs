pub mod state {
    use crate::crypto::crypto;
    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;
    use std::fmt;

    // max msg skips in a single chain
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

    #[derive(Serialize, Deserialize, Clone)]
    pub struct Message {
        pub header: Vec<u8>,  // encrypted header
        pub payload: Vec<u8>, // message ciphertext
    }

    // each party stores the following values per conversation
    pub struct State {
        root_key: [u8; 32],                          // 32 byte root key
        dh_self: crypto::KeyPair,                    // local ratchet key
        ck_self: [u8; 32],                           // local chain key
        hk_self: [u8; 32],                           // sending header key
        hk_next_self: [u8; 32],                      // next sending header key
        n_send: u32,                                 // sending msg number
        dh_remote: Option<crypto::PublicKey>,        // remote ratchet key
        ck_remote: [u8; 32],                         // remote chain key
        hk_remote: [u8; 32],                         // receiving header key
        hk_next_remote: [u8; 32],                    // next receiving header key
        n_recv: u32,                                 // receiving msg number
        n_prev: u32,                                 // length of previous sending chain
        skipped: HashMap<([u8; 32], u32), [u8; 32]>, // skipped messages (upper bound: MAX_SKIP)
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

        // generate a message header from current state
        pub fn header(&self) -> Header {
            Header {
                public_key: self.dh_self.public().to_bytes(),
                prev_chain_len: self.n_prev,
                msg_num: self.n_send,
            }
        }

        // initialize sender
        pub fn init_sender(sk: &[u8; 32], pk: [u8; 32], hk: [u8; 32], hk_next: [u8; 32]) -> Self {
            let key_pair = crypto::KeyPair::generate();
            let remote_pk = crypto::PublicKey::from(pk);
            let shared_key = key_pair.dh(remote_pk);
            let (root_key, chain_key, hk_next_self) =
                crypto::kdf_rk(sk, shared_key.as_bytes()).unwrap();
            Self {
                root_key,
                dh_self: key_pair,
                ck_self: chain_key,
                hk_self: hk,
                hk_next_self,
                n_send: 0,
                dh_remote: Some(remote_pk),
                ck_remote: [0u8; 32],
                hk_remote: [0u8; 32],
                hk_next_remote: hk_next,
                n_recv: 0,
                n_prev: 0,
                skipped: HashMap::new(),
            }
        }

        // initialize receiver
        pub fn init_receiver(
            root_key: [u8; 32],
            dh_self: crypto::KeyPair,
            hk_next_remote: [u8; 32],
            hk_next_self: [u8; 32],
        ) -> Self {
            Self {
                root_key,
                dh_self,
                ck_self: [0u8; 32],
                hk_self: [0u8; 32],
                hk_next_self,
                n_send: 0,
                dh_remote: None,
                ck_remote: [0u8; 32],
                hk_remote: [0u8; 32],
                hk_next_remote,
                n_recv: 0,
                n_prev: 0,
                skipped: HashMap::new(),
            }
        }

        // encrypt plaintext pt with message key mk
        pub fn encrypt(&mut self, pt: &[u8]) -> Message {
            let (ck, mk) = crypto::kdf_ck(&self.ck_self).unwrap();
            let header = serde_json::to_vec(&self.header()).unwrap();
            self.ck_self = ck;
            self.n_send += 1;
            Message {
                header: crypto::encrypt(&self.hk_self, &header).unwrap(),
                payload: crypto::encrypt(&mk, pt).unwrap(),
            }
        }

        //  decrypt message payload and verify auth tag
        pub fn decrypt(&mut self, msg: &mut Message) -> Vec<u8> {
            // try any header keys corresponding to skipped messages
            let pt = self.try_skip(msg);
            if pt.is_some() {
                return pt.unwrap();
            }

            let (header, skipped) = self.decrypt_header(&msg.header).unwrap();

            // next header key worked -> advance chain
            if skipped {
                self.skip(header.prev_chain_len).unwrap();
                self.ratchet(&header);
            }

            // skip over any missing messages
            self.skip(header.msg_num).unwrap();

            // update chain
            let (ck_r, mk) = crypto::kdf_ck(&self.ck_remote).unwrap();
            self.ck_remote = ck_r;
            self.n_recv += 1;

            crypto::decrypt(&mk, &mut msg.payload).unwrap()
        }

        // check if this message corresponds to a skipped key
        pub fn try_skip(&mut self, msg: &mut Message) -> Option<Vec<u8>> {
            let mut skipped_key: Option<([u8; 32], u32)> = None;

            for ((hk, n), _) in &self.skipped {
                // try decrypting under this header key
                let header = crypto::decrypt(hk, &msg.header);
                if header.is_ok() {
                    // decode header
                    let decoded: Option<Header> = serde_json::from_slice(&header.unwrap()).unwrap();
                    let header = decoded.unwrap();

                    // found skipped message
                    if &header.msg_num == n {
                        skipped_key = Some((*hk, *n));
                        break;
                    }
                }
            }

            // remove skipped message
            if skipped_key.is_some() {
                let mk = self.skipped.remove(&skipped_key.unwrap()).unwrap();
                let pt = crypto::decrypt(&mk, &msg.payload).unwrap();
                return Some(pt);
            }

            None
        }

        // try decrypting the header with the remote header key, next header key
        pub fn decrypt_header(&self, header: &[u8]) -> Result<(Header, bool), crypto::CryptoError> {
            let check = crypto::decrypt(&self.hk_remote, header);
            if check.is_ok() {
                let decoded: Option<Header> = serde_json::from_slice(&check.unwrap()).unwrap();
                return Ok((decoded.unwrap(), false));
            }

            let check = crypto::decrypt(&self.hk_next_remote, header);
            if check.is_ok() {
                let decoded: Option<Header> = serde_json::from_slice(&check.unwrap()).unwrap();
                return Ok((decoded.unwrap(), true));
            }

            Err(crypto::CryptoError)
        }

        // skip a message interval on an out of order message
        pub fn skip(&mut self, until: u32) -> Result<(), MsgOverflowError> {
            if until > self.n_recv + MAX_SKIP {
                return Err(MsgOverflowError);
            }

            if self.ck_remote != [0u8; 32] {
                while self.n_recv < until {
                    let (ck_r, mk) = crypto::kdf_ck(&self.ck_remote).unwrap();
                    self.ck_remote = ck_r;
                    self.skipped.insert((self.hk_remote, self.n_recv), mk); // save skipped message key
                    self.n_recv += 1
                }
            }

            Ok(())
        }

        // preform a single DH ratchet step
        pub fn ratchet(&mut self, header: &Header) {
            // reset chain length
            self.n_prev = self.n_send;
            self.n_send = 0;
            self.n_recv = 0;

            // advance header keys
            self.hk_self = self.hk_next_self;
            self.hk_remote = self.hk_next_remote;

            // update receiving chain
            self.dh_remote = Some(crypto::PublicKey::from(header.public_key));
            let shared_key = self.dh_self.dh(self.dh_remote.unwrap());
            let (rk, ck_r, hkn_r) = crypto::kdf_rk(&self.root_key, shared_key.as_bytes()).unwrap();
            self.root_key = rk;
            self.ck_remote = ck_r;
            self.hk_next_remote = hkn_r;

            self.dh_self.zero(); // zero ephemeral key
            self.dh_self = crypto::KeyPair::generate(); // update key

            // update sending chain
            let shared_key = self.dh_self.dh(self.dh_remote.unwrap());
            let (rk, ck_s, hkn_s) = crypto::kdf_rk(&self.root_key, shared_key.as_bytes()).unwrap();
            self.root_key = rk;
            self.ck_self = ck_s;
            self.hk_next_self = hkn_s;
        }
    }
}
