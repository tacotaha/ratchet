use rand::{seq::SliceRandom, RngCore};
use ratchet::{
    crypto::crypto,
    state::state::{Header, Message, State},
};
use std::collections::HashMap;

// simulate a key exchange protocol for testing
fn negotiate_keys() -> (State, State) {
    // ratchet key
    let alice_kp = crypto::KeyPair::generate();
    let bob_kp = crypto::KeyPair::generate();

    // header key
    let alice_hk = crypto::KeyPair::generate();
    let bob_hk = crypto::KeyPair::generate();

    // next header key
    let alice_nhk = crypto::KeyPair::generate();
    let bob_nhk = crypto::KeyPair::generate();

    // simulate shared key negotiation
    let sk = alice_kp.dh(bob_kp.public());
    let hk = alice_hk.dh(bob_hk.public());
    let nhk = alice_nhk.dh(bob_nhk.public());

    let alice = State::init_sender(
        sk.as_bytes(),
        bob_kp.public().to_bytes(),
        hk.to_bytes(),
        nhk.to_bytes(),
    );
    let bob = State::init_receiver(sk.to_bytes(), bob_kp, hk.to_bytes(), nhk.to_bytes());

    (alice, bob)
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
    let (mut alice, mut bob) = negotiate_keys();

    for _ in 0..(1 << 10) {
        let size = rand::random::<usize>() % (1 << 10) + 1;

        let mut payload = vec![0u8; size];
        rand::thread_rng().fill_bytes(&mut payload);

        let mut msg = alice.encrypt(&payload);
        let pt = bob.decrypt(&mut msg);

        assert_eq!(pt, payload);
    }
}

#[test]
fn test_out_of_order() {
    let n_msg = 1 << 10;
    let (mut alice, mut bob) = negotiate_keys();
    let mut messages: Vec<Message> = Vec::with_capacity(n_msg);
    let mut payloads = HashMap::<Vec<u8>, Message>::new();

    for _ in 0..n_msg {
        let size = rand::random::<usize>() % (1 << 10) + 1;

        let mut payload = vec![0u8; size];
        rand::thread_rng().fill_bytes(&mut payload);

        let ct = alice.encrypt(&payload);
        messages.push(ct.clone());
        payloads.insert(payload, ct);
    }

    messages.shuffle(&mut rand::thread_rng());

    for msg in &mut messages {
        let pt = bob.decrypt(msg);
        let m = payloads.get(&pt).unwrap();
        assert_eq!(msg.header, m.header);
        assert_eq!(msg.payload, m.payload);
    }
}

#[test]
fn test_ping_pong() {
    let (mut alice, mut bob) = negotiate_keys();

    for _ in 0..(1 << 10) {
        let size = rand::random::<usize>() % (1 << 10) + 1;
        let mut payload = vec![0u8; size];
        rand::thread_rng().fill_bytes(&mut payload);

        let mut msg = alice.encrypt(&payload);
        let pt = bob.decrypt(&mut msg);
        assert_eq!(pt, payload);

        let size = rand::random::<usize>() % (1 << 10) + 1;
        let mut payload = vec![0u8; size];
        rand::thread_rng().fill_bytes(&mut payload);

        msg = bob.encrypt(&payload);
        let pt = alice.decrypt(&mut msg);
        assert_eq!(pt, payload);
    }
}
