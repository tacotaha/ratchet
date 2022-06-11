use crate::crypto::crypto::KeyPair;

pub struct State {
    root_key: [u8; 32],
    dh_send: KeyPair,
    ck_send: [u8; 32],
    n_send: u32,
    dh_recv: KeyPair,
    ck_recv: [u8; 32],
    n_recv: u32,
    n_prev: u32,
}
