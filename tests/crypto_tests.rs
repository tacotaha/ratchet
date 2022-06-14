use rand::RngCore;
use ratchet::crypto::crypto;

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

        let mut ct = crypto::encrypt(&mut mk, &mut payload).unwrap();
        let pt = crypto::decrypt(&mut mk, &mut ct).unwrap();
        assert_eq!(pt, payload);
    }
}

#[test]
#[should_panic]
fn test_enc_invalid_nonce() {
    for _ in 0..(1 << 10) {
        let size = rand::random::<usize>() % (1 << 10) + 1;
        let mut payload = vec![0u8; size];
        rand::thread_rng().fill_bytes(&mut payload);

        let mut mk = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut mk);

        let mut ct = crypto::encrypt(&mut mk, &mut payload).unwrap();
        let pt = crypto::decrypt(&mut mk, &mut ct).unwrap();
        assert_eq!(pt, payload);

        let ct_len = ct.len();
        let offset = rand::random::<usize>() % 12;
        ct[ct_len - offset - 1] ^= 0xff; // flip a random byte
        crypto::decrypt(&mut mk, &mut ct).unwrap(); // auth should fail
    }
}
