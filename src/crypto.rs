

use rand::prelude::IndexedRandom;  // random words
use rand::RngExt;


use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce
};

pub fn generate_magic_code() -> String {
    let adjectives = [
        "autumn", "hidden", "bitter", "misty", "silent", "empty", "dry", "dark",
        "summer", "icy", "delicate", "quiet", "white", "cool", "spring", "winter",
        "patient", "twilight", "dawn", "crimson", "wispy", "weathered", "blue",
    ];
    let nouns = [
        "waterfall", "river", "breeze", "moon", "rain", "wind", "sea", "morning",
        "snow", "lake", "sunset", "pine", "shadow", "leaf", "dawn", "glitter",
        "forest", "hill", "cloud", "meadow", "sun", "glade", "bird", "brook",
    ];

    let mut rng = rand::rng();
    let number = rng.random_range(1..100);
    let adj = adjectives.choose(&mut rng).unwrap();
    let noun = nouns.choose(&mut rng).unwrap();

    format!("{}-{}-{}", number, adj, noun)
}

// padding 40byte seqence number into 12-byte Nonce
pub fn seq_to_nonce(seq_num: u32) -> Nonce {

    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[8] = (seq_num >> 24) as u8;
    nonce_bytes[9] = (seq_num >> 16) as u8;
    nonce_bytes[10] = (seq_num >> 8) as u8;
    nonce_bytes[11] = seq_num as u8;

    Nonce::from(nonce_bytes)
}

pub fn encrypt_chunk(seq_num: u32, plaintext: &[u8], secret_key: &[u8; 32]) -> Vec<u8> {
    let key = Key::from(*secret_key);
    let cipher = ChaCha20Poly1305::new(&key);
    let nonce = seq_to_nonce(seq_num);
    cipher.encrypt(&nonce, plaintext).expect("Encryption Failed..")
}

pub fn decrypt_chunk(seq_num: u32, ciphertext: &[u8], secret_key: &[u8; 32]) -> Result<Vec<u8>, chacha20poly1305::aead::Error> {
    let key = Key::from(*secret_key);
    
    let cipher = ChaCha20Poly1305::new(&key);
    let nonce = seq_to_nonce(seq_num);
    cipher.decrypt(&nonce, ciphertext)
}
