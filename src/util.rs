pub use std::fs::File;
pub use std::io;
pub use std::io::prelude::*;
use super::Encoding;

pub fn random_key() -> Vec<u8> {
    use rand::{thread_rng, Rng};

    let mut rng = thread_rng();
    let mut key: Vec<u8> = vec![0; 16];

    rng.fill(key.as_mut_slice());
    key
}

pub fn read_and_decode_lines(filename: &'static str, encoding: Encoding) -> Vec<u8> {
    use super::{b64_decode, hex_decode};

    let f = File::open(filename).expect("file not found");
    let mut text: Vec<u8> = Vec::new();

    for line in io::BufReader::new(f).lines() {
        let mut new_line: Vec<u8>;
        match encoding {
            Encoding::BASE64 => new_line = b64_decode(&line.unwrap()).unwrap(),
            Encoding::HEX => new_line = hex_decode(&line.unwrap()).unwrap()
        };
        text.append(&mut new_line);
    }

    text
}
