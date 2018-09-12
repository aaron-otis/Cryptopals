extern crate hex;
extern crate base64;
extern crate hamming;
extern crate crypto;
extern crate colored;
extern crate rand;
extern crate url;

pub mod xor;
pub mod frequency_analysis;
pub mod my_crypto;
pub mod url_parsing;
pub mod util;
mod tests;

pub use hex::encode as hex_encode;
pub use hex::decode as hex_decode;
pub use base64::encode as b64_encode;
pub use base64::decode as b64_decode;
pub use std::fs::File;
pub use std::io;
pub use std::io::prelude::*;
pub use hamming::distance as hamming_distance;
pub use colored::*;
pub use rand::prelude::*;
pub use util::{random_key, read_and_decode_lines};

pub enum Encoding {BASE64, HEX}

fn main() {
    set1();
    set2();
    set3();
}

// Basic challenges.
fn set1() {
    /*
     * Basic challenge 3: Decrypt a single byte XOR. Uses frequency analysis
     * to determine the single byte key in order to decrypt the message.
     */
    use frequency_analysis::find_single_byte_key;
    use xor::xor;
    let basic3_str = match hex_decode("1b37373331363f78151b7f2b783431333d783978\
                                       28372d363c78373e783a393b3736") {
        Ok(s) => s,
        Err(e) => panic!("Invalid hex string: {}", e)
    };
    let basic3_key = find_single_byte_key(&basic3_str);
    let basic3_res = match String::from_utf8(xor(&vec![basic3_key],
                                                      &basic3_str)) {
        Ok(s) => s,
        Err(e) => panic!("Invalid UTF-8 sequence: {}", e)
    };
    print!("{}", "Basic challenge 3 decrypted: ".green());
    println!("{}", basic3_res);

    /* 
     * Basic challenge 4: Detect single byte XOR. Decrypts each line and checks
     * if the decryption forms a valid ASCII string.
     */
    let f = File::open("src/Basic_challege_4.txt").expect("file not found");
    let mut basic4_res: Vec<(usize, String)> = Vec::new();

    for (j, line) in io::BufReader::new(f).lines().enumerate() {
        let line = match line {
            Ok(s) => match hex_decode(s.into_bytes()) {
                Ok(decoded) => decoded,
                Err(e) => panic!("invalid hex: {}", e)
            },
            Err(e) => panic!("error: {}", e)
        };
        let basic4_key = find_single_byte_key(&line);
        let decrypt_attempt = xor(&vec![basic4_key], &line);

        if frequency_analysis::is_valid_string(&decrypt_attempt) {
            basic4_res.push((j, String::from_utf8(decrypt_attempt)
                      .expect("Invalid UTF-8 sequence")));
        }
    }

    println!("\n{}", "Basic challenge 4 decrypted:".green());
    for (lineno, line) in basic4_res {
        println!("line {}: {}", lineno, line);
    }

    /* 
     * Basic challenge 6: Break repeating-key XOR.
     */
    let text = read_and_decode_lines("src/Basic_challege_6.txt", Encoding::BASE64);
    let basic6_res = xor::crack_repeating_key_xor(text);
    println!("\n{}", "Basic challenge 6 decrypted:".green());
    println!("{}", basic6_res);

    /* 
     * Basic challenge 7: AES in ECB mode. The supplied file has been encrypted
     * via AES-ECB with the supplied key. AES-ECB implemented in order to
     * decrypt the message.
     */
    use my_crypto::symmetric::modes::ecb_decrypt;
    use my_crypto::symmetric::{BlockCipher, BlockCiphers};

    let key = b"YELLOW SUBMARINE";
    let text = read_and_decode_lines("src/Basic_challege_7.txt", Encoding::BASE64);
    let bc = match BlockCipher::new(BlockCiphers::AES, key) {
        Ok(bc) => bc,
        Err(_e) => panic!("block cipher initialization failed")
    };
    let basic7_result = ecb_decrypt(&bc, &text);
    println!("\n{}", "Basic challenge 7 decrypted:".green());
    println!("{}", String::from_utf8(basic7_result[.. text.len() - 4].to_vec()).unwrap());

    /* 
     * Basic challenge 8: Detect AES in ECB mode. One of the lines in the
     * supplied file is encrypted via AES-ECB. This is detected by looking
     * for identical ciphertext blocks.
     */
    println!("{}", "Basic challenge 8:".green());
    use my_crypto::symmetric::analysis::detect_ecb;
    let f = File::open("src/Basic_challege_8.txt").expect("file not found");
    for (i, line) in io::BufReader::new(f).lines().enumerate() {
        if detect_ecb(line.unwrap().as_bytes(), 16) {
            println!("Detected ECB mode on line {}", i);
        }
    }
}

// Block crypto set.
fn set2() {
    /* 
     * Block crypto challenge 10: Implement CBC mode. The supplied file is
     * encrypted with AES-CBC under the supplied key and an IV of all zeros.
     * CBC mode was implemented to decrypt it.
     */
    use my_crypto::symmetric::modes::cbc_decrypt;
    use my_crypto::symmetric::{BlockCipher, BlockCiphers};
    use my_crypto::padding::pkcs7::unpad;
    let text = read_and_decode_lines("src/Block_crypto_challenge_10.txt",
                                        Encoding::BASE64);
    let key = b"YELLOW SUBMARINE";
    let bc = match BlockCipher::new(BlockCiphers::AES, key) {
        Ok(bc) => bc,
        Err(_e) => panic!("block cipher initialization failed")
    };
    let iv = vec![0; bc.block_size()];
    let pt = match unpad(&cbc_decrypt(&bc, &text, &iv), bc.block_size()) {
        Ok(text) => text,
        Err(_e) => panic!("invalid padding")
    };
    let block_crypto10_result = String::from_utf8(pt)
                                        .expect("error converting to string");
    println!("\n{}\n{}", "Block Cipher challenge 10".green(), block_crypto10_result);
    drop(block_crypto10_result);

    /* 
     * Block crypto challenge 11: ECB/CBC detection oracle.
     */
    use my_crypto::oracle::{random_encryption, detection};
    use my_crypto::symmetric::modes::Modes;
    let vec_size: usize = 64;
    let tests = vec![vec![0; vec_size], vec![1; vec_size], vec![97; vec_size]];

    println!("{}", "Testing random encryption oracle (challenge 11)".green());
    for vec in tests {
        let enc = random_encryption(&vec);
        match detection(&enc) {
            Modes::ECB => println!("detected ECB"),
            Modes::CBC => println!("detected CBC")
        }
    }

    /* 
     * Block crypto challenge 12: Byte-at-a-time ECB decryption (simple).
     * Decrypts a message appended to user input encrypted under ECB mode.
     */
    use my_crypto::oracle::ECBOracle;
    use my_crypto::symmetric::attacks::ecb_oracle_decryption;
    let key = random_key();
    let oracle = ECBOracle::new(&key, false);
    let decrypted = ecb_oracle_decryption(&|msg| oracle.encrypt(msg));
    println!("\n{}", "Block crypto challenge 12".green());
    println!("{}\n{}", "decrypted:".blue(), decrypted);
    drop(oracle);
    drop(decrypted);

    /* 
     * Block crypto challenge 13: ECB cut-and-paste. Modifies ECB ciphertexts
     * such that it decrypts with a specific message. Relies on the fact that
     * ECB ciphertext modification do not propagate errors.
     */
    use url_parsing::{encrypt_profile, decrypt_profile, parse_url};
    let key = random_key();
    let bc = match BlockCipher::new(BlockCiphers::AES, &key) {
        Ok(bc) => bc,
        Err(e) => panic!(e)
    };
    let ct_to_paste = encrypt_profile(b"bbbbbbbbbbbbb", &bc);
    let ct_for_padding = encrypt_profile(&["bbbbbbbbbbadmin".as_bytes(),
                                           &[11 as u8; 11]].concat(), &bc);
    let concated = [&ct_to_paste[.. 32], &ct_for_padding[16 .. 32]].concat();
    let parsed = parse_url(decrypt_profile(&concated, &bc).as_bytes());
    println!("{}", "Block crypto challenge 13".green());
    println!("role: {}", parsed["role"]);

    /* 
     * Block crypto challenge 14: Byte-at-a-time ECB decryption (harder).
     * Decrypts a message appended to user input when a random length string
     * is prepended to the user's input and encrypted under ECB mode.
     */
    let key = random_key();
    let oracle = ECBOracle::new(&key, true);
    println!("\n{}", "Block crypto challenge 14".green());
    println!("{}\n{}", "decrypted:".blue(),
                       ecb_oracle_decryption(&|msg| oracle.encrypt(msg)));

    /* 
     * Block crypto challenge 16: CBC bitflipping attacks. Demonstrates that
     * CBC ciphertext is malleable which can be used to modify decrypted
     * blocks. Relies on the fact that the previous ciphertext block is XORed
     * with the current plaintext block before encrypting it. By XORing the
     * previous ciphertext block with the current plaintext block (which is
     * controlled by the user) and with the desired replacement message, one
     * can replace the original plaintext block with a new one.
     */
    println!("\n{}", "Block crypto challenge 16".green());
    use my_crypto::oracle::CBCBitflipOracle;
    use xor::xor;

    // Generate CBC ciphertext.
    let key = random_key();
    let oracle = CBCBitflipOracle::new(&key);
    let input = vec!['a' as u8; 32];
    let ct = oracle.encrypt(&input);

    // Bit flipping attack on CBC ciphertext. XOR previous ciphertext block
    // with the current plaintext block and the desired message.
    let mut c_prime = xor(&xor(b"aaaaaaaaaaaaaaaa", b";admin=true;aaaa"),
                          &ct[32 .. 48]);

    // Cut and paste the modified ciphertext block.
    let mut first = ct[.. 32].to_vec();
    let mut last = ct[48 ..].to_vec();
    c_prime.append(&mut last);
    first.append(&mut c_prime);

    // Decrypt the new message ;^)
    match oracle.is_admin(&first) {
        true => println!("Achieved admin!"),
        false => println!("Failed to achieve admin")
    };
}

// Block and stream crypto.
fn set3() {
    /*
     * Block and stream crypto challenge 17: The CBC padding oracle. 
     */
}
