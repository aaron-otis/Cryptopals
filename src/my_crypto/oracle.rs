/*
 * Oracles used in various challenges.
 */

use super::symmetric::modes::Modes;
use super::symmetric::{BlockCipher, BlockCiphers};


/* 
 * An ECB oracle that prepends a specified message and appends a specific
 * message to user input before encrypting it under AES-ECB.
 */
pub struct ECBOracle<'a> {
    bc: BlockCipher<'a>,
    prepend: Vec<u8>
}

impl <'a>ECBOracle<'a> {
    // Create an ECBOracle object.
    pub fn new(key: &'a [u8], prepend: bool) -> ECBOracle<'a> {
        use rand::{thread_rng, Rng};
        let mut begin: Vec<u8> = Vec::new();

        if prepend {
            // Generate a random string of length 0 - 256, chosen randomly.
            let mut rng = thread_rng();
            let len: usize = rng.gen_range(0, 256);
            begin = vec![0; len];
            rng.fill(begin.as_mut_slice());
        }

        ECBOracle {
            bc: match BlockCipher::new(BlockCiphers::AES, key) {
                Ok (bc) => bc,
                Err (_e) => panic!("block cipher initialization failed!")
            },
            prepend: begin.to_owned()
        }
    }

    // Encrypts user input, after prepending and appending to it, via AES-ECB.
    pub fn encrypt(&self, msg: &[u8]) -> Vec<u8> {
        use super::symmetric::modes::ecb_encrypt;
        use super::padding::pkcs7::pad;
        use super::super::b64_decode;

        // Prepend and append messages.
        let mut begin: Vec<u8> = self.prepend.to_owned();
        let mut msg = msg.to_vec();
        let mut secret = b64_decode(
            "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\
             aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
             dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\
             YnkK").unwrap();
        msg.append(&mut secret);
        begin.append(&mut msg);

        // Encrypt.
        ecb_encrypt(&self.bc, &pad(&begin, self.bc.block_size()))
    }
}

pub struct CBCBitflipOracle<'a> {
    bc: BlockCipher<'a>,
    iv: Vec<u8>,
    prepend: Vec<u8>,
    append: Vec<u8>
}

/*
 * A CBC oracle the prepends and appends specific messages to user input before
 * encrypting it under AES-CBC with an IV of all zeros.
 */
impl <'a>CBCBitflipOracle<'a> {
    // Creates a new CBCBitflipOracle object. Uses and IV of all zeros.
    pub fn new(key: &'a [u8]) -> CBCBitflipOracle<'a> {
        CBCBitflipOracle {
            bc: match BlockCipher::new(BlockCiphers::AES, key) {
                Ok (bc) => bc,
                Err (_e) => panic!("block cipher initialization failed!")
            },
            iv: [0; 16].to_vec(),
            prepend: b"comment1=cooking%20MCs;userdata=".to_vec(),
            append: b";comment2=%20like%20a%20pound%20of%20bacon".to_vec()
        }
    }

    /*
     * Encrypts user input appending and prepending the appropriate strings
     * via AES-CBC. Returns the generated ciphertext as a byte vector.
     */
    pub fn encrypt(&self, msg: &[u8]) -> Vec<u8> {
        use super::padding::pkcs7::pad;
        use super::symmetric::modes::cbc_encrypt;

        let mut append = self.append.to_owned();
        let mut new_msg = self.prepend.to_owned();
        let mut msg_vec = msg.to_vec();

        // Quote ';' and '=' characters.
        let mut i: usize = 0;
        while i < msg_vec.len() {
            if msg_vec[i] == ';' as u8 || msg_vec[i] == '=' as u8 {
                msg_vec.insert(i, '\\' as u8);
                i += 1;
            }
            i += 1;
        }

        // Create new input string.
        msg_vec.append(&mut append);
        new_msg.append(&mut msg_vec);

        // Pad input and encrypt.
        cbc_encrypt(&self.bc,
                    &pad(&new_msg, self.bc.block_size()),
                    &self.iv)
    }

    /* 
     * Decrypts supplied ciphertext and then checks for the string
     * ';admin=true;'. Returns true if found and false otherwise.
     */
    pub fn is_admin(&self, ct: &[u8]) -> bool {
        use super::symmetric::modes::cbc_decrypt;
        use super::padding::pkcs7::unpad;

        let substr = b";admin=true;".to_vec();
        let decrypted = match unpad(&cbc_decrypt(&self.bc, ct, &self.iv),
                                    self.bc.block_size()) {
            Ok(msg) => msg,
            Err(_e) => panic!("Invalid padding")
        };

        // Look for admin=true substring.
        for i in 0 .. decrypted.len() - (self.bc.block_size() + 1) {
            let block = decrypted[i .. i + substr.len()].to_vec();
            if block == substr {
                return true;
            }
        }

        false
    }
}

pub struct CBCPaddingOracle<'a> {
    bc: BlockCipher<'a>,
    strings: Vec<&'a [u8]>
}

impl <'a>CBCPaddingOracle<'a> {
    pub fn new(key: &'a [u8]) -> CBCPaddingOracle<'a> {
        let strings: Vec<&[u8]> = vec![b"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIG\
                                        p1bXBpbmc=",
                                       b"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW\
                                        4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
                                       b"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0by
                                        B0aGUgcG9pbnQsIG5vIGZha2luZw==",
                                       b"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3\
                                        VuZCBvZiBiYWNvbg==",
                                       b"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW\
                                        4ndCBxdWljayBhbmQgbmltYmxl",
                                       b"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhci\
                                        BhIGN5bWJhbA==",
                                       b"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIH\
                                        NvdXBlZCB1cCB0ZW1wbw==",
                                       b"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW\
                                        1lIHRvIGdvIHNvbG8=",
                                       b"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbn\
                                        Qgb2g=",
                                       b"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzby\
                                        BteSBoYWlyIGNhbiBibG93"];

        CBCPaddingOracle {
            bc: match BlockCipher::new(BlockCiphers::AES, key) {
                Ok (bc) => bc,
                Err (_e) => panic!("block cipher initialization failed!")
            },
            strings: strings
        }
    }

    pub fn gen_ciphertext(&self) -> (Vec<u8>, Vec<u8>) {
        use rand::{thread_rng, Rng};
        use super::symmetric::modes::cbc_encrypt;
        use super:: padding::pkcs7::pad;

        // Pick a random string.
        let mut rng = thread_rng();
        let index = rng.gen_range(0, self.strings.len() - 1);
        let string = self.strings[index].to_vec();

        // Generate a random IV.
        let mut iv = vec![0; self.bc.block_size()];
        rng.fill(iv.as_mut_slice());

        // Encrypt via CBC.
        let ct = cbc_encrypt(&self.bc, &pad(&string, self.bc.block_size()), &iv);

        (iv, ct)
    }

    pub fn is_valid(&self, ct: &[u8], iv: &[u8]) -> bool {
        use super::symmetric::modes::cbc_decrypt;
        use super::padding::pkcs7::is_valid;

        let decrypted = cbc_decrypt(&self.bc, ct, iv);

        is_valid(&decrypted, self.bc.block_size())
    }
}

/*
 * Generates ciphertext under AES-CBC or AES-ECB each 50% of the time. Appends
 * and prepends different random 5-10 byte strings to user input before
 * encrypting.
 */
pub fn random_encryption(msg: &[u8]) -> Vec<u8> {
    use rand::{random, thread_rng, Rng};
    use super::symmetric::modes::{cbc_encrypt, ecb_encrypt};
    use super::symmetric::{BlockCipher, BlockCiphers};
    use super::padding::pkcs7;
    use super::super::random_key;
    use colored::*;

    let mut rng = thread_rng();

    // Generate random key.
    let key: Vec<u8> = random_key();

    // Initialize block cipher primitive.
    let bc = match BlockCipher::new(BlockCiphers::AES, &key) {
        Ok(bc) => bc,
        Err(_e) => panic!("block cipher initialization failed")
    };

    // Append 5-10 random bytes to msg.
    let mut pad: Vec<u8> = vec![0; rng.gen_range(5, 11)];
    let mut text = msg.to_vec();
    rng.fill(pad.as_mut_slice());
    text.append(&mut pad);

    // Prepend 5-10 random bytes to msg.
    let mut pad: Vec<u8> = vec![0; rng.gen_range(5, 11)];
    pad.append(&mut text);
    text = pad;

    // Choose either ECB or CBC mode.
    let choice: usize = random();
    let blk_size = bc.block_size();
    if choice % 2 == 0 { // Use CBC.
        println!("{}", "encrypting message via AES-CBC".yellow());
        // Generate random IV.
        let mut iv: Vec<u8> = vec![0; bc.block_size()];
        rng.fill(iv.as_mut_slice());

        cbc_encrypt(&bc, &pkcs7::pad(&text, blk_size), &iv)
    }
    else { // Use ECB.
        println!("{}", "encrypting message via AES-EBC".yellow());
        ecb_encrypt(&bc, &pkcs7::pad(&text, blk_size))
    }
}

// Detects whether ECB or CBC mode was used to encrypt ct.
pub fn detection(ct: &[u8]) -> Modes {
    use super::symmetric::analysis::detect_ecb;

    if detect_ecb(ct, 16) {
        Modes::ECB
    }
    else {
        Modes::CBC
    }
}
