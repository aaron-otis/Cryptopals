use super::symmetric::modes::Modes;
use super::symmetric::{BlockCipher, BlockCiphers};

pub struct ECBOracle<'a> {
    bc: BlockCipher<'a>,
    prepend: Vec<u8>
}

impl <'a>ECBOracle<'a> {
    pub fn new(key: &'a [u8], prepend: bool) -> ECBOracle<'a> {
        use rand::{thread_rng, Rng};
        let mut begin: Vec<u8> = Vec::new();

        if prepend {
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

    pub fn encrypt(&self, msg: &[u8]) -> Vec<u8> {
        use super::symmetric::modes::ecb_encrypt;
        use super::padding::pkcs7::pad;
        use super::super::b64_decode;

        let mut begin: Vec<u8> = self.prepend.to_owned();
        let mut msg = msg.to_vec();
        let mut secret = b64_decode(
            "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\
             aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
             dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\
             YnkK").unwrap();

        msg.append(&mut secret);
        begin.append(&mut msg);
        ecb_encrypt(&self.bc, &pad(&begin, self.bc.block_size()))
    }
}

pub struct CBCBitflipOracle<'a> {
    bc: BlockCipher<'a>,
    iv: Vec<u8>,
    prepend: Vec<u8>,
    append: Vec<u8>
}

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
        let decrypted = match unpad(&cbc_decrypt(&self.bc, ct, &self.iv)) {
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

pub fn detection(ct: &[u8]) -> Modes {
    use super::symmetric::analysis::detect_ecb;

    if detect_ecb(ct, 16) {
        Modes::ECB
    }
    else {
        Modes::CBC
    }
}
