use crypto;

pub enum BlockCiphers {AES}
pub enum BlockCipherErrors {InvalidKey,
                            InvalidCipher,
                            InvalidLength}

pub struct BlockCipher<'a> {
    cipher: BlockCiphers,
    block_size: usize,
    key: &'a [u8]
}

impl<'a> BlockCipher<'a> {
    pub fn new(cipher: BlockCiphers, key: &[u8])
      -> Result<BlockCipher, BlockCipherErrors> {
        match cipher {
            BlockCiphers::AES => if key.len() == 16 {
                    Ok(BlockCipher {
                        cipher: BlockCiphers::AES,
                        block_size: 16,
                        key: key,
                       })
                }
                else {
                    Err(BlockCipherErrors::InvalidKey)
                }
        }
    }

    pub fn encrypt(&self, msg: &[u8]) -> Vec<u8> {
        use crypto::aes::ecb_encryptor;
        use crypto::buffer::{RefReadBuffer,
                             RefWriteBuffer,
                             WriteBuffer,
                             ReadBuffer};
        use crypto::symmetriccipher::SymmetricCipherError;

        assert!(msg.len() <= self.block_size);
        let mut tmp: Vec<u8> = vec![0; msg.len()];
        let mut result= RefWriteBuffer::new(tmp.as_mut_slice());

        match &self.cipher {
            BlockCiphers::AES => {
                let mut encryptor = ecb_encryptor(
                                        crypto::aes::KeySize::KeySize128,
                                        self.key,
                                        crypto::blockmodes::NoPadding);
                match encryptor.encrypt(&mut RefReadBuffer::new(msg),
                                        &mut result,
                                        true) {
                    Ok(_msg) => (),
                    Err(e) => match e {
                        SymmetricCipherError::InvalidLength =>
                            println!("invalid length"),
                        SymmetricCipherError::InvalidPadding =>
                            println!("invalid padding")
                        
                    }
                }

                let mut reader = result.take_read_buffer();
                reader.take_remaining().to_vec()
            }
        }
    }

    pub fn decrypt(&self, ct: &[u8]) -> Vec<u8> {
        use crypto::aes::ecb_decryptor;
        use crypto::buffer::{RefReadBuffer,
                             RefWriteBuffer,
                             WriteBuffer,
                             ReadBuffer};
        use crypto::symmetriccipher::SymmetricCipherError;

        assert_eq!(ct.len(), self.block_size);
        let mut tmp: Vec<u8> = vec![0; self.block_size];
        let mut result= RefWriteBuffer::new(tmp.as_mut_slice());

        match &self.cipher {
            BlockCiphers::AES => {
                let mut decryptor = ecb_decryptor(
                                        crypto::aes::KeySize::KeySize128,
                                        self.key,
                                        crypto::blockmodes::NoPadding);
                let mut reader = RefReadBuffer::new(ct);
                match decryptor.decrypt(&mut reader,
                                        &mut result,
                                        true) {
                    Ok(_msg) => (),
                    Err(e) => match e {
                        SymmetricCipherError::InvalidLength =>
                            println!("invalid length"),
                        SymmetricCipherError::InvalidPadding =>
                            println!("invalid padding")
                        
                    }

                }

                /* Need to get a reader from the RefWriteBuffer in order
                 * to be able to read from it. */
                let mut reader = result.take_read_buffer();
                reader.take_remaining().to_vec()
            },
        }
    }

    pub fn block_size(&self) -> usize {
        self.block_size
    }
}

pub mod modes {
    use my_crypto::symmetric::BlockCipher;

    pub enum Modes {ECB, CBC}

    pub fn ecb_encrypt(bc: &BlockCipher, msg: &[u8]) -> Vec<u8> {
        let mut result: Vec<u8> = Vec::new();

        for chunk in msg.chunks(bc.block_size()) {
            let mut enc = bc.encrypt(chunk);
            result.append(&mut enc);
        }

        assert_eq!(msg.len(), result.len());
        result
    }

    pub fn ecb_decrypt(bc: &BlockCipher, ct: &[u8]) -> Vec<u8> {
        let mut result: Vec<u8> = Vec::new();

        for chunk in ct.chunks(bc.block_size()) {
            result.append(&mut bc.decrypt(chunk));
        }

        result
    }

    pub fn cbc_encrypt(bc: &BlockCipher, msg: &[u8], iv: &[u8]) -> Vec<u8> {
        use xor::xor;
        let mut result: Vec<u8> = Vec::new();
        
        assert_eq!(iv.len(), bc.block_size());
        assert!(msg.len() % bc.block_size() == 0);

        for (i, chunk) in msg.chunks(bc.block_size).enumerate() {
            if i == 0 {
                result.append(&mut bc.encrypt(xor(iv, chunk).as_slice()));
            }
            else {
                let tmp = xor(&result[result.len() - bc.block_size .. 
                                      result.len()], chunk);
                result.append(&mut bc.encrypt(&tmp));
            }
        }

        assert_eq!(msg.len(), result.len());
        result
    }

    pub fn cbc_decrypt(bc: &BlockCipher, ct: &[u8], iv: &[u8]) -> Vec<u8> {
        use xor::xor;
        let mut result: Vec<u8> = Vec::new();
        let mut prev_chunk: Vec<u8> = Vec::new();
        assert_eq!(iv.len(), bc.block_size);

        for (i, chunk) in ct.chunks(bc.block_size).enumerate() {
            if i == 0 {
                result.append(&mut xor(&bc.decrypt(chunk), iv));
            }
            else {
                result.append(&mut xor(&bc.decrypt(chunk), &prev_chunk))
            }
            prev_chunk = chunk.to_vec();
        }

        result
    }
}

pub mod analysis {
    pub fn detect_ecb(ct: &[u8], blk_size: usize) -> bool {
        let mut i = 1;

        for test in ct.chunks(blk_size) {
            for chunk in ct[i * blk_size ..].chunks(blk_size) {
                if test == chunk {
                    return true
                }
            }
            i += 1;
        }
        false
    }

    // TODO: Return a Vec containing positions of all detected ECB blocks.
    pub fn detect_ecb_position (ct: &[u8],
                                blk_size: usize) -> Result<usize, bool> {
        let mut i = 1;

        for test in ct.chunks(blk_size) {
            for chunk in ct[i * blk_size ..].chunks(blk_size) {
                if test == chunk {
                    return Ok(i - 1 as usize)
                }
            }
            i += 1;
        }
        Err(false)
    }

    pub fn detect_block_size(encrypt: &Fn(&[u8]) -> Vec<u8>) -> usize {
        let mut input: Vec<u8> = Vec::new();
        let mut ct: Vec<u8>;
        let mut old_size: usize;
        let mut blk_size: usize = 0;

        ct = encrypt(&input);
        for _i in 1 .. 3 {
            blk_size = 0;
            old_size = ct.len();

            while ct.len() == old_size {
                old_size = ct.len();
                input.push(96);
                ct = encrypt(&input);
                blk_size += 1;
            }
        }
        
        blk_size
    }
}

pub mod attacks {

    pub fn ecb_oracle_decryption(encrypt: &Fn(&[u8]) -> Vec<u8>) -> String {
        use colored::*;
        use std::collections::HashMap;
        use super::analysis::{detect_block_size,
                              detect_ecb,
                              detect_ecb_position};

        // Detect block size (should be 16).
        let blk_size = detect_block_size(encrypt);
        println!("block size found: {}", blk_size);

        // Detect ECB mode (should be true).
        print!("ECB detected: ");
        match detect_ecb(&encrypt(&vec![0; 64]), blk_size) {
            true => println!("{}", "yes".green()),
            false => panic!("{}", "ECB mode not detected!".red())
        }

        // Determine the number of bytes to pad input in order to round
        // the prepended string to a full block.
        let mut prepend_pad_len: usize = 0;
        let mut msg: Vec<u8> = vec![0; blk_size * 2];
        let mut ct: Vec<u8> = encrypt(&msg);
        while !detect_ecb(&ct, blk_size) {
            msg.push(0);
            prepend_pad_len += 1;
            ct = encrypt(&msg);
        }

        // Find position of first ECB block.
        let first_ecb_block_pos = match detect_ecb_position(&ct, blk_size){
            Ok(size) => size,
            Err(_) => panic!("Could not find position of ECB blocks.")
        };

        // Determine the length of the prepended string.
        let prepend_len = first_ecb_block_pos * blk_size - prepend_pad_len;

        // Perform decryption.
        let mut decrypted: Vec<u8> = Vec::new();
        let secret_len = encrypt(&decrypted).len() - prepend_len;

        for i in 0 .. secret_len {
            let len = blk_size -
                      (decrypted.len() % blk_size + 1) +
                      prepend_pad_len;
            let mut input: Vec<u8> = vec![96; len];
            
            // Index into ciphertext must start after prepended secret.
            let index = i /
                        blk_size *
                        blk_size +
                        first_ecb_block_pos *
                        blk_size;
            assert_eq!(index % blk_size, 0);

            ct = encrypt(&input);
            let discover = ct[index .. index + blk_size].to_vec();
            assert_eq!(discover.len(), blk_size);

            let mut dict: HashMap<u8, Vec<u8>> = HashMap::new();
            input.append(&mut decrypted.to_owned());

            // TODO: Support more than ASCII characters.
            for j in 0 .. 128 {
                input.push(j);
                dict.insert(j as u8, encrypt(&input)[index .. index + blk_size]
                                     .to_vec());
                input.pop();
            }

            for (k, v) in dict {
                if discover == v {
                    decrypted.push(k);
                    break;
                }
            }

            // Detect padding and stop if correct padding is found.
            if decrypted[decrypted.len() - 1] == 1 {
                decrypted.pop();
                break;
            }
        }
        String::from_utf8(decrypted).unwrap()
    }
}
