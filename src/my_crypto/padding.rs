/*
 * Implements padding schemes.
 */

pub enum PaddingError {InvalidPadding}

// PKCS#7 implementation.
pub mod pkcs7 {
    use super::PaddingError;

    // Adds PKCS#7 padding to the input returning a vector of bytes.
    pub fn pad(text: &[u8], blk_size: usize) -> Vec<u8> {
        let pad_len = blk_size - text.len() % blk_size;
        let mut ptr: Vec<u8> = vec![0; text.len()];
        ptr.clone_from_slice(text);

        if pad_len > 0 {
            ptr.append(&mut vec![pad_len as u8; pad_len]);
        }
        else {
            ptr.append(&mut vec![blk_size as u8; blk_size]);
        }
        ptr
    }

    /* 
     * Removes PKCS#7 padding, returning a vector of bytes if the padding is
     * valid or an error is not.
     */
    pub fn unpad(text: &[u8], blk_size: usize) -> Result<Vec<u8>, PaddingError> {
        match is_valid(text, blk_size) {
            true => {
                let pad_len = text[text.len() - 1];
                Ok(text[.. text.len() - pad_len as usize].to_vec())
            },
            false => Err(PaddingError::InvalidPadding)
        }
    }

    // Determines whether the input has valid PKCS#7 padding or not.
    pub fn is_valid(text: &[u8], blk_size: usize) -> bool {
        let size = text[text.len() - 1];

        if size as usize > blk_size {
            return false;
        }

        let padding = text.to_vec()[text.len() - size as usize ..].to_vec();
        if padding.len() != size as usize {
            return false;
        }

        for c in padding {
            if c != size {
                return false;
            }
        }
        true
    }
}
