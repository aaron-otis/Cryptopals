pub enum PaddingError {InvalidPadding}

pub mod pkcs7 {
    use super::PaddingError;

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

    pub fn unpad(text: &[u8]) -> Result<Vec<u8>, PaddingError> {
        match is_valid(text) {
            true => {
                let pad_len = text[text.len() - 1];
                Ok(text[.. text.len() - pad_len as usize].to_vec())
            },
            false => Err(PaddingError::InvalidPadding)
        }
    }

    pub fn is_valid(text: &[u8]) -> bool {
        let size = text[text.len() - 1];
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
