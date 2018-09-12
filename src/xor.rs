pub enum Error { UnequalLengths }

pub fn xor(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    let mut i = 0;

    for &m in msg.iter() {
        if i >= key.len() {
            i = 0;
        }

        result.push(m ^ key[i]);
        i += 1;
    }

    result
}

pub fn _fixed_xor(key: Vec<u8>, msg: Vec<u8>) -> Result<Vec<u8>, Error> {
    if key.len() == msg.len() {
        let mut result: Vec<u8> = Vec::new();
        for (k, m) in key.iter().zip(msg.iter()) {
            result.push(k ^ m);
        }

        Ok(result)
    }
    else {
        Err(Error::UnequalLengths)
    }
}

pub fn crack_repeating_key_xor(text: Vec<u8>) -> String {
    use frequency_analysis::find_multi_byte_key;

    let key = find_multi_byte_key(&text, false);
    assert!(key.len() > 0);
    let decrypted = xor(&key, &text);

    String::from_utf8(decrypted).expect("Invalid UTF-8 sequence")
}

pub fn find_xor_key_len(text: &Vec<u8>) -> usize {
    use hamming_distance;

    let mut key_size = 1;
    let mut min_hamming_distance = text.len();

    for i in 1 .. text.len() / 16 {
        let normalized = hamming_distance(&text[0 .. 8 * i],
                                          &text[8 * i .. 16 * i]) / (i as u64);

        if (normalized as usize) < min_hamming_distance {
            min_hamming_distance = normalized as usize;
            key_size = i;
        }
    }

    assert!(key_size > 0);
    key_size
}
