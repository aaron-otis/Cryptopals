// Finds a single byte XOR key by using frequency analysis.
pub fn find_single_byte_key(ct: &Vec<u8>) -> u8 {
    let mut frequencies: [i32; 256] = [0; 256];
    let mut i = 0;
    let mut max_val = 0;

    // Record frequencies.
    for &c in ct.iter() {
        frequencies[c as usize] += 1;
    }

    // Find the character with the highest frequency.
    for (j, &val) in frequencies.iter().enumerate() {
        if val > max_val {
            i = j;
            max_val = val;
        }
    }

    // This character is most likely a space (ASCII code 32), so XOR with a
    // space to reveal the key.
    (32 as u8) ^ (i as u8)
}

/* 
 * Finds a multi-byte XOR key by performing frequency analysis on blocks
 * containing every ith byte.
 */
pub fn find_multi_byte_key(ct: &Vec<u8>, print_key: bool) -> Vec<u8> {
    use xor::find_xor_key_len;

    let key_size = find_xor_key_len(ct);
    let mut key: Vec<u8> = Vec::new();

    for i in 0 .. key_size {
        let mut chunk: Vec<u8> = Vec::new();
        let mut j = 0;

        while j < ct.len() - key_size {
            chunk.push(ct[i + j]);
            j += key_size;
        }

        key.push(find_single_byte_key(&chunk));
    }

    if print_key {
        println!("found multi-byte xor key: {}",
                 String::from_utf8(key.to_vec()).unwrap());
    }
    key
}

// Determines if a string contains alphanumeric and whitespace characters or not.
pub fn is_valid_string(text: &Vec<u8>) -> bool {
    for &c in text.iter() {
        if  !c.is_ascii_alphabetic() && !c.is_ascii_whitespace(){
            return false
        }
    }

    true
}
