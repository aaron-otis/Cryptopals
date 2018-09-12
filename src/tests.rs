#[cfg(test)]

// Basic set challenge 1: Convert a hex string to a base 64 string.
#[test]
fn hex_to_base64_test() {
    use super::{hex_decode, b64_encode};

    let hex_str: &'static str = "49276d206b696c6c696e6720796f75722062726169\
                                 6e206c696b65206120706f69736f6e6f7573206d75\
                                 7368726f6f6d";
    let b64_str: &'static str = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG\
                                 9pc29ub3VzIG11c2hyb29t";
    let result = match hex_decode(hex_str) {
        Ok(hstr) => b64_encode(&hstr),
        Err(_e) => String::from(""),
    };
        
    assert_eq!(b64_str, result);
}

// Basic set challenge 2: Xor of two equal length strings.
#[test]
fn fixed_xor_test() {
    use super::{hex_encode, hex_decode, xor};

    let hex_str: &'static str = "1c0111001f010100061a024b53535009181c";
    let key = match hex_decode("686974207468652062756c6c277320657965") {
        Ok(key) => key,
        Err(_) => vec![1]
    };
    let expected_result: &'static str = "746865206b696420646f6e277420706c6179";

    let result = match hex_decode(hex_str) {
        Ok(hstr) => match xor::_fixed_xor(key, hstr) {
            Ok(res) => res,
            Err(_e) => vec![1, 2],
        },
        Err(_e) => Vec::new(),
    };

    assert_eq!(hex_encode(result), expected_result);
}

// Basic set challenge 5: Xor of strings with different lengths.
#[test]
fn repeating_key_xor_test() {
    use xor::xor;
    use super::hex_encode;

    let key = "ICE";
    let text = "Burning 'em, if you ain't quick and nimble\nI go crazy \
                when I hear a cymbal";

    assert_eq!(hex_encode(xor(key.as_bytes(), text.as_bytes())),
               "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a2\
                6226324272765272a282b2f20430a652e2c652a3124333a653e2b202763\
                0c692b20283165286326302e27282f") ;
}

// Test the external crate hamming to ensure it works as expected.
#[test]
fn hamming_distance_test() {
    use super::hamming_distance;

    let hd = hamming_distance(b"this is a test", b"wokka wokka!!!");
    assert_eq!(hd, 37);
}

// Block crypto challenge 9: Implement PKCS#7 padding.
#[test]
fn pkcs7_padding_test() {
    use my_crypto::padding::pkcs7;

    let mut answer: Vec<u8> = "YELLOW SUBMARINE".as_bytes().to_vec();
    let padded = pkcs7::pad(answer.as_slice(), 20);

    answer.append(&mut vec![4; 4]);
    assert_eq!(padded, answer);

    // Test when length of data is a multiple of the block size.
    let mut answer: Vec<u8> = "YELLOW SUBMARINE".as_bytes().to_vec();
    let padded = pkcs7::pad(answer.as_slice(), 16);

    answer.append(&mut vec![16; 16]);
    assert_eq!(padded, answer);
}

// Test that CBC mode works.
#[test]
fn cbc_test() {
    use my_crypto::symmetric::modes::{cbc_encrypt, cbc_decrypt};
    use my_crypto::symmetric::{BlockCipher, BlockCiphers};

    let key = b"YELLOW SUBMARINE";
    let bc = match BlockCipher::new(BlockCiphers::AES, key) {
        Ok(bc) => bc,
        Err(_e) => panic!("block cipher initialization failed")
    };
    let iv = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let mut msg = vec![96; 512];
    msg.append(&mut vec![97; 32]);

    let ct = cbc_encrypt(&bc, &msg, &iv);
    let bc = match BlockCipher::new(BlockCiphers::AES, key) {
        Ok(bc) => bc,
        Err(_e) => panic!("block cipher initialization failed")
    };
    assert_eq!(msg, cbc_decrypt(&bc, &ct, &iv));
}

// Test url parsing.
#[test]
fn url_parsing_test() {
    use url_parsing::parse_url;

    let res = parse_url(b"user=me&role=user");

    assert_eq!(res.get("user"), Some(&"me".to_string()));
    assert_eq!(res.get("role"), Some(&"user".to_string()));
}

// Test profile_for function.
#[test]
fn profile_for_test() {
    use url_parsing::profile_for;

    let url = profile_for("me@example.com".to_string());
    assert_eq!(url, "email=me@example.com&uid=10&role=user".to_string());

    // Test escaping.
    let url = profile_for("me@a.com&role=admin".to_string());
    assert_eq!(url, "email=me@a.com\\&role\\=admin&uid=10&role=user".to_string());
}

// Test profile encryption.
#[test]
fn encrypt_profile_test() {
    use my_crypto::symmetric::BlockCipher;
    use my_crypto::symmetric::BlockCiphers::AES;
    use url_parsing::{encrypt_profile, decrypt_profile};
    use super::random_key;

    let key = random_key();
    let bc = match BlockCipher::new(AES, &key){
        Ok(bc) => bc,
        Err(e) => panic!(e)
    };
    let ct = encrypt_profile(b"me@example.com", &bc);
    let decrypted = decrypt_profile(&ct, &bc);
    assert_eq!("email=me@example.com&uid=10&role=user", decrypted);
}

// Block cipher set challenge 15: PKCS#7 padding validation.
#[test]
fn pkcs7_validation_test() {
    use my_crypto::padding::pkcs7::is_valid;

    let valid = b"ICE ICE BABY\x04\x04\x04\x04";
    let invalid1 = b"ICE ICE BABY\x05\x05\x05\x05";
    let invalid2 = b"ICE ICE BABY\x01\x02\x03\x04";
    let invalid3 = b"ICE ICE BABY\x01\x02\x03\x100";

    assert_eq!(is_valid(valid), true);
    assert_eq!(is_valid(invalid1), false);
    assert_eq!(is_valid(invalid2), false);
    assert_eq!(is_valid(invalid3), false);
}

// Test CBC bit flipping decryption.
#[test]
fn cbc_bitflipping_decryption_test() {
    use my_crypto::oracle::CBCBitflipOracle;
    use super::random_key;

    let key = random_key();
    let oracle = CBCBitflipOracle::new(&key);
    let ct = oracle.encrypt(b";admin=true;");

    assert_eq!(oracle.is_admin(&ct), false);
}

// Test that the CBC padding oracle works.
#[test]
fn cbc_padding_oracle_test() {
    use my_crypto::oracle::CBCPaddingOracle;
    use util::random_key;

    let key = random_key();
    let oracle = CBCPaddingOracle::new(&key);
    let (iv, ct) = oracle.gen_ciphertext();

    // Should pass validation.
    assert_eq!(oracle.is_valid(&ct, &iv), true);

    let mut ct_prime = ct.to_owned();
    ct_prime[ct.len() - 1] = 100;

    // Should fail validation.
    assert_eq!(oracle.is_valid(&ct_prime, &iv), false);
}
