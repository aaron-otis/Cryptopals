use std::collections::HashMap;
use my_crypto::symmetric::BlockCipher;

pub fn profile_for(email: String) -> String {
    let mut url = email.replace("&", "\\&");

    url = url.replace("=", "\\=");
    url = "email=".to_string() + &url + "&uid=10&role=user";

    url
}

pub fn parse_url(url: &[u8]) -> HashMap<String, String> {
    use url::form_urlencoded::parse;

    let fields: HashMap<String, String> = parse(url).into_owned().collect();

    fields
}

pub fn encrypt_profile(email: &[u8], bc: &BlockCipher) -> Vec<u8> {
    use my_crypto::symmetric::modes::ecb_encrypt;
    use my_crypto::padding::pkcs7::pad;

    let url = profile_for(String::from_utf8(email.to_vec()).unwrap());
    ecb_encrypt(bc, &pad(&url.as_bytes(), bc.block_size()))
}

pub fn decrypt_profile(ct: &[u8], bc: &BlockCipher) -> String {
    use my_crypto::symmetric::modes::ecb_decrypt;
    use my_crypto::padding::pkcs7::unpad;

    let decrypted = match unpad(&ecb_decrypt(bc, &ct)){
        Ok(d) => d,
        Err(e) => panic!(e)
    };
    String::from_utf8(decrypted).unwrap()
}
