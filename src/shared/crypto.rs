use aes::Aes256;
use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
use cbc::{Decryptor, Encryptor};
use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha2::Sha256;

// they are used
#[allow(dead_code)]
type Aes256CbcEnc = Encryptor<Aes256>;
#[allow(dead_code)]
type Aes256CbcDec = Decryptor<Aes256>;

pub fn derive_key_from_password(password: &[u8], salt: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    let _ = pbkdf2::<Hmac<Sha256>>(password, salt, 10000, &mut key);
    key
}

/// Encrypt using AES-256-CBC
pub fn encrypt(
    key: &[u8],
    iv: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let cipher = Aes256CbcEnc::new_from_slices(key, iv)?;
    Ok(cipher.encrypt_padded_vec_mut::<Pkcs7>(plaintext))
}

/// Decrypt using AES-256-CBC
pub fn decrypt(
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let cipher = Aes256CbcDec::new_from_slices(key, iv)?;
    Ok(cipher.decrypt_padded_vec_mut::<Pkcs7>(ciphertext).unwrap())
}
