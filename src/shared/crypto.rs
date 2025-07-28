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
pub fn encrypt(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let cipher = Aes256CbcEnc::new_from_slices(key, iv)?;
    Ok(cipher.encrypt_padded_vec_mut::<Pkcs7>(data))
}

/// Decrypt using AES-256-CBC
pub fn decrypt(
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let cipher = Aes256CbcDec::new_from_slices(key, iv)?;
    match cipher.decrypt_padded_vec_mut::<Pkcs7>(ciphertext) {
        Ok(v) => Ok(v),
        Err(e) => Err(format!("Decryption unpad error: {:?}", e).into()),
    }
}

pub fn test_all_crypto_functions() {
    // Test data
    let password = b"test_password_123";
    let salt = b"random_salt_data";
    let iv = b"1234567890123456"; // 16 bytes for AES-256-CBC
    let test_data = b"Hello, this is secret data to encrypt and decrypt!";

    println!("Testing crypto functions...");

    // Test 1: Key derivation
    println!("1. Testing key derivation...");
    let key = derive_key_from_password(password, salt);
    println!("   ✓ Key derived successfully: {} bytes", key.len());

    // Test 2: Encryption
    println!("2. Testing encryption...");
    match encrypt(&key, iv, test_data) {
        Ok(ciphertext) => {
            println!("   ✓ Encryption successful");
            println!("   Original data length: {} bytes", test_data.len());
            println!("   Encrypted data length: {} bytes", ciphertext.len());

            // Test 3: Decryption
            println!("3. Testing decryption...");
            match decrypt(&key, iv, &ciphertext) {
                Ok(decrypted) => {
                    println!("   ✓ Decryption successful");

                    // Test 4: Verify data integrity
                    println!("4. Verifying data integrity...");
                    if decrypted == test_data {
                        println!(
                            "   ✓ Data integrity verified - original and decrypted data match!"
                        );
                    } else {
                        println!("   ✗ Data integrity failed - data doesn't match!");
                    }
                }
                Err(e) => {
                    println!("   ✗ Decryption failed: {:?}", e);
                }
            }
        }
        Err(e) => {
            println!("   ✗ Encryption failed: {:?}", e);
        }
    }

    // Test 5: Test with different key (should fail to decrypt properly)
    println!("5. Testing with wrong key (should fail)...");
    let wrong_key = derive_key_from_password(b"wrong_password", salt);
    match encrypt(&key, iv, test_data) {
        Ok(ciphertext) => match decrypt(&wrong_key, iv, &ciphertext) {
            Ok(_) => println!("   ⚠ Unexpected success with wrong key"),
            Err(_) => println!("   ✓ Correctly failed with wrong key"),
        },
        Err(e) => println!("   Error in setup: {:?}", e),
    }

    println!("All tests completed!");
}
