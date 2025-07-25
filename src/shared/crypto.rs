#[derive(Clone)]
pub struct KeyPair {
    private_key: rsa::RsaPrivateKey,
    public_key: rsa::RsaPublicKey,
}
pub fn generate_rsa_private_key() -> Result<rsa::RsaPrivateKey, rsa::Error> {
    let mut rng: rand::prelude::ThreadRng = rand::thread_rng();
    let bits: usize = 2048;

    return rsa::RsaPrivateKey::new(&mut rng, bits);
}

pub fn generate_rsa_key_pair() -> KeyPair {
    let private_key = generate_rsa_private_key().unwrap();
    let public_key = rsa::RsaPublicKey::from(&private_key);

    KeyPair {
        private_key,
        public_key,
    }
}
