use pea_2_pea::*;
#[readonly::make]
pub struct Network {
    #[readonly]
    pub encrypted: bool,
    #[readonly]
    pub key: [u8; 32],
    #[readonly]
    pub net_id: String,
    #[readonly]
    pub salt: [u8; SALT_AND_IV_SIZE as usize],
    #[readonly]
    pub peers: Vec<std::net::SocketAddr>,
}

impl Network {
    pub fn new(
        encrypted: bool,
        key: [u8; 32],
        net_id: String,
        salt: [u8; SALT_AND_IV_SIZE as usize],
        peers: Vec<std::net::SocketAddr>,
    ) -> Self {
        Network {
            encrypted,
            key,
            net_id,
            salt,
            peers,
        }
    }
}
