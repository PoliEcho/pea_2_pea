use pea_2_pea::*;

#[readonly::make]
pub struct Peer {
    #[readonly]
    pub sock_addr: std::net::SocketAddr,
    pub private_ip: std::net::Ipv4Addr,
}
impl Peer {
    pub fn new(sock_addr: std::net::SocketAddr, private_ip: Option<std::net::Ipv4Addr>) -> Self {
        Peer {
            sock_addr,
            private_ip: match private_ip {
                Some(ip) => ip,
                None => std::net::Ipv4Addr::UNSPECIFIED,
            },
        }
    }
}

#[readonly::make]
pub struct Network {
    #[readonly]
    pub encrypted: bool,
    #[readonly]
    pub key: [u8; 32],
    #[readonly]
    pub net_id: String,
    #[readonly]
    pub salt: [u8; BLOCK_SIZE as usize],
    pub peers: Vec<Peer>,
    pub private_ip: std::net::Ipv4Addr,
}

impl Network {
    pub fn new(
        encrypted: bool,
        key: [u8; 32],
        net_id: String,
        salt: [u8; BLOCK_SIZE as usize],
        peers: Vec<Peer>,
    ) -> Self {
        Network {
            encrypted,
            key,
            net_id,
            salt,
            peers,
            private_ip: std::net::Ipv4Addr::UNSPECIFIED,
        }
    }
}

#[readonly::make]
pub struct EncryptablePulicSockAddr {
    #[readonly]
    pub iv: [u8; BLOCK_SIZE],
    #[readonly]
    pub sock_addr: Box<[u8]>,
}

impl EncryptablePulicSockAddr {
    pub fn new(iv: [u8; BLOCK_SIZE], sock_addr: Box<[u8]>) -> Self {
        EncryptablePulicSockAddr { iv, sock_addr }
    }
}
