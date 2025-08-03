use pea_2_pea::*;

#[derive(Clone)]
#[readonly::make]
pub struct Client {
    #[readonly]
    pub client_sock_addr: Vec<u8>,
    pub last_heart_beat: i64,
    #[readonly]
    pub iv: [u8; BLOCK_SIZE as usize],
    #[readonly]
    pub src: std::net::SocketAddr,
}

impl Client {
    pub fn new(
        client_addr: Vec<u8>,
        heart_beat: i64,
        iv: [u8; BLOCK_SIZE as usize],
        src: std::net::SocketAddr,
    ) -> Self {
        Client {
            client_sock_addr: client_addr,
            last_heart_beat: heart_beat,
            iv,
            src,
        }
    }
}
#[derive(Clone)]
#[readonly::make]
pub struct Registration {
    #[readonly]
    pub net_id: String,
    pub clients: Vec<Client>,

    pub last_heart_beat: i64,

    #[readonly]
    pub encrypted: bool,
    #[readonly]
    pub salt: [u8; BLOCK_SIZE as usize],
    pub invalid: bool,
}

impl Registration {
    pub fn new(
        net_id: String,
        client_addr: Vec<u8>,
        encrypted: bool,
        heart_beat: i64,
        salt: Option<[u8; BLOCK_SIZE as usize]>,
        iv: Option<[u8; BLOCK_SIZE as usize]>,
        src: std::net::SocketAddr,
    ) -> Self {
        Registration {
            net_id,
            clients: vec![Client::new(
                client_addr,
                heart_beat,
                iv.unwrap_or([0; BLOCK_SIZE as usize]),
                src,
            )],
            encrypted,
            last_heart_beat: heart_beat,
            salt: salt.unwrap_or([0; BLOCK_SIZE as usize]),
            invalid: false,
        }
    }
}
