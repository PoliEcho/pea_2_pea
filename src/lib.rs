use core::fmt;

pub const SERVER_PORT: u16 = 3543;
pub const UDP_BUFFER_SIZE: usize = 65527;
pub const IP_BUFFER_SIZE: usize = 65535;
pub const DEFAULT_TIMEOUT: u64 = 30;
pub const VERSION: &str = "v1.0";
pub const BLOCK_SIZE: usize = 16;
pub const STANDARD_RETRY_MAX: usize = 10;

pub const DEST_IN_IPV4_OFFSET: usize = 16;
pub const IPV4_SIZE: usize = 4;

pub const MAPPING_SHOT_COUNT: u8 = 5;

pub const DEFAULT_NETWORK_PREFIX: [u8; 3] = [172, 22, 44];

#[repr(u8)]
#[allow(non_camel_case_types)]
pub enum ServerMethods {
    QUERY = 0, // return IP and port of the client
    REGISTER = 1,
    GET = 2,
    HEARTBEAT = 3, // this also registers addtional clients
}
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[allow(non_camel_case_types)]
#[repr(u8)]
pub enum ServerResponse {
    GENERAL_ERROR = 255,
    ID_EXISTS = 254,
    ID_DOESNT_EXIST = 253, // both error since sometimes it is the problem that the id exist and somethimes problem is that is doesn't
    IO = 252,              // had to place it here to avoid creating anther enum
}

#[allow(non_camel_case_types)]
#[derive(Debug)]
pub enum ServerErrorResponses {
    // success server returns id of method
    GENERAL_ERROR(String),
    ID_EXISTS,
    ID_DOESNT_EXIST,
    IO(std::io::Error), // IO errors wraper
}

impl fmt::Display for ServerErrorResponses {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServerErrorResponses::GENERAL_ERROR(msg) => write!(f, "General error: {}", msg),
            ServerErrorResponses::ID_EXISTS => write!(f, "ID is already registered"),
            ServerErrorResponses::ID_DOESNT_EXIST => write!(f, "ID isn't yet registered"),
            ServerErrorResponses::IO(err) => write!(f, "IO error: {}", err),
        }
    }
}
impl std::error::Error for ServerErrorResponses {}
impl From<std::io::Error> for ServerErrorResponses {
    fn from(error: std::io::Error) -> Self {
        ServerErrorResponses::IO(error)
    }
}
impl ServerErrorResponses {
    pub fn into_io_error(self) -> std::io::Error {
        match self {
            ServerErrorResponses::IO(io_err) => io_err,
            other => std::io::Error::new(std::io::ErrorKind::Other, other),
        }
    }
}
impl ServerErrorResponses {
    pub fn kind(&self) -> ServerResponse {
        match self {
            ServerErrorResponses::GENERAL_ERROR(_) => ServerResponse::GENERAL_ERROR,
            ServerErrorResponses::ID_EXISTS => ServerResponse::ID_EXISTS,
            ServerErrorResponses::ID_DOESNT_EXIST => ServerResponse::ID_DOESNT_EXIST,
            ServerErrorResponses::IO(_) => ServerResponse::IO,
        }
    }
}

#[allow(non_camel_case_types)]
#[repr(usize)]
pub enum RegisterRequestDataPositions {
    ENCRYPTED = 1, // this feeld should be 0 if not encrypted
    ID_LEN = 2,
    SOCKADDR_LEN = 3,
    SALT = 4,
    IV = (BLOCK_SIZE as usize + RegisterRequestDataPositions::SALT as usize) as usize,
    DATA = (BLOCK_SIZE as usize + RegisterRequestDataPositions::IV as usize) as usize, // after this there will be id and sockaddr in string or encrypted form after
}

#[allow(non_camel_case_types)]
#[repr(usize)]
pub enum GetRequestDataPositions {
    ID = 1, // no need for len since id is the whoule rest of the packet
}

#[allow(non_camel_case_types)]
#[repr(usize)]
pub enum GetResponseDataPositions {
    ENCRYPTED = 1, // this feeld should be 0 if not encrypted
    NUM_OF_CLIENTS = 2,
    SALT = 3,
    CLIENTS = (BLOCK_SIZE as usize + RegisterRequestDataPositions::SALT as usize) - 1 as usize,
    // after this there will be blocks of this sturcture: one byte size of sockaddr than there will be IV that is SALT_AND_IV_SIZE long and after that there will be sockaddr this repeats until the end of packet
}

#[allow(non_camel_case_types)]
#[repr(usize)]
pub enum HeartBeatRequestDataPositions {
    ID_LEN = 1,
    SOCKADDR_LEN = 2,
    IV = 3,
    DATA = (HeartBeatRequestDataPositions::IV as usize + BLOCK_SIZE as usize) as usize, // first ID than sockaddr
}

#[allow(non_camel_case_types)]
#[repr(u8)]
pub enum P2PMethods {
    PEER_QUERY = 20,   // responds with its private ip
    PEER_HELLO = 21,   // sends private ip encrypted if on
    PEER_GOODBYE = 22, // sends private ip encrypted if on
    PACKET = 23,       // sends IP packet encrypted if on
    NEW_CLIENT_NOTIFY = 24,
    DO_NOTHING = 25,
}
#[repr(usize)]
pub enum P2PStandardDataPositions {
    // sould apply to all P2P Methods
    IV = 1,
    DATA = P2PStandardDataPositions::IV as usize + BLOCK_SIZE,
}

pub mod shared;
