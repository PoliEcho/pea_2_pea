use core::fmt;

pub const SERVER_PORT: u16 = 3543;
pub const BUFFER_SIZE: usize = 65535;
pub const DEFAULT_TIMEOUT: u64 = 30;
pub const VERSION: &str = "v0.1";
pub const SALT_AND_IV_SIZE: u8 = 16;
pub const STANDARD_RETRY_MAX: usize = 10;

#[repr(u8)]
pub enum ServerMethods {
    QUERY = 0, // return IP and port of the client
    REGISTER = 1,
    GET = 2,
    HEARTBEAT = 3,
}
#[allow(non_camel_case_types)]
pub enum ServerResponse {
    GENERAL_ERROR = 255,
    ID_EXISTS = 254,
    ID_DOESNT_EXIST = 253, // both error since sometimes it is the problem that the id exist and somethimes problem is that is doesn't
}

#[allow(non_camel_case_types)]
#[derive(Debug)]
pub enum ServerErrorResponses {
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

#[allow(non_camel_case_types)]
pub enum RegisterRequestDataPositions {
    ENCRYPTED = 1, // this feeld should be 0 if not encrypted
    ID_LEN = 2,
    SOCKADDR_LEN = 3,
    SALT = 4,
    IV = (SALT_AND_IV_SIZE + RegisterRequestDataPositions::SALT as u8) as isize,
    DATA = (SALT_AND_IV_SIZE + RegisterRequestDataPositions::IV as u8) as isize, // after this there will be id and sockaddr in string or encrypted form after
}

#[allow(non_camel_case_types)]
pub enum GetResponseDataPositions {
    ENCRYPTED = 1, // this feeld should be 0 if not encrypted
    ID_LEN = 2,
    NUM_OF_CLIENTS = 3,
    SALT = 4,
    CLIENTS = (SALT_AND_IV_SIZE + RegisterRequestDataPositions::SALT as u8) as isize,
    // after this there will be blocks of this sturcture: one byte size of sockaddr than there will be IV that is SALT_AND_IV_SIZE long and after that there will be sockaddr this repeats until the end of packet
}

pub mod shared;
