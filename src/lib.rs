pub const SERVER_PORT: u16 = 3543;
pub const BUFFER_SIZE: usize = 65535;
pub const DEFAULT_TIMEOUT: u64 = 30;
pub const VERSION: &str = "v0.1";
pub const SALT_AND_IV_SIZE: u8 = 16;

#[repr(u8)]
pub enum ServerMethods {
    QUERY = 0, // return IP and port of the client
    REGISTER = 1,
    GET = 2,
    HEARTBEAT = 3,
}

pub enum ServerResponse {
    // avoid 0 from empty buffers
    OK = 1,
    GENERAL_ERROR = 255,
    ID_EXISTS = 254,
    ID_DOESNT_EXIST = 253, // both error since sometimes it is the problem that the id exist and somethimes problem is that is doesn't
}

pub enum RegisterRequestDataPositions {
    ENCRYPTED = 1, // this feeld should be 0 if not encrypted
    ID_LEN = 2,
    SOCKADDR_LEN = 3,
    SALT = 4,
    IV = (SALT_AND_IV_SIZE + RegisterRequestDataPositions::SALT as u8) as isize,
    DATA = (SALT_AND_IV_SIZE + RegisterRequestDataPositions::IV as u8) as isize, // after this there will be id and sockaddr in string or encrypted form after
}

pub mod shared;
