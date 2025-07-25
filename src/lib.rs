pub const SERVER_PORT: u16 = 3543;
pub const BUFFER_SIZE: usize = 65535;
pub const DEFAULT_TIMEOUT: u64 = 30;
pub const VERSION: &str = "v0.1";
pub const RSA_SIZE: usize = 2048;

#[repr(u8)]
pub enum ServerMethods {
    QUERY = 0,
    REGISTER = 1,
    GET = 2,
    HEARTBEAT = 3,
}

pub mod shared;
