pub const SERVER_PORT: u16 = 3543;
pub const BUFFER_SIZE: usize = 65535;
pub const DEFAULT_TIMEOUT: u64 = 30;
pub const VERSION: &str = "v0.1";
pub const RSA_SIZE: usize = 2048;

#[repr(u8)]
pub enum ServerMethods {
    REGISTER = 0,
    GET = 1,
    HEARTBEAT = 2,
}

pub mod shared;
