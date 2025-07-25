pub const SERVER_PORT: u16 = 3543;
pub const BUFFER_SIZE: usize = 65535;
pub const DEFAULT_TIMEOUT: u64 = 30;
pub const VERSION: &str = "v0.1";

pub enum ServerMetods {
    REGISTER,
    GET,
}
