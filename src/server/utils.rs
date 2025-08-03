use colored::Colorize;
use pea_2_pea::*;

pub fn send_general_error_to_client<T: std::error::Error>(
    dst: core::net::SocketAddr,
    e: T,
    socket: std::sync::Arc<smol::net::UdpSocket>,
) {
    let mut resp_buf: Box<[u8]> = vec![0; e.to_string().len() + 1].into_boxed_slice();

    resp_buf[0] = ServerResponse::GENERAL_ERROR as u8; // set 1st byte to ERROR
    resp_buf[1..1 + e.to_string().len()].copy_from_slice(e.to_string().as_bytes()); // send error text to client

    let _ = socket.send_to(&[ServerResponse::GENERAL_ERROR as u8], dst);
}

pub fn disconnected_cleaner(
    registration_vector: std::sync::Arc<
        orx_concurrent_vec::ConcurrentVec<crate::types::Registration>,
    >,
) {
    loop {
        std::thread::sleep(std::time::Duration::from_secs(120));
        println!("{} starting cleanup", "[LOG]".blue());
        let time_now = chrono::Utc::now().timestamp();
        unsafe {
            registration_vector.iter_mut().for_each(|reg| {
                reg.clients.retain(|c| time_now - c.last_heart_beat < 120);
                if time_now - reg.last_heart_beat > 120 {
                    reg.invalid = true;
                }
            })
        }
    }
}
