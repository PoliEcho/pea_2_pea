use pea_2_pea::*;
pub fn send_general_error_to_client<T: std::error::Error>(
    dst: core::net::SocketAddr,
    e: T,
    socket: std::sync::Arc<std::net::UdpSocket>,
) {
    let mut resp_buf: Box<[u8]> = vec![0; e.to_string().len() + 1].into_boxed_slice();

    resp_buf[0] = ServerResponse::GENERAL_ERROR as u8; // set 1st byte to ERROR
    resp_buf[1..1 + e.to_string().len()].copy_from_slice(e.to_string().as_bytes()); // send error text to client

    let _ = socket.send_to(&[ServerResponse::GENERAL_ERROR as u8], dst);
}
