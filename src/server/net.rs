pub async fn handle_request(
    mut buf: [u8; pea_2_pea::BUFFER_SIZE],
    socket: std::sync::Arc<std::net::UdpSocket>,
    src: core::net::SocketAddr,
    data_len: usize,
) {
    #[cfg(target_endian = "little")]
    buf.reverse();
}
