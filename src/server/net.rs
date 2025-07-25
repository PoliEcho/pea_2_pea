pub async fn handle_request(
    mut buf: [u8; pea_2_pea::BUFFER_SIZE],
    socket: std::sync::Arc<std::net::UdpSocket>,
    src: core::net::SocketAddr,
    data_len: usize,
    server_key_pair: pea_2_pea::shared::crypto::KeyPair,
) {
    #[cfg(target_endian = "little")]
    buf.reverse();

    match buf[0] {
        x if x == pea_2_pea::ServerMethods::QUERY as u8 => {
            #[cfg(debug_assertions)]
            println!("QUERY method");
        }
        x if x == pea_2_pea::ServerMethods::GET as u8 => {
            #[cfg(debug_assertions)]
            println!("GET method");
        }
        x if x == pea_2_pea::ServerMethods::REGISTER as u8 => {
            #[cfg(debug_assertions)]
            println!("REGISTER method");
        }
        x if x == pea_2_pea::ServerMethods::HEARTBEAT as u8 => {
            #[cfg(debug_assertions)]
            println!("HEARTBEAT method");
        }
        _ => {
            #[cfg(debug_assertions)]
            println!("Unknown method");
            return;
        }
    }
}
