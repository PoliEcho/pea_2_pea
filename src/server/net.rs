pub async fn handle_request(
    buf: [u8; pea_2_pea::BUFFER_SIZE],
    socket: std::sync::Arc<std::net::UdpSocket>,
    src: core::net::SocketAddr,
    data_len: usize,
) {
    let mut rng: rand::prelude::ThreadRng = rand::thread_rng();

    match buf[0] {
        x if x == pea_2_pea::ServerMethods::QUERY as u8 => {
            #[cfg(debug_assertions)]
            eprintln!("QUERY method");

            let client_sock_addr_str: String = src.to_string();
            let mut send_vec: Vec<u8> = client_sock_addr_str.into();
            send_vec.insert(0, pea_2_pea::ServerMethods::QUERY as u8);

            match socket.send_to(&send_vec, &src) {
                Ok(s) => {
                    #[cfg(debug_assertions)]
                    eprintln!("send {} bytes", s);
                }
                Err(e) => {
                    eprintln!("Error snding data: {}", e);
                }
            }
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
