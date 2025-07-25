use rsa::{Pkcs1v15Encrypt, pkcs1::EncodeRsaPublicKey, pkcs8::DecodePublicKey};
pub async fn handle_request(
    buf: [u8; pea_2_pea::BUFFER_SIZE],
    socket: std::sync::Arc<std::net::UdpSocket>,
    src: core::net::SocketAddr,
    data_len: usize,
    server_key_pair: pea_2_pea::shared::crypto::KeyPair,
) {
    let mut rng: rand::prelude::ThreadRng = rand::thread_rng();

    match buf[0] {
        x if x == pea_2_pea::ServerMethods::QUERY as u8 => {
            #[cfg(debug_assertions)]
            eprintln!("QUERY method");

            let client_public_key: rsa::RsaPublicKey =
                match rsa::RsaPublicKey::from_public_key_der(&buf[1..]) {
                    Ok(key) => key,
                    Err(e) => {
                        eprintln!("Error serializing client key: {}", e);
                        return;
                    }
                };

            let pkcs_encoded_public_key: rsa::pkcs8::Document =
                server_key_pair.public_key.to_pkcs1_der().unwrap();
            let mut send_vec: Vec<u8> = pkcs_encoded_public_key.into_vec();
            send_vec.insert(0, pea_2_pea::ServerMethods::QUERY as u8);

            let send_vec_encrypted: Vec<u8> = client_public_key
                .encrypt(&mut rng, Pkcs1v15Encrypt, &send_vec)
                .unwrap();

            match socket.send_to(&send_vec_encrypted, &src) {
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
