mod net;
use std::{net::UdpSocket, process::exit, sync::Arc};

use rsa::pkcs8::der::zeroize::Zeroize;
fn main() -> std::io::Result<()> {
    {
        let socket: Arc<UdpSocket> = Arc::new(
            (|| -> std::io::Result<UdpSocket> {
                let listen_port: u16 = 60000;
                match UdpSocket::bind(format!("0.0.0.0:{}", listen_port)) {
                    Ok(socket) => return Ok(socket),
                    Err(e) => return Err(e),
                }
            })()
            .expect("Failed to bind to any available port"),
        );

        let server_key_pear: pea_2_pea::shared::crypto::KeyPair =
            pea_2_pea::shared::crypto::generate_rsa_key_pair();

        let mut buf: [u8; pea_2_pea::BUFFER_SIZE] = [0; pea_2_pea::BUFFER_SIZE];
        smol::block_on(async {
            loop {
                buf.zeroize();
                match socket.recv_from(&mut buf) {
                    Ok((data_length, src)) => {
                        smol::spawn(net::handle_request(
                            buf,
                            socket.clone(),
                            src,
                            data_length,
                            server_key_pear.clone(),
                        ))
                        .detach();
                    }
                    Err(e) => {
                        eprintln!("Error receiving data: {}", e);
                        exit(-4);
                    }
                }
            }
        });

        // socket.send_to(&buf, &src)?;
    } // the socket is closed here
    Ok(())
}
