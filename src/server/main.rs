mod net;
mod types;
mod utils;
use std::{
    net::UdpSocket,
    process::exit,
    sync::{Arc, RwLock},
};

use orx_concurrent_vec::ConcurrentVec;
fn main() -> std::io::Result<()> {
    {
        let socket: Arc<UdpSocket> = Arc::new(
            (|| -> std::io::Result<UdpSocket> {
                let listen_port: u16 = pea_2_pea::SERVER_PORT;
                match UdpSocket::bind(format!("0.0.0.0:{}", listen_port)) {
                    Ok(socket) => return Ok(socket),
                    Err(e) => return Err(e),
                }
            })()
            .expect("Failed to bind to any available port"),
        );

        let registration_vector: Arc<ConcurrentVec<types::Registration>> =
            Arc::new(orx_concurrent_vec::ConcurrentVec::new());

        let mut buf: [u8; pea_2_pea::BUFFER_SIZE] = [0u8; pea_2_pea::BUFFER_SIZE];
        smol::block_on(async {
            loop {
                buf.fill(0);
                match socket.recv_from(&mut buf) {
                    Ok((data_length, src)) => {
                        smol::spawn(net::handle_request(
                            buf,
                            socket.clone(),
                            src,
                            data_length,
                            registration_vector.clone(),
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
