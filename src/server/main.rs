mod net;
use std::{net::UdpSocket, process::exit, sync::Arc};
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

        let mut buf: [u8; pea_2_pea::BUFFER_SIZE] = [0; pea_2_pea::BUFFER_SIZE];
        smol::block_on(async {
            loop {
                match socket.recv_from(&mut buf) {
                    Ok((data_length, src)) => {
                        smol::spawn(net::handle_request(buf, socket.clone(), src, data_length))
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
