use std::net::UdpSocket;
fn main() -> std::io::Result<()> {
    {
        let socket: UdpSocket = (|| -> std::io::Result<UdpSocket> {
            let mut port: u16 = 59999;
            loop {
                port += 1;
                match UdpSocket::bind(format!("0.0.0.0:{}", port)) {
                    Ok(socket) => return Ok(socket),
                    Err(_) => continue, // Retry on error
                }
            }
        })()
        .expect("Failed to bind to any available port");
    }
    Ok(())
}
