use std::io::ErrorKind;
use std::net::{SocketAddr, UdpSocket};

#[cfg(target_os = "windows")]
use std::os::windows::io::AsRawSocket;
#[cfg(target_os = "windows")]
use winapi::shared::minwindef::{BOOL, DWORD, FALSE};
#[cfg(target_os = "windows")]
use winapi::um::mswsock::SIO_UDP_CONNRESET;
#[cfg(target_os = "windows")]
use winapi::um::winsock2::{SOCKET_ERROR, WSAIoctl};

#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;

#[cfg(target_os = "windows")]
fn enable_icmp_errors(socket: &UdpSocket) -> std::io::Result<()> {
    let socket_handle = socket.as_raw_socket();
    let mut bytes_returned: DWORD = 0;
    let enable: BOOL = FALSE;

    let result = unsafe {
        WSAIoctl(
            socket_handle as usize,
            SIO_UDP_CONNRESET,
            &enable as *const _ as *mut _,
            std::mem::size_of::<BOOL>() as DWORD,
            std::ptr::null_mut(),
            0,
            &mut bytes_returned,
            std::ptr::null_mut(),
            None,
        )
    };

    if result == SOCKET_ERROR {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn enable_icmp_errors(socket: &UdpSocket) -> std::io::Result<()> {
    let fd = socket.as_raw_fd();
    let optval: libc::c_int = 1;

    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_IP,
            libc::IP_RECVERR,
            &optval as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };

    if ret < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn check_icmp_error_queue(socket: &UdpSocket) -> std::io::Result<()> {
    use libc::{MSG_ERRQUEUE, iovec, msghdr, recvmsg};

    let fd = socket.as_raw_fd();
    let mut buf = [0u8; 1024];
    let mut control_buf = [0u8; 1024];

    let mut iov = iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };

    let mut msg: msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = control_buf.len();

    let result = unsafe { recvmsg(fd, &mut msg, MSG_ERRQUEUE) };

    if result < 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::WouldBlock {
            return Ok(());
        }
        return Err(error);
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::NetworkUnreachable,
        "ICMP destination unreachable received",
    ))
}

#[cfg(target_os = "windows")]
fn check_icmp_error_queue(_socket: &UdpSocket) -> std::io::Result<()> {
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn enable_icmp_errors(_socket: &UdpSocket) -> std::io::Result<()> {
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn check_icmp_error_queue(_socket: &UdpSocket) -> std::io::Result<()> {
    Ok(())
}
