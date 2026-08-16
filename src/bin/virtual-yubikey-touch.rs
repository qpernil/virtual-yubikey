use std::io;
use std::os::unix::net::UnixDatagram;

const TOUCH_SOCKET: &str = "/run/virtual-yubikey/touch.sock";
const COMMAND_TOUCH: &[u8] = b"T";

fn main() {
    if let Err(error) = touch() {
        eprintln!("virtual-yubikey-touch: {error}");
        std::process::exit(1);
    }
}

fn touch() -> io::Result<()> {
    let socket = UnixDatagram::unbound()?;
    socket
        .send_to(COMMAND_TOUCH, TOUCH_SOCKET)
        .map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("no virtual YubiKey operation is waiting for touch: {error}"),
            )
        })?;
    println!("Virtual YubiKey touched");
    Ok(())
}
