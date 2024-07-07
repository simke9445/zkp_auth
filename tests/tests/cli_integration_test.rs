use std::env;
use std::process::{Child, Command};
use std::thread;
use std::time::Duration;

fn start_server(host: &str, port: u16) -> Child {
    let cargo = env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    Command::new(cargo)
        .args(&[
            "run",
            "--package",
            "server",
            "--bin",
            "server",
            "--",
            &host,
            &port.to_string(),
        ])
        .spawn()
        .expect("Failed to start server")
}

fn run_client(
    username: &str,
    algo: &str,
    server_host: &str,
    server_port: u16,
) -> std::io::Result<()> {
    let cargo = env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let output = Command::new(cargo)
        .args(&[
            "run",
            "--package",
            "client",
            "--bin",
            "client",
            "--",
            username,
            algo,
            &server_host.to_string(),
            &server_port.to_string(),
        ])
        .output()?;

    if !output.status.success() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!(
                "Client command failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ),
        ));
    }

    println!("Client output: {}", String::from_utf8_lossy(&output.stdout));
    Ok(())
}

#[test]
fn test_ec_authentication_flow() {
    let server_host = "0.0.0.0";
    let server_port = 50052;
    let mut server = start_server(server_host, server_port);

    // Wait for the server to start
    thread::sleep(Duration::from_secs(2));

    let result = run_client("test_user_ec", "ec", server_host, server_port);
    assert!(
        result.is_ok(),
        "EC authentication flow failed: {:?}",
        result.err()
    );

    server.kill().expect("Failed to kill server process");
}

#[test]
fn test_dl_authentication_flow() {
    let server_host = "0.0.0.0";
    let server_port = 50053;
    let mut server = start_server(server_host, server_port);

    // Wait for the server to start
    thread::sleep(Duration::from_secs(2));

    let result = run_client("test_user_dl", "dl", server_host, server_port);
    assert!(
        result.is_ok(),
        "DL authentication flow failed: {:?}",
        result.err()
    );

    server.kill().expect("Failed to kill server process");
}
