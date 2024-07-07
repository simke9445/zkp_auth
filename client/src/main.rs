use std::env;

use client::auth::client::Client;
use proto::zkp_auth::AuthAlgo;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    if args.len() != 5 {
        eprintln!(
            "Usage: {} <username> <auth_algo> <server_host> <server_port>",
            args[0]
        );
        eprintln!("  auth_algo: 'dl' for Discrete Logarithm or 'ec' for Elliptic Curve");
        std::process::exit(1);
    }

    let username = &args[1];
    let auth_algo = match args[2].to_lowercase().as_str() {
        "dl" => AuthAlgo::Dl,
        "ec" => AuthAlgo::Ec,
        _ => {
            eprintln!(
                "Invalid auth_algo. Use 'dl' for Discrete Logarithm or 'ec' for Elliptic Curve"
            );
            std::process::exit(1);
        }
    };
    let server_host = &args[3];
    let server_port = &args[4];

    let mut client = Client::new(format!("http://{}:{}", server_host, server_port)).await?;

    // Register
    client.register(username, auth_algo).await?;
    println!("Registered user: {}", username);

    // Create authentication challenge
    let auth_id = client
        .create_authentication_challenge(username, auth_algo)
        .await?;
    println!("Created authentication challenge. Auth ID: {}", auth_id);

    // Verify authentication
    let session_id = client.verify_authentication(&auth_id, auth_algo).await?;
    println!("Authentication verified. Session ID: {}", session_id);

    Ok(())
}
