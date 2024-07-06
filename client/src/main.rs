use std::error::Error;

use client::auth::client::Client;
use proto::zkp_auth::AuthAlgo;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut client = Client::new("http://[::1]:50051".to_string()).await?;

    let user = String::from("alice");
    let algo = AuthAlgo::Ec;

    // Register a user
    client.register(&user, algo).await?;

    // Start authentication
    let auth_id = client.create_authentication_challenge(&user, algo).await?;

    // Complete authentication
    let session_id = client.verify_authentication(&auth_id, algo).await?;

    println!("Authentication successful. Session ID: {}", session_id);

    Ok(())
}
