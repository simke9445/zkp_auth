use client::auth::client::Client;
use proto::zkp_auth::auth_server::AuthServer;
use proto::zkp_auth::AuthAlgo;
use server::auth::server::Server as ZkpServer;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::time::sleep;
use tonic::transport::Server;

async fn start_server(port: u16) {
    let addr = format!("[::1]:{}", port).parse::<SocketAddr>().unwrap();
    let server = ZkpServer::new().unwrap();

    tokio::spawn(async move {
        Server::builder()
            .add_service(AuthServer::new(server))
            .serve(addr)
            .await
            .unwrap();
    });

    // Give the server a moment to start
    sleep(Duration::from_millis(100)).await;
}

async fn run_client_flow(
    port: u16,
    username: &str,
    algo: AuthAlgo,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut client = Client::new(format!("http://[::1]:{}", port)).await?;

    // Register
    client.register(username, algo).await?;

    // Create authentication challenge
    let auth_id = client
        .create_authentication_challenge(username, algo)
        .await?;

    // Verify authentication
    let session_id = client.verify_authentication(&auth_id, algo).await?;

    println!("session_id: {:?}", session_id);

    // If we got here without errors, the flow succeeded
    Ok(())
}

#[tokio::test]
async fn test_ec_authentication_flow() {
    let port = 50052;
    start_server(port).await;

    let result = run_client_flow(port, "test_user_ec", AuthAlgo::Ec).await;
    assert!(
        result.is_ok(),
        "EC authentication flow failed: {:?}",
        result.err()
    );
}

#[tokio::test]
async fn test_dl_authentication_flow() {
    let port = 50053;
    start_server(port).await;

    let result = run_client_flow(port, "test_user_dl", AuthAlgo::Dl).await;
    assert!(
        result.is_ok(),
        "DL authentication flow failed: {:?}",
        result.err()
    );
}
