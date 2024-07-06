use std::env;
use proto::zkp_auth::auth_server::AuthServer;
use server::auth::server::Server;
use tonic::transport::Server as TonicServer;

const DEFAULT_PORT: u16 = 50051;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let port = args.get(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_PORT);

    let addr = format!("[::1]:{}", port).parse()?;
    let server = Server::new()?;

    println!("ZKP Auth Server listening on {}", addr);

    TonicServer::builder()
        .add_service(AuthServer::new(server))
        .serve(addr)
        .await?;

    Ok(())
}