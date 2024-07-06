use proto::zkp_auth::auth_server::AuthServer;
use server::auth::server::Server;
use tonic::transport::Server as TonicServer;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "[::1]:50051".parse()?;
    let server = Server::new()?;

    println!("ZKP Auth Server listening on {}", addr);

    TonicServer::builder()
        .add_service(AuthServer::new(server))
        .serve(addr)
        .await?;

    Ok(())
}
