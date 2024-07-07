use proto::zkp_auth::auth_server::AuthServer;
use server::auth::server::Server as ZkpServer;
use std::env;
use tonic::transport::Server;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    if args.len() != 3 {
        eprintln!("Usage: {} <host> <port>", args[0]);
        std::process::exit(1);
    }

    let host = &args[1];
    let port = &args[2];

    let addr = format!("{}:{}", host, port).parse()?;
    let server = ZkpServer::new()?;

    println!("ZKP Auth Server listening on {}", addr);

    Server::builder()
        .add_service(AuthServer::new(server))
        .serve(addr)
        .await?;

    Ok(())
}
