# ZKP Authentication System

## Overview

This project implements a Zero-Knowledge Proof (ZKP) authentication protocol based on the Chaum-Pedersen Protocol. The system is implemented in Rust, using gRPC for client-server communication, and supports both Discrete Logarithm (DL) and Elliptic Curve (EC) cryptography.

## Project Structure

```
zkp_auth/
├── aws/               # AWS deployment configurations
├── client/            # Client implementation
│   └── src/
│       └── auth/      # Client authentication logic
├── crypto/            # Cryptographic implementations
│   └── src/
│       ├── dl/        # Discrete Logarithm cryptography
│       └── ec/        # Elliptic Curve cryptography
├── proto/             # Protocol Buffer definitions
├── server/            # Server implementation
│   └── src/
│       └── auth/      # Server authentication logic
├── tests/             # Integration tests
├── util/              # Utility functions and shared code
└── docker-compose.yml # Docker setup for local deployment
```

## Features Implemented

1. ZKP Protocol implementation (Chaum-Pedersen)
2. gRPC-based client-server communication
3. Support for both Discrete Logarithm and Elliptic Curve flavors
4. Integration tests for authentication protocol and client-server interaction
5. BigNum support for large number operations
6. Modular, clean, and maintainable code architecture
7. Docker containerization for both client and server
8. AWS deployment configuration

## Algorithms and Cryptography

### Discrete Logarithm (DL) Implementation

- Uses large prime numbers for the group order (q) and modulus (p)
- Implements the Chaum-Pedersen protocol using modular exponentiation
- Parameters: 
  - q: 256-bit prime
  - p: 257-bit prime where p = 2q + 1 
  - g, h: Generators of the group of order q
- p is chosen to be a safe prime of q for simplicity

### Elliptic Curve (EC) Implementation

- Uses the secp256k1 curve (same as Bitcoin)
- Implements the Chaum-Pedersen protocol using elliptic curve point multiplication
- Parameters:
  - Curve: secp256k1
  - G, H: Points on the curve serving as generators

### Protobuf Changes

The original protobuf definition was modified to support BigNum operations and to include an AuthAlgo enum:

```protobuf
enum AuthAlgo {
    DL = 0;
    EC = 1;
}

message RegisterRequest {
    string user = 1;
    bytes y1 = 2;  // Changed from int64 to bytes
    bytes y2 = 3;  // Changed from int64 to bytes
    AuthAlgo auth_algo = 4;  // Added to specify the authentication algorithm
}

// Similar changes for other messages
```

These changes allow for:
- The transmission of large numbers as byte arrays, supporting both DL and EC implementations.
- For DL: bytes represent BigNum values
- For EC: bytes represent compressed EC points
- Specification of the authentication algorithm (DL or EC) in each request

## Tonic and tonic-build Usage

Tonic is used for implementing the gRPC server and client. tonic-build is used to generate Rust code from the protobuf definitions.

To resolve potential VS Code issues:
1. Install protobuf: `brew install protobuf`
2. Add to VS Code settings: `"rust-analyzer.cargo.buildScripts.enable": true`
3. Restart VS Code to enable code completion for generated modules

## Docker Compose Setup

The `docker-compose.yml` file sets up two services:

1. `zkp_auth_server`: The authentication server
   - Runs the server on 0.0.0.0:50051

2. `zkp_auth_client`: The client application
   - Sets defaults for environment variables username and auth algo
   - Runs the client, connecting to the server, executing the authentication flow

## Key Abstractions

- `EcProver` / `DlProver`: Implement the prover's side of the ZKP protocol
- `EcVerifier` / `DlVerifier`: Implement the verifier's side of the ZKP protocol
- `EcAuthClient` / `DlAuthClient`: Respective auth client implementation
- `EcAuthServer` / `DlAuthServer`: Respective auth server implementation

## Testing

- Authentication protocol tests in `crypto/src/dl/` and `crypto/src/ec/`
- Integration tests in `tests/` directory

## Dependencies

- Rust 1.79 or later
- OpenSSL
- Protobuf compiler

## Setup and Installation

To set up the project and install all dependencies:

1. Clone the repository
2. Navigate to the project root
3. Run the following command to install all workspace dependencies:

```bash
cargo build
```

## Running the Server and Client

### Server

To run the server:

```bash
cargo run --package server --bin server -- 0.0.0.0 50051
```

This command starts the server listening on all interfaces (`0.0.0.0`) on port 50051.

### Client

To run the client:

```bash
cargo run --package client --bin client -- username dl 0.0.0.0 50051
```

The client's `main.rs` implements a complete authentication flow:

1. Parses command-line arguments for username, auth algo (dl or ec), server host, and port.
2. Establishes a connection with the server.
3. Performs user registration, generating a secret `x` on the fly.
4. Initiates an authentication challenge.
5. Completes the authentication process.

## Usage

For local testing using Docker:

```bash
docker-compose up --build
```

For AWS deployment, refer to the AWS CDK stack in the `aws/` directory.

## Design Principles

1. Modularity: Separate DL and EC implementations for independent development.
2. Abstraction: Generalized Chaum-Pedersen protocol for both DL and EC.
3. Security: Leveraging established OpenSSL library.
4. Flexibility: Runtime choice between DL and EC algorithms.

## Assumptions and Limitations

1. Trusted parameter setup and distribution.
2. In-memory, non-persistent user registrations.
3. Simplified error handling for demonstration purposes.

## Potential Improvements

1. Persistent storage for user registrations.
2. Enhanced error handling and logging.
3. Dynamic parameter distribution: Implement secure method for server to distribute updated parameters to clients.