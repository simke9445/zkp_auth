dependencies:
- brew install protobuf

tonic-build
- add to vscode settings: `"rust-analyzer.cargo.buildScripts.enable": true`
- restart vscode to enable code completion for generated modules (if it doesn't work out of the box)