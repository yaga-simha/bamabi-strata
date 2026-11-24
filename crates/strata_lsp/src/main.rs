#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Binary entrypoint for `strata-lsp` stdio Language Server.

use tower_lsp::Server;

#[tokio::main]
async fn main() {
    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();
    let (service, socket) = strata_lsp::build_lsp_service();
    Server::new(stdin, stdout, socket).serve(service).await;
}
