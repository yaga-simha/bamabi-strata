#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Binary entrypoint for `strata-lsp` stdio Language Server.

use strata_lsp::StrataLspBackend;
use tower_lsp::{LspService, Server};

#[tokio::main]
async fn main() {
    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();
    let (service, socket) = LspService::new(StrataLspBackend::new);
    Server::new(stdin, stdout, socket).serve(service).await;
}
