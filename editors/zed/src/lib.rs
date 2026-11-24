#![forbid(unsafe_code)]

//! Zed editor extension entrypoint for **Strata v2.0**, wiring the stdio `strata-lsp` language
//! server via `zed_extension_api`.

use zed_extension_api::lsp::{Completion, CompletionKind, Symbol, SymbolKind};
use zed_extension_api::settings::LspSettings;
use zed_extension_api::{
    self as zed, CodeLabel, CodeLabelSpan, LanguageServerId, Os, Result, Worktree,
};

/// Zed WebAssembly extension state for Strata v2.0.
struct StrataExtension;

impl StrataExtension {
    const SERVER_ID: &'static str = "strata-lsp";

    fn binary_name() -> &'static str {
        let (os, _arch) = zed::current_platform();
        match os {
            Os::Windows => "strata-lsp.exe",
            Os::Mac | Os::Linux => "strata-lsp",
        }
    }

    fn find_worktree_target_binary(worktree: &Worktree, bin_name: &str) -> Option<String> {
        let root = worktree.root_path();
        let trimmed = root.trim_end_matches(['/', '\\']);
        let sep = if trimmed.contains('\\') { '\\' } else { '/' };

        for profile in ["release", "debug"] {
            let candidate = format!("{trimmed}{sep}target{sep}{profile}{sep}{bin_name}");
            if let Some(found) = worktree.which(&candidate) {
                return Some(found);
            }
            let dep_rel = format!("target/{profile}/strata-lsp.d");
            if worktree.read_text_file(&dep_rel).is_ok() {
                return Some(candidate);
            }
        }
        None
    }

    fn literal_completion_label(
        name: String,
        highlight: &'static str,
        detail: Option<String>,
        detail_sep: &'static str,
    ) -> CodeLabel {
        let name_len = name.len();
        let mut spans = Vec::with_capacity(if detail.is_some() { 2 } else { 1 });
        spans.push(CodeLabelSpan::literal(name, Some(highlight.to_owned())));
        if let Some(d) = detail {
            let mut text = String::with_capacity(detail_sep.len() + d.len());
            text.push_str(detail_sep);
            text.push_str(&d);
            spans.push(CodeLabelSpan::literal(text, Some("comment".to_owned())));
        }
        CodeLabel {
            code: String::new(),
            spans,
            filter_range: (0..name_len).into(),
        }
    }
}

impl zed::Extension for StrataExtension {
    fn new() -> Self {
        Self
    }

    fn language_server_command(
        &mut self,
        language_server_id: &LanguageServerId,
        worktree: &Worktree,
    ) -> Result<zed::Command> {
        if language_server_id.as_ref() != Self::SERVER_ID {
            return Err(format!(
                "unsupported language server id `{language_server_id}` (expected `{}`)",
                Self::SERVER_ID
            ));
        }

        let binary_settings = LspSettings::for_worktree(Self::SERVER_ID, worktree)
            .ok()
            .and_then(|s| s.binary);

        let (configured_path, args, env) = match binary_settings {
            Some(b) => {
                let env = b
                    .env
                    .map(|map| map.into_iter().collect::<Vec<_>>())
                    .unwrap_or_else(|| worktree.shell_env());
                (b.path, b.arguments.unwrap_or_default(), env)
            }
            None => (None, Vec::new(), worktree.shell_env()),
        };

        if let Some(configured_path) = configured_path {
            return Ok(zed::Command {
                command: configured_path,
                args,
                env,
            });
        }

        let bin_name = Self::binary_name();
        if let Some(path) = worktree
            .which("strata-lsp")
            .or_else(|| worktree.which(bin_name))
        {
            return Ok(zed::Command {
                command: path,
                args,
                env,
            });
        }

        if let Some(local_target_bin) = Self::find_worktree_target_binary(worktree, bin_name) {
            return Ok(zed::Command {
                command: local_target_bin,
                args,
                env,
            });
        }

        Err(
            "`strata-lsp` binary not found on PATH or in workspace `target/{release,debug}/`. \
             Install it with `cargo install --path crates/strata_lsp` (or `cargo build --release -p strata_lsp`), \
             or set `lsp.strata-lsp.binary.path` in Zed `settings.json`."
                .to_owned(),
        )
    }

    fn language_server_initialization_options(
        &mut self,
        language_server_id: &LanguageServerId,
        worktree: &Worktree,
    ) -> Result<Option<zed::serde_json::Value>> {
        Ok(
            LspSettings::for_worktree(language_server_id.as_ref(), worktree)
                .ok()
                .and_then(|s| s.initialization_options),
        )
    }

    fn language_server_workspace_configuration(
        &mut self,
        language_server_id: &LanguageServerId,
        worktree: &Worktree,
    ) -> Result<Option<zed::serde_json::Value>> {
        Ok(
            LspSettings::for_worktree(language_server_id.as_ref(), worktree)
                .ok()
                .and_then(|s| s.settings),
        )
    }

    fn label_for_completion(
        &self,
        language_server_id: &LanguageServerId,
        completion: Completion,
    ) -> Option<CodeLabel> {
        if language_server_id.as_ref() != Self::SERVER_ID {
            return None;
        }
        let kind = completion.kind?;
        let name = completion.label;
        let detail = completion.detail;

        match kind {
            CompletionKind::Function => {
                if let Some(sig) = detail.as_deref().and_then(|d| d.strip_prefix("fn")) {
                    let name_len = name.len();
                    let sig_end = 3 + name_len + sig.len();
                    let mut code = String::with_capacity(sig_end + 3);
                    code.push_str("fn ");
                    code.push_str(&name);
                    code.push_str(sig);
                    code.push_str(" {}");
                    return Some(CodeLabel {
                        code,
                        spans: vec![CodeLabelSpan::code_range(0..sig_end)],
                        filter_range: (3..3 + name_len).into(),
                    });
                }
                Some(Self::literal_completion_label(
                    name, "function", detail, "  ",
                ))
            }
            CompletionKind::Struct | CompletionKind::Class | CompletionKind::Interface => {
                Some(Self::literal_completion_label(name, "type", detail, "  "))
            }
            CompletionKind::Enum => {
                Some(Self::literal_completion_label(name, "enum", detail, "  "))
            }
            CompletionKind::EnumMember => Some(Self::literal_completion_label(
                name, "variant", detail, "  ",
            )),
            CompletionKind::Field => Some(Self::literal_completion_label(
                name, "property", detail, ": ",
            )),
            CompletionKind::Property => {
                let name_len = name.len();
                let mut display = String::with_capacity(1 + name_len);
                display.push('@');
                display.push_str(&name);
                Some(CodeLabel {
                    code: String::new(),
                    spans: vec![CodeLabelSpan::literal(
                        display,
                        Some("attribute".to_owned()),
                    )],
                    filter_range: (1..1 + name_len).into(),
                })
            }
            CompletionKind::Constant => Some(Self::literal_completion_label(
                name, "constant", detail, "  ",
            )),
            CompletionKind::TypeParameter => Some(Self::literal_completion_label(
                name,
                "type.builtin",
                detail,
                "  ",
            )),
            CompletionKind::Keyword => {
                Some(Self::literal_completion_label(name, "keyword", None, ""))
            }
            _ => None,
        }
    }

    fn label_for_symbol(
        &self,
        language_server_id: &LanguageServerId,
        symbol: Symbol,
    ) -> Option<CodeLabel> {
        if language_server_id.as_ref() != Self::SERVER_ID {
            return None;
        }
        let (prefix, highlight) = match symbol.kind {
            SymbolKind::Struct | SymbolKind::Object => ("component ", "type"),
            SymbolKind::Enum => ("enum ", "enum"),
            SymbolKind::EnumMember => ("variant ", "variant"),
            SymbolKind::Interface => ("rpc ", "type"),
            SymbolKind::Function => ("fn ", "function"),
            SymbolKind::Method => ("test ", "function"),
            SymbolKind::Event => ("event ", "type"),
            SymbolKind::Class => ("fsm ", "type"),
            SymbolKind::Constant => ("const ", "constant"),
            SymbolKind::Field => ("field ", "property"),
            SymbolKind::Module | SymbolKind::Namespace => ("module ", "namespace"),
            _ => return None,
        };
        let filter_start = prefix.len();
        let name = symbol.name;
        let name_len = name.len();
        Some(CodeLabel {
            code: String::new(),
            spans: vec![
                CodeLabelSpan::literal(prefix, Some("keyword".to_owned())),
                CodeLabelSpan::literal(name, Some(highlight.to_owned())),
            ],
            filter_range: (filter_start..filter_start + name_len).into(),
        })
    }
}

zed::register_extension!(StrataExtension);
