//! Build script compiling the generated C parser (`src/parser.c`) for `tree-sitter-strata`.

fn main() {
    let src_dir = std::path::Path::new("src");
    let parser_path = src_dir.join("parser.c");

    println!("cargo:rerun-if-changed={}", parser_path.display());

    let mut c_config = cc::Build::new();
    c_config.std("c11").include(src_dir);
    c_config.file(&parser_path);
    c_config.compile("tree-sitter-strata");
}
