//! Criterion 0.8 + `hotpath-rs` benchmark suite for `tree-sitter-strata` parsing
//! and Zed / reference Tree-sitter `.scm` query execution.

use std::hint::black_box;
use std::path::PathBuf;

use hotpath::criterion::{
    BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main,
};
use streaming_iterator::StreamingIterator;
use tree_sitter::{InputEdit, Language, Parser, Point, Query, QueryCursor, Tree};

const COOKBOOK_FILES: &[(&str, &str)] = &[
    ("01_rain_swarm", "01_rain_swarm.strata"),
    ("02_soa_and_ticks", "02_soa_and_ticks.strata"),
    ("03_metroidvania_core", "03_metroidvania_core.strata"),
    ("04_cozy_valley", "04_cozy_valley.strata"),
    ("05_soulslike_combat", "05_soulslike_combat.strata"),
    ("06_battle_royale_server", "06_battle_royale_server.strata"),
    ("07_visual_boss_graph", "07_visual_boss_graph.strata"),
    (
        "08_authoritative_multiplayer",
        "08_authoritative_multiplayer.strata",
    ),
];

const ZED_QUERY_FILES: &[&str] = &[
    "highlights.scm",
    "brackets.scm",
    "indents.scm",
    "outline.scm",
    "overrides.scm",
    "runnables.scm",
];

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("resolve repo root")
}

fn load_cookbooks() -> Vec<(&'static str, String)> {
    let dir = repo_root().join("fixtures/cookbooks");
    COOKBOOK_FILES
        .iter()
        .map(|&(name, file)| {
            let src = std::fs::read_to_string(dir.join(file))
                .unwrap_or_else(|e| panic!("failed to read {file}: {e}"));
            (name, src)
        })
        .collect()
}

fn load_zed_query(lang: &Language, filename: &str) -> Query {
    let path = repo_root()
        .join("editors/zed/languages/strata")
        .join(filename);
    let src = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
    Query::new(lang, &src).unwrap_or_else(|e| panic!("failed to compile Zed query {filename}: {e}"))
}

fn strata_language() -> Language {
    tree_sitter_strata::LANGUAGE.into()
}

fn new_parser() -> Parser {
    let mut parser = Parser::new();
    parser
        .set_language(&strata_language())
        .expect("set strata language");
    parser
}

#[hotpath::measure]
fn parse_full_source(parser: &mut Parser, src: &str) -> Tree {
    parser.parse(src, None).expect("parse strata source")
}

#[hotpath::measure]
fn parse_incremental_edit(
    parser: &mut Parser,
    old_tree: &mut Tree,
    edit: &InputEdit,
    new_src: &str,
) -> Tree {
    old_tree.edit(edit);
    parser
        .parse(new_src, Some(old_tree))
        .expect("incremental parse")
}

#[hotpath::measure]
fn run_query_captures(cursor: &mut QueryCursor, query: &Query, tree: &Tree, src: &[u8]) -> usize {
    let mut count = 0usize;
    let mut captures = cursor.captures(query, tree.root_node(), src);
    while let Some((m, capture_idx)) = captures.next() {
        let capture = m.captures[*capture_idx];
        count = count.wrapping_add(capture.index as usize + capture.node.start_byte());
    }
    count
}

#[hotpath::measure]
fn run_query_matches(cursor: &mut QueryCursor, query: &Query, tree: &Tree, src: &[u8]) -> usize {
    let mut count = 0usize;
    let mut matches = cursor.matches(query, tree.root_node(), src);
    while let Some(m) = matches.next() {
        count = count.wrapping_add(m.pattern_index + m.captures.len());
    }
    count
}

fn make_single_token_edit(src: &str, needle: &str, replacement: &str) -> (String, InputEdit) {
    let start_byte = src
        .find(needle)
        .unwrap_or_else(|| panic!("needle `{needle}` not found"));
    let old_end_byte = start_byte + needle.len();
    let new_end_byte = start_byte + replacement.len();

    let prefix = &src[..start_byte];
    let row = prefix.bytes().filter(|&b| b == b'\n').count();
    let col = prefix
        .rfind('\n')
        .map_or(start_byte, |i| start_byte - i - 1);

    let mut edited = String::with_capacity(src.len() - needle.len() + replacement.len());
    edited.push_str(&src[..start_byte]);
    edited.push_str(replacement);
    edited.push_str(&src[old_end_byte..]);

    let edit = InputEdit {
        start_byte,
        old_end_byte,
        new_end_byte,
        start_position: Point::new(row, col),
        old_end_position: Point::new(row, col + needle.len()),
        new_end_position: Point::new(row, col + replacement.len()),
    };
    (edited, edit)
}

fn bench_parse_full(c: &mut Criterion) {
    let cookbooks = load_cookbooks();
    let total_bytes: u64 = cookbooks.iter().map(|(_, s)| s.len() as u64).sum();

    let mut group = c.benchmark_group("parse_full");
    let mut parser = new_parser();

    for &(target_name, _) in &[
        ("05_soulslike_combat", ""),
        ("08_authoritative_multiplayer", ""),
        ("03_metroidvania_core", ""),
    ] {
        let (_, src) = cookbooks
            .iter()
            .find(|(n, _)| *n == target_name)
            .expect("target cookbook");
        group.throughput(Throughput::Bytes(src.len() as u64));
        group.bench_with_input(BenchmarkId::from_parameter(target_name), src, |b, src| {
            b.iter(|| black_box(parse_full_source(&mut parser, black_box(src))));
        });
    }

    group.throughput(Throughput::Bytes(total_bytes));
    group.bench_function("all_8_cookbooks", |b| {
        b.iter(|| {
            let mut nodes = 0usize;
            for (_, src) in &cookbooks {
                let tree = parse_full_source(&mut parser, black_box(src));
                nodes = nodes.wrapping_add(tree.root_node().child_count());
            }
            black_box(nodes)
        });
    });

    group.finish();
}

fn bench_parse_incremental(c: &mut Criterion) {
    let cookbooks = load_cookbooks();
    let mut group = c.benchmark_group("parse_incremental");

    let cases = [
        ("05_soulslike_combat", "800.0", "850.0"),
        ("08_authoritative_multiplayer", "100.0", "125.0"),
    ];

    for (name, needle, replacement) in cases {
        let (_, src) = cookbooks
            .iter()
            .find(|(n, _)| *n == name)
            .expect("target cookbook");
        let (edited, edit) = make_single_token_edit(src, needle, replacement);
        let mut parser = new_parser();
        let base_tree = parse_full_source(&mut parser, src);

        group.throughput(Throughput::Bytes(edited.len() as u64));
        group.bench_function(BenchmarkId::new("single_token_edit", name), |b| {
            b.iter_batched(
                || base_tree.clone(),
                |mut tree| {
                    black_box(parse_incremental_edit(
                        &mut parser,
                        &mut tree,
                        &edit,
                        black_box(&edited),
                    ))
                },
                BatchSize::SmallInput,
            );
        });
    }

    group.finish();
}

fn bench_zed_queries(c: &mut Criterion) {
    let lang = strata_language();
    let cookbooks = load_cookbooks();
    let mut parser = new_parser();
    let parsed: Vec<(&'static str, &str, Tree)> = cookbooks
        .iter()
        .map(|(name, src)| (*name, src.as_str(), parse_full_source(&mut parser, src)))
        .collect();
    let total_bytes: u64 = parsed.iter().map(|(_, s, _)| s.len() as u64).sum();

    // 1. Zed highlights.scm across key cookbooks + full corpus
    let zed_highlights = load_zed_query(&lang, "highlights.scm");
    let mut group = c.benchmark_group("zed_highlights");
    let mut cursor = QueryCursor::new();

    for target_name in [
        "05_soulslike_combat",
        "08_authoritative_multiplayer",
        "03_metroidvania_core",
    ] {
        let &(_, src, ref tree) = parsed
            .iter()
            .find(|(n, _, _)| *n == target_name)
            .expect("target cookbook");
        group.throughput(Throughput::Bytes(src.len() as u64));
        group.bench_function(BenchmarkId::new("captures", target_name), |b| {
            b.iter(|| {
                black_box(run_query_captures(
                    &mut cursor,
                    &zed_highlights,
                    tree,
                    black_box(src.as_bytes()),
                ))
            });
        });
    }

    group.throughput(Throughput::Bytes(total_bytes));
    group.bench_function("captures/all_8_cookbooks", |b| {
        b.iter(|| {
            let mut acc = 0usize;
            for &(_, src, ref tree) in &parsed {
                acc = acc.wrapping_add(run_query_captures(
                    &mut cursor,
                    &zed_highlights,
                    tree,
                    black_box(src.as_bytes()),
                ));
            }
            black_box(acc)
        });
    });

    group.bench_function("matches/all_8_cookbooks", |b| {
        b.iter(|| {
            let mut acc = 0usize;
            for &(_, src, ref tree) in &parsed {
                acc = acc.wrapping_add(run_query_matches(
                    &mut cursor,
                    &zed_highlights,
                    tree,
                    black_box(src.as_bytes()),
                ));
            }
            black_box(acc)
        });
    });
    group.finish();

    // 2. All 6 Zed .scm query files on all 8 cookbooks
    let mut all_group = c.benchmark_group("zed_queries_all_cookbooks");
    all_group.throughput(Throughput::Bytes(total_bytes));
    for &query_file in ZED_QUERY_FILES {
        let query = load_zed_query(&lang, query_file);
        all_group.bench_function(query_file, |b| {
            b.iter(|| {
                let mut acc = 0usize;
                for &(_, src, ref tree) in &parsed {
                    acc = acc.wrapping_add(run_query_captures(
                        &mut cursor,
                        &query,
                        tree,
                        black_box(src.as_bytes()),
                    ));
                }
                black_box(acc)
            });
        });
    }
    all_group.finish();

    // 3. Reference tree-sitter-strata/queries/highlights.scm
    let ref_highlights =
        Query::new(&lang, tree_sitter_strata::HIGHLIGHTS_QUERY).expect("compile ref highlights");
    let mut ref_group = c.benchmark_group("ref_highlights");
    for target_name in ["05_soulslike_combat", "08_authoritative_multiplayer"] {
        let &(_, src, ref tree) = parsed
            .iter()
            .find(|(n, _, _)| *n == target_name)
            .expect("target cookbook");
        ref_group.throughput(Throughput::Bytes(src.len() as u64));
        ref_group.bench_function(BenchmarkId::new("captures", target_name), |b| {
            b.iter(|| {
                black_box(run_query_captures(
                    &mut cursor,
                    &ref_highlights,
                    tree,
                    black_box(src.as_bytes()),
                ))
            });
        });
    }
    ref_group.throughput(Throughput::Bytes(total_bytes));
    ref_group.bench_function("captures/all_8_cookbooks", |b| {
        b.iter(|| {
            let mut acc = 0usize;
            for &(_, src, ref tree) in &parsed {
                acc = acc.wrapping_add(run_query_captures(
                    &mut cursor,
                    &ref_highlights,
                    tree,
                    black_box(src.as_bytes()),
                ));
            }
            black_box(acc)
        });
    });
    ref_group.finish();
}

criterion_group!(
    benches,
    bench_parse_full,
    bench_parse_incremental,
    bench_zed_queries
);
criterion_main!(benches);
