//! Criterion `0.8` + `hotpath-rs` microbenchmarks for `strata_mir`:
//! - MIR lowering + `verify_mir` + passes across representative cookbooks
//! - 2-pass counting-sort CSR spatial rebuild and `query_disc` scaling (`N = 1k, 10k, 50k`)

use hotpath::criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::fs;
use std::hint::black_box;
use std::path::PathBuf;
use strata_mir::{csr_cell_range, lower_to_mir, verify_mir};
use strata_sema::analyze_source;

const MIR_COOKBOOKS: &[&str] = &[
    "01_rain_swarm",
    "03_metroidvania_core",
    "04_cozy_valley",
    "05_soulslike_combat",
    "08_authoritative_multiplayer",
];

const SPATIAL_GRID_SRC: &str = r#"
module bench::spatial_mir @version(1.0.0);

component Pos2 { xy: vec2 = vec2(0.0, 0.0) }
tag Actor;
component HitStat { hits: u32 = 0 }

spatial_grid Grid2D(
    cell_size: 4.0_m,
    bounds: vec2(-128.0_m, -128.0_m)..vec2(128.0_m, 128.0_m),
    capacity: 1024,
) over Actor by Pos2.xy;

sys scan(g: &res Grid2D) {
    for row in query(p: &Pos2, h: &mut HitStat) {
        let mut c: u32 = 0;
        for hit in g.query_disc(row.p.xy, 6.0_m) {
            let _ = hit.id;
            c += 1;
        }
        row.h.hits = c;
    }
}

schedule FixedUpdate { scan }
"#;

fn bench_mir_lower_and_verify(c: &mut Criterion) {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("fixtures")
        .join("cookbooks");

    let mut analyzed_modules: Vec<(String, strata_sema::AnalyzedModule)> = MIR_COOKBOOKS
        .iter()
        .map(|&name| {
            let path = dir.join(format!("{name}.strata"));
            let src = fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("failed reading {}: {e}", path.display()));
            let analyzed = analyze_source(format!("{name}.strata"), &src);
            assert!(analyzed.ok(), "cookbook `{name}` sema failed");
            (name.to_owned(), analyzed)
        })
        .collect();

    let spatial_analyzed = analyze_source("spatial_mir.strata", SPATIAL_GRID_SRC);
    assert!(spatial_analyzed.ok(), "SPATIAL_GRID_SRC sema failed");
    analyzed_modules.push(("spatial_grid_csr".to_owned(), spatial_analyzed));

    let mut group = c.benchmark_group("mir_lower_verify");
    group.sample_size(25);
    for (name, analyzed) in &analyzed_modules {
        group.bench_with_input(BenchmarkId::from_parameter(name), analyzed, |b, mod_hir| {
            b.iter(|| {
                let mir = lower_to_mir(black_box(mod_hir));
                let ok = verify_mir(&mir).is_ok();
                black_box((ok, mir.functions.len()));
            });
        });
    }
    group.finish();
}

/// Pre-allocated scratch buffers implementing Strata's 2-pass counting-sort CSR spatial grid
/// (`0 B` steady-state heap allocations per tick).
struct CsrGridScratch {
    cols: usize,
    rows: usize,
    bounds_min: [f32; 2],
    inv_cell_size: f32,
    counts: Vec<u32>,
    offsets: Vec<u32>,
    write_cursors: Vec<u32>,
    entity_cells: Vec<u32>,
    sorted_entities: Vec<u64>,
    sorted_pos: Vec<[f32; 2]>,
}

impl CsrGridScratch {
    fn new(cols: usize, rows: usize, bounds_min: [f32; 2], cell_size: f32, n: usize) -> Self {
        let cells = cols * rows;
        Self {
            cols,
            rows,
            bounds_min,
            inv_cell_size: 1.0 / cell_size,
            counts: vec![0; cells],
            offsets: vec![0; cells + 1],
            write_cursors: vec![0; cells],
            entity_cells: vec![0; n],
            sorted_entities: vec![0; n],
            sorted_pos: vec![[0.0; 2]; n],
        }
    }

    #[inline]
    fn cell_coords(&self, x: f32, y: f32) -> (usize, usize) {
        let cx = (((x - self.bounds_min[0]) * self.inv_cell_size).floor() as isize)
            .clamp(0, (self.cols - 1) as isize) as usize;
        let cy = (((y - self.bounds_min[1]) * self.inv_cell_size).floor() as isize)
            .clamp(0, (self.rows - 1) as isize) as usize;
        (cx, cy)
    }

    fn rebuild_2pass(&mut self, entities: &[u64], positions: &[[f32; 2]]) {
        self.counts.fill(0);
        // Pass 1: count entities per cell and cache quantized cell index.
        for (i, &[x, y]) in positions.iter().enumerate() {
            let (cx, cy) = self.cell_coords(x, y);
            let cell = cy * self.cols + cx;
            self.entity_cells[i] = cell as u32;
            self.counts[cell] += 1;
        }
        // Exclusive prefix sum.
        let mut acc = 0u32;
        for (cell, &cnt) in self.counts.iter().enumerate() {
            self.offsets[cell] = acc;
            self.write_cursors[cell] = acc;
            acc += cnt;
        }
        self.offsets[self.counts.len()] = acc;

        // Pass 2: scatter into dense CSR arrays.
        for i in 0..positions.len() {
            let cell = self.entity_cells[i] as usize;
            let dst = self.write_cursors[cell] as usize;
            self.write_cursors[cell] += 1;
            self.sorted_entities[dst] = entities[i];
            self.sorted_pos[dst] = positions[i];
        }
    }

    fn query_disc(&self, center: [f32; 2], radius: f32) -> u32 {
        let r2 = radius * radius;
        let (min_cx, min_cy) = self.cell_coords(center[0] - radius, center[1] - radius);
        let (max_cx, max_cy) = self.cell_coords(center[0] + radius, center[1] + radius);
        let total = self.sorted_entities.len();
        let mut hits = 0u32;
        for cy in min_cy..=max_cy {
            for cx in min_cx..=max_cx {
                let cell = cy * self.cols + cx;
                if let Some((start, end)) = csr_cell_range(&self.offsets, cell, total) {
                    for idx in start..end {
                        let p = self.sorted_pos[idx];
                        let dx = p[0] - center[0];
                        let dy = p[1] - center[1];
                        if dx * dx + dy * dy <= r2 {
                            hits += 1;
                        }
                    }
                }
            }
        }
        hits
    }
}

fn bench_mir_spatial_csr_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("mir_spatial_csr_scaling");
    group.sample_size(25);

    for &n in &[1_000usize, 10_000, 50_000] {
        let entities: Vec<u64> = (0..n).map(|i| i as u64 + 1).collect();
        let positions: Vec<[f32; 2]> = (0..n)
            .map(|i| {
                let a = (i as f32) * 0.618_034;
                let x = ((a * 199.0).sin()) * 120.0;
                let y = ((a * 137.0).cos()) * 120.0;
                [x, y]
            })
            .collect();
        let mut scratch = CsrGridScratch::new(64, 64, [-128.0, -128.0], 4.0, n);
        scratch.rebuild_2pass(&entities, &positions);

        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::new("csr_rebuild_2pass", n), &n, |b, _| {
            b.iter(|| {
                scratch.rebuild_2pass(black_box(&entities), black_box(&positions));
                black_box(scratch.offsets[scratch.counts.len()]);
            });
        });

        group.bench_with_input(BenchmarkId::new("csr_query_disc_64", n), &n, |b, _| {
            b.iter(|| {
                let mut total_hits = 0u32;
                for q in 0..64 {
                    let cx = ((q % 8) as f32 - 3.5) * 20.0;
                    let cy = ((q / 8) as f32 - 3.5) * 20.0;
                    total_hits += scratch.query_disc(black_box([cx, cy]), 6.0);
                }
                black_box(total_hits);
            });
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_mir_lower_and_verify,
    bench_mir_spatial_csr_scaling
);
criterion_main!(benches);
