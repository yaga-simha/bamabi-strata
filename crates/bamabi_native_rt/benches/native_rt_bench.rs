//! Criterion `0.8` + `hotpath-rs` microbenchmarks for `bamabi_native_rt`:
//! - `DirtyRunCoalescer` and Bevy `SelectiveMutSlice` across `0%`, `1%`, `10%`, and `100%` dirty densities
//! - `Fixed32` and `Fixed64` arithmetic + Q32.32 shifted division (`div_restoring` and `/`)
//! - Quantized net delta codecs (`quantize_scalar_f64`, `pack_bits_le`, `unpack_bits_le`, `StrataNetPacket`)

use bamabi_native_rt::{
    ChunkSliceQueryExt, DirtyRunCoalescer, Fixed32, Fixed64, SelectiveMutSlice, StrataNetPacket,
    dequantize_scalar_f64, pack_bits_le, quantize_scalar_f64, unpack_bits_le,
};
use bevy_ecs::prelude::*;
use hotpath::criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use std::hint::black_box;

#[repr(C)]
#[derive(Component, Clone, Copy, Default)]
struct Heat {
    temp: f32,
    active: u8,
    _pad: [u8; 3],
}

fn bench_selective_mut_slice_densities(c: &mut Criterion) {
    const ENTITIES: usize = 50_000;
    let mut world = World::new();
    world.spawn_batch((0..ENTITIES).map(|i| Heat {
        temp: (i % 100) as f32,
        active: 0,
        _pad: [0; 3],
    }));
    let mut q_state = world.query::<&mut Heat>();

    let mut group = c.benchmark_group("selective_mut_slice_50k");
    group.sample_size(30);
    group.throughput(Throughput::Elements(ENTITIES as u64));

    for (label, stride) in [
        ("0pct_clean", 0usize),
        ("1pct_dirty", 100usize),
        ("10pct_dirty", 10usize),
        ("100pct_dirty", 1usize),
    ] {
        group.bench_function(BenchmarkId::new("ecs_slice", label), |b| {
            b.iter(|| {
                let mut flushed = 0usize;
                if let Ok(chunks) = q_state.query_mut(&mut world).strata_contiguous_iter_mut() {
                    for heat_cm in chunks {
                        let mut slice = SelectiveMutSlice::from_contiguous_mut(heat_cm);
                        let len = slice.len();
                        if stride > 0 {
                            for row in (0..len).step_by(stride) {
                                slice.as_mut_untracked()[row].temp += 0.25;
                                slice.mark_dirty_row(row);
                            }
                        }
                        flushed += slice.flush_dirty_runs();
                    }
                }
                black_box(flushed);
            });
        });

        group.bench_function(BenchmarkId::new("coalescer_only", label), |b| {
            b.iter(|| {
                let mut coalescer = DirtyRunCoalescer::new(ENTITIES as u32);
                let mut flushes = 0usize;
                if stride > 0 {
                    for row in (0..ENTITIES).step_by(stride) {
                        coalescer.mark_row(row, |s, e| {
                            flushes += (e - s) as usize;
                        });
                    }
                }
                let total = coalescer.finish(|s, e| {
                    flushes += (e - s) as usize;
                });
                black_box((total, flushes));
            });
        });
    }
    group.finish();
}

fn bench_fixed_point_q32_32(c: &mut Criterion) {
    let f32_pairs: Vec<(Fixed32, Fixed32)> = (0..1024)
        .map(|i| {
            let a = Fixed32::from_f32(((i as f32) - 512.0) * 0.25 + 1.5);
            let b = Fixed32::from_f32(((i % 17) as f32) * 0.5 + 0.75);
            (a, b)
        })
        .collect();
    let f64_pairs: Vec<(Fixed64, Fixed64)> = (0..1024)
        .map(|i| {
            let a = Fixed64::from_f64(((i as f64) - 512.0) * 1.25 + 3.5);
            let b = Fixed64::from_f64(((i % 19) as f64) * 0.75 + 1.25);
            (a, b)
        })
        .collect();

    let mut group = c.benchmark_group("fixed_point_batch_1024");
    group.throughput(Throughput::Elements(1024));

    group.bench_function("fix32_arith_div", |b| {
        b.iter(|| {
            let mut acc = Fixed32(0);
            for &(a, d) in &f32_pairs {
                acc = acc + (a * d) - (a / d);
            }
            black_box(acc);
        });
    });

    group.bench_function("fix64_div_i128", |b| {
        b.iter(|| {
            let mut acc = Fixed64(0);
            for &(a, d) in &f64_pairs {
                acc = acc + (a / d);
            }
            black_box(acc);
        });
    });

    group.bench_function("fix64_div_restoring", |b| {
        b.iter(|| {
            let mut acc = Fixed64(0);
            for &(a, d) in &f64_pairs {
                acc = acc + a.div_restoring(d);
            }
            black_box(acc);
        });
    });

    group.finish();
}

fn bench_net_quantize_delta_codec(c: &mut Criterion) {
    const PACKETS: usize = 128;
    let inputs: Vec<(f64, f64, f64, f64)> = (0..PACKETS)
        .map(|i| {
            let t = i as f64;
            (
                (t * 1.73).sin() * 250.0,
                (t * 2.41).cos() * 250.0,
                (t * 0.37).sin() * 3.1,
                (t * 0.89).abs() % 100.0,
            )
        })
        .collect();

    let mut packets = vec![StrataNetPacket::default(); PACKETS];
    for (i, pkt) in packets.iter_mut().enumerate() {
        pkt.module_net_fingerprint = 0x1234_5678_9abc_def0;
        pkt.item_schema_fingerprint = 0xfedc_ba98_7654_3210;
        pkt.entity_bits = (i as u64) + 1;
        pkt.payload_bits = 56;
        pkt.payload_bytes = 7;
    }

    let mut group = c.benchmark_group("net_quantize_delta_128");
    group.throughput(Throughput::Elements(PACKETS as u64));

    group.bench_function("encode_quantize_pack_128", |b| {
        b.iter(|| {
            for (i, &(x, y, yaw, hp)) in inputs.iter().enumerate() {
                let pkt = &mut packets[i];
                let qx = quantize_scalar_f64(x, -256.0, 256.0, 16, None);
                let qy = quantize_scalar_f64(y, -256.0, 256.0, 16, None);
                let qyaw =
                    quantize_scalar_f64(yaw, -std::f64::consts::PI, std::f64::consts::PI, 12, None);
                let qhp = quantize_scalar_f64(hp, 0.0, 100.0, 12, None);
                pack_bits_le(&mut pkt.payload, 0, 16, qx);
                pack_bits_le(&mut pkt.payload, 16, 16, qy);
                pack_bits_le(&mut pkt.payload, 32, 12, qyaw);
                pack_bits_le(&mut pkt.payload, 44, 12, qhp);
            }
            black_box(packets[0].payload[0]);
        });
    });

    group.bench_function("decode_verify_unpack_128", |b| {
        b.iter(|| {
            let mut sum = 0.0_f64;
            for pkt in &packets {
                if pkt.verify_item_frame(0x1234_5678_9abc_def0, 0xfedc_ba98_7654_3210) {
                    let qx = unpack_bits_le(&pkt.payload, 0, 16);
                    let qy = unpack_bits_le(&pkt.payload, 16, 16);
                    let qyaw = unpack_bits_le(&pkt.payload, 32, 12);
                    let qhp = unpack_bits_le(&pkt.payload, 44, 12);
                    sum += dequantize_scalar_f64(qx, -256.0, 256.0, 16, None);
                    sum += dequantize_scalar_f64(qy, -256.0, 256.0, 16, None);
                    sum += dequantize_scalar_f64(
                        qyaw,
                        -std::f64::consts::PI,
                        std::f64::consts::PI,
                        12,
                        None,
                    );
                    sum += dequantize_scalar_f64(qhp, 0.0, 100.0, 12, None);
                }
            }
            black_box(sum);
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_selective_mut_slice_densities,
    bench_fixed_point_q32_32,
    bench_net_quantize_delta_codec
);
criterion_main!(benches);
