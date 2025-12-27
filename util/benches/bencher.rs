use criterion::{criterion_group, criterion_main, Criterion};

use core::hint::black_box;

use ytls_util::ByteSlices;

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("byte-slices single", |b| {
        b.iter(|| {
            let f: [u8; 2] = [42, 69];
            let bs = black_box(ByteSlices::Single(&f));
            //assert_eq!(bs.len(), 1);
            //assert_eq!(bs.total_len(), 2);
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
