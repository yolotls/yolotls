use criterion::{criterion_group, criterion_main, Criterion};

use core::hint::black_box;
use hex_literal::hex;

use ytls_util::Nonce12;

fn criterion_benchmark(c: &mut Criterion) {
    let iv_bytes: [u8; 12] = hex!("6fac81d4f2c3bebe02b8b375");
    let mut running_nonce = Nonce12::from_ks_iv(&iv_bytes);

    c.bench_function("nonce handouts", |b| {
        b.iter(|| {
            let _cur = black_box(running_nonce.use_and_incr());
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
