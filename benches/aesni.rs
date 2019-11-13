extern crate criterion;

use criterion::*;
use crypto_pimitives::*;

fn bench_aes_128_ecb_enc(c: &mut Criterion) {
    let test_size = 16*1024;
    let pt = vec![0u8; test_size];
    let mut ct = vec![0u8; test_size];
    let key = vec![0u8; 15*16];

    let mut group = c.benchmark_group("aes-ni");

    group.throughput(Throughput::Bytes(test_size as u64));

    group.bench_function("aes_128_ecb_enc",|b| b.iter(||
        aesni_ecb_enc(&mut ct, &pt, test_size/16, KeySize::K128, &key)
    ));

    group.bench_function("aes_196_ecb_enc",|b| b.iter(||
        aesni_ecb_enc(&mut ct, &pt, test_size/16, KeySize::K196, &key)
    ));

    group.bench_function("aes_256_ecb_enc",|b| b.iter(||
        aesni_ecb_enc(&mut ct, &pt, test_size/16, KeySize::K256, &key)
    ));

    group.finish();
}

criterion_group!(benches, bench_aes_128_ecb_enc);
criterion_main!(benches);
