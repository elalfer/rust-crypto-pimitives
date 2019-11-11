#[macro_use]
extern crate criterion;

use criterion::*;

#[link(name = "hw_acc.a")]
extern "C" {
    fn aesni_enc_ecb(ct: *mut u8, rounds: usize, pt: *const u8, blocks: usize, key: *const u8);
}

fn bench_aes_128_ecb_enc(c: &mut Criterion) {
    let test_size = 16*1024;
    let pt = vec![0u8; test_size];
    let mut ct = vec![0u8; test_size];
    let key = vec![0u8; 15*16];

    let mut group = c.benchmark_group("aes-ni");

    group.throughput(Throughput::Bytes(test_size as u64));

    group.bench_function("aes_128_ecb_enc",|b| b.iter(||
        unsafe { aesni_enc_ecb(ct.as_mut_ptr(), 10, pt.as_ptr(), test_size/16, key.as_ptr()); } 
        ));
    group.bench_function("aes_256_ecb_enc",|b| b.iter(||
        unsafe { aesni_enc_ecb(ct.as_mut_ptr(), 14, pt.as_ptr(), test_size/16, key.as_ptr()); } 
        ));
    group.finish();
}

criterion_group!(benches, bench_aes_128_ecb_enc);
criterion_main!(benches);
