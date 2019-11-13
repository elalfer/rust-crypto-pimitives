
// Import C implementations
#[link(name = "hw_acc.a")]
extern "C" {
    fn aesni_enc_ecb(ct: *mut u8, rounds: usize, pt: *const u8, 
        blocks: usize, key: *const u8);

    fn aesni_dec_ecb(pt: *mut u8, rounds: usize, ct: *const u8, 
        blocks: usize, key: *const u8);
}

pub enum KeySize {
    K128,
    K196,
    K256
}

pub fn aesni_ecb_enc(cypher_text: &mut [u8], plain_text: &[u8], blocks: usize,
    key_size: KeySize, enc_key: &[u8]) {
    let rounds: usize =
        match key_size {
            KeySize::K128 => 10,
            KeySize::K196 => 12,
            KeySize::K256 => 14
        };

    unsafe { aesni_enc_ecb(cypher_text.as_mut_ptr(), rounds, plain_text.as_ptr(), 
        blocks, enc_key.as_ptr()); } 
}

pub fn aesni_dec_enc(plain_text: &mut [u8], cypher_text: &[u8], blocks: usize,
    key_size: KeySize, enc_key: &[u8]) {
    let rounds: usize =
        match key_size {
            KeySize::K128 => 10,
            KeySize::K196 => 12,
            KeySize::K256 => 14
        };

    unsafe { aesni_dec_ecb(plain_text.as_mut_ptr(), rounds, cypher_text.as_ptr(), 
        blocks, enc_key.as_ptr()); } 
}

#[cfg(test)]
mod tests {

    // TODO Add validation tests
}
