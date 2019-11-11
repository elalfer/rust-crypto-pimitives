#[cfg(test)]
mod tests {
    #[link(name = "hw_acc.a")]
    extern "C" {
        fn aesni_enc_ecb(ct: *mut u8, rounds: usize, pt: *const u8, blocks: usize, key: *const u8);
    }

    #[test]
    fn it_works() {
        //println!("{}", unsafe { test_print() });
        assert_eq!(2 + 2, 4);
    }
}
