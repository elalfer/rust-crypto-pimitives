extern crate cc;

fn main() {
    let mut cfg = cc::Build::new();
    cfg.file("src/hw/aesni.c");
    cfg.compile("hw_acc.a");
}
