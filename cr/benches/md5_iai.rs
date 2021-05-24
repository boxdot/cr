use iai::black_box;

fn iai_md5_0000() -> [u8; 16] {
    cr::md5::md5(black_box(&[]))
}

fn iai_md5_1000() -> [u8; 16] {
    cr::md5::md5(black_box(&vec![0xffu8; 1000]))
}

iai::main!(iai_md5_0000, iai_md5_1000);
