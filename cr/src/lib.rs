pub mod aes;
pub mod des;
pub mod twofish;

#[cfg(test)]
pub fn hex<const N: usize>(s: impl AsRef<str>) -> Option<[u8; N]> {
    let mut ar = [0; N];
    let mut idx = 0;
    for c in s.as_ref().as_bytes().iter() {
        if idx >= 2 * N {
            return None;
        }
        let b = match c {
            b'0'..=b'9' => c - 48,
            b'A'..=b'F' => c - 55,
            b'a'..=b'f' => c - 87,
            b' ' | b'\r' | b'\n' | b'\t' => continue,
            _ => return None,
        };
        ar[idx / 2] = ar[idx / 2] << 4 | b;
        idx += 1;
    }
    if idx == 2 * N {
        Some(ar)
    } else {
        None
    }
}

#[cfg(test)]
pub fn hex_string<const N: usize>(ar: [u8; N]) -> String {
    let mut s = String::new();
    for &b in ar.iter() {
        for i in (0..2).rev() {
            let v = (b >> (4 * i)) & 0xF;
            let c = match v {
                0..=9 => v + 48,
                10..=16 => v + 55,
                _ => unreachable!(),
            };
            s.push(c as char);
        }
    }
    s
}
