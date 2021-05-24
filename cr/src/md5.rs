//! MD5 Message-Digest algorithm
//!
//! https://datatracker.ietf.org/doc/html/rfc1321
#![allow(clippy::many_single_char_names)]

pub fn md5(input: &[u8]) -> [u8; 16] {
    let mut state = Md5::new();
    state.update(input);
    state.digest()
}

pub struct Md5 {
    state: [u32; 4],
    count: [u32; 2],
    buffer: [u8; 64],
}

impl Md5 {
    pub fn new() -> Self {
        Self {
            state: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476],
            count: [0, 0],
            buffer: [0; 64],
        }
    }

    pub fn update(&mut self, input: &[u8]) -> &mut Self {
        let mut idx = ((self.count[0] >> 3) & 0x3f) as usize; // number of bytes mod 64

        let input_len = input.len() as u32;
        self.count[0] = self.count[0].wrapping_add(input_len << 3);
        if self.count[0] < input_len << 3 {
            self.count[1] += 1;
        }
        self.count[1] += input_len >> 29;

        let mut block = [0; 16];
        for &byte in input {
            self.buffer[idx] = byte;
            idx += 1;
            if idx == 64 {
                decode(&self.buffer, &mut block);
                transform(&mut self.state, &block);
                idx = 0;
            }
        }

        self
    }

    pub fn digest(mut self) -> [u8; 16] {
        let len_bits: [u8; 8] = encode(&self.count); // save length

        let idx = (self.count[0] >> 3 & 0x3f) as usize;
        let pad_len = if idx < 56 { 56 - idx } else { 120 - idx };
        self.update(&PADDING[0..pad_len]);

        self.update(&len_bits); // append length

        encode(&self.state)
    }
}

impl Default for Md5 {
    fn default() -> Self {
        Self::new()
    }
}

fn transform(state: &mut [u32; 4], x: &[u32; 16]) {
    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];

    // Round 1
    const S11: u32 = 7;
    const S12: u32 = 12;
    const S13: u32 = 17;
    const S14: u32 = 22;

    step(&mut a, b, c, d, x[0], S11, 0xd76aa478, f); // 1
    step(&mut d, a, b, c, x[1], S12, 0xe8c7b756, f); // 2
    step(&mut c, d, a, b, x[2], S13, 0x242070db, f); // 3
    step(&mut b, c, d, a, x[3], S14, 0xc1bdceee, f); // 4
    step(&mut a, b, c, d, x[4], S11, 0xf57c0faf, f); // 5
    step(&mut d, a, b, c, x[5], S12, 0x4787c62a, f); // 6
    step(&mut c, d, a, b, x[6], S13, 0xa8304613, f); // 7
    step(&mut b, c, d, a, x[7], S14, 0xfd469501, f); // 8
    step(&mut a, b, c, d, x[8], S11, 0x698098d8, f); // 9
    step(&mut d, a, b, c, x[9], S12, 0x8b44f7af, f); // 10
    step(&mut c, d, a, b, x[10], S13, 0xffff5bb1, f); // 11
    step(&mut b, c, d, a, x[11], S14, 0x895cd7be, f); // 12
    step(&mut a, b, c, d, x[12], S11, 0x6b901122, f); // 13
    step(&mut d, a, b, c, x[13], S12, 0xfd987193, f); // 14
    step(&mut c, d, a, b, x[14], S13, 0xa679438e, f); // 15
    step(&mut b, c, d, a, x[15], S14, 0x49b40821, f); // 16

    // Round 2
    const S21: u32 = 5;
    const S22: u32 = 9;
    const S23: u32 = 14;
    const S24: u32 = 20;

    step(&mut a, b, c, d, x[1], S21, 0xf61e2562, g); // 17
    step(&mut d, a, b, c, x[6], S22, 0xc040b340, g); // 18
    step(&mut c, d, a, b, x[11], S23, 0x265e5a51, g); // 19
    step(&mut b, c, d, a, x[0], S24, 0xe9b6c7aa, g); // 20
    step(&mut a, b, c, d, x[5], S21, 0xd62f105d, g); // 21
    step(&mut d, a, b, c, x[10], S22, 0x2441453, g); // 22
    step(&mut c, d, a, b, x[15], S23, 0xd8a1e681, g); // 23
    step(&mut b, c, d, a, x[4], S24, 0xe7d3fbc8, g); // 24
    step(&mut a, b, c, d, x[9], S21, 0x21e1cde6, g); // 25
    step(&mut d, a, b, c, x[14], S22, 0xc33707d6, g); // 26
    step(&mut c, d, a, b, x[3], S23, 0xf4d50d87, g); // 27
    step(&mut b, c, d, a, x[8], S24, 0x455a14ed, g); // 28
    step(&mut a, b, c, d, x[13], S21, 0xa9e3e905, g); // 29
    step(&mut d, a, b, c, x[2], S22, 0xfcefa3f8, g); // 30
    step(&mut c, d, a, b, x[7], S23, 0x676f02d9, g); // 31
    step(&mut b, c, d, a, x[12], S24, 0x8d2a4c8a, g); // 32

    // Round 3
    const S31: u32 = 4;
    const S32: u32 = 11;
    const S33: u32 = 16;
    const S34: u32 = 23;

    step(&mut a, b, c, d, x[5], S31, 0xfffa3942, h); // 33
    step(&mut d, a, b, c, x[8], S32, 0x8771f681, h); // 34
    step(&mut c, d, a, b, x[11], S33, 0x6d9d6122, h); // 35
    step(&mut b, c, d, a, x[14], S34, 0xfde5380c, h); // 36
    step(&mut a, b, c, d, x[1], S31, 0xa4beea44, h); // 37
    step(&mut d, a, b, c, x[4], S32, 0x4bdecfa9, h); // 38
    step(&mut c, d, a, b, x[7], S33, 0xf6bb4b60, h); // 39
    step(&mut b, c, d, a, x[10], S34, 0xbebfbc70, h); // 40
    step(&mut a, b, c, d, x[13], S31, 0x289b7ec6, h); // 41
    step(&mut d, a, b, c, x[0], S32, 0xeaa127fa, h); // 42
    step(&mut c, d, a, b, x[3], S33, 0xd4ef3085, h); // 43
    step(&mut b, c, d, a, x[6], S34, 0x4881d05, h); // 44
    step(&mut a, b, c, d, x[9], S31, 0xd9d4d039, h); // 45
    step(&mut d, a, b, c, x[12], S32, 0xe6db99e5, h); // 46
    step(&mut c, d, a, b, x[15], S33, 0x1fa27cf8, h); // 47
    step(&mut b, c, d, a, x[2], S34, 0xc4ac5665, h); // 48

    // Round 4
    const S41: u32 = 6;
    const S42: u32 = 10;
    const S43: u32 = 15;
    const S44: u32 = 21;

    step(&mut a, b, c, d, x[0], S41, 0xf4292244, i); // 49
    step(&mut d, a, b, c, x[7], S42, 0x432aff97, i); // 50
    step(&mut c, d, a, b, x[14], S43, 0xab9423a7, i); // 51
    step(&mut b, c, d, a, x[5], S44, 0xfc93a039, i); // 52
    step(&mut a, b, c, d, x[12], S41, 0x655b59c3, i); // 53
    step(&mut d, a, b, c, x[3], S42, 0x8f0ccc92, i); // 54
    step(&mut c, d, a, b, x[10], S43, 0xffeff47d, i); // 55
    step(&mut b, c, d, a, x[1], S44, 0x85845dd1, i); // 56
    step(&mut a, b, c, d, x[8], S41, 0x6fa87e4f, i); // 57
    step(&mut d, a, b, c, x[15], S42, 0xfe2ce6e0, i); // 58
    step(&mut c, d, a, b, x[6], S43, 0xa3014314, i); // 59
    step(&mut b, c, d, a, x[13], S44, 0x4e0811a1, i); // 60
    step(&mut a, b, c, d, x[4], S41, 0xf7537e82, i); // 61
    step(&mut d, a, b, c, x[11], S42, 0xbd3af235, i); // 62
    step(&mut c, d, a, b, x[2], S43, 0x2ad7d2bb, i); // 63
    step(&mut b, c, d, a, x[9], S44, 0xeb86d391, i); // 64

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
}

fn encode<const N: usize>(input: &[u32]) -> [u8; N] {
    let mut res = [0; N];
    for i in 0..input.len() {
        let bytes = u32::to_le_bytes(input[i]);
        res[4 * i] = bytes[0];
        res[4 * i + 1] = bytes[1];
        res[4 * i + 2] = bytes[2];
        res[4 * i + 3] = bytes[3];
    }
    res
}

fn decode(bytes: &[u8; 64], res: &mut [u32; 16]) {
    for i in 0..16 {
        res[i] = u32::from_le_bytes([
            bytes[4 * i],
            bytes[4 * i + 1],
            bytes[4 * i + 2],
            bytes[4 * i + 3],
        ]);
    }
}

fn f(x: u32, y: u32, z: u32) -> u32 {
    (x & y) | ((!x) & z)
}

fn g(x: u32, y: u32, z: u32) -> u32 {
    (x & z) | (y & (!z))
}

fn h(x: u32, y: u32, z: u32) -> u32 {
    x ^ y ^ z
}

fn i(x: u32, y: u32, z: u32) -> u32 {
    y ^ (x | !z)
}

#[allow(clippy::too_many_arguments)]
fn step(
    a: &mut u32,
    b: u32,
    c: u32,
    d: u32,
    x: u32,
    s: u32,
    ac: u32,
    f: impl FnOnce(u32, u32, u32) -> u32,
) {
    *a = a.wrapping_add(f(b, c, d).wrapping_add(x).wrapping_add(ac));
    *a = a.rotate_left(s);
    *a = a.wrapping_add(b);
}

const PADDING: [u8; 64] = [
    0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex;

    #[test]
    fn test_md5() {
        assert_eq!(md5(b""), hex("d41d8cd98f00b204e9800998ecf8427e").unwrap());
        assert_eq!(md5(b"a"), hex("0cc175b9c0f1b6a831c399e269772661").unwrap());
        assert_eq!(
            md5(b"abc"),
            hex("900150983cd24fb0d6963f7d28e17f72").unwrap()
        );
        assert_eq!(
            md5(b"message digest"),
            hex("f96b697d7cb7938d525a2f31aaf161d0").unwrap()
        );
        assert_eq!(
            md5(b"abcdefghijklmnopqrstuvwxyz"),
            hex("c3fcd3d76192e4007dfb496cca67e13b").unwrap()
        );
        assert_eq!(
            md5(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"),
            hex("d174ab98d277d9f5a5611c2c9f419d9f").unwrap()
        );
        assert_eq!(
            md5(b"12345678901234567890123456789012345678901\
                234567890123456789012345678901234567890"),
            hex("57edf4a22be3c955ac49da2e2107b67a").unwrap()
        );
    }
}
