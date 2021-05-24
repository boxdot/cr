//! Secure state Algorithm 1 (SHA1) algorithm
//!
//! https://datatracker.ietf.org/doc/html/rfc3174
#![allow(clippy::many_single_char_names)]

use std::convert::TryInto;

pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut state = Sha1::new();
    state.update(data);
    state.digest()
}

pub struct Sha1 {
    state: [u32; 5],
    len: u64, // number of bytes
    block_idx: usize,
    block: [u8; 64],
}

impl Sha1 {
    pub fn new() -> Self {
        Self {
            state: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0],
            len: 0,
            block_idx: 0,
            block: [0; 64],
        }
    }

    pub fn update(&mut self, mut input: &[u8]) {
        self.len += input.len() as u64;

        let remaining = 64 - self.block_idx;
        if input.len() < remaining {
            // not enough bytes to compress a block
            let n = input.len();
            self.block[self.block_idx..self.block_idx + n].copy_from_slice(input);
            self.block_idx += n;
            return;
        }

        if self.block_idx != 0 {
            // buffer has already some bytes
            let (head, tail) = input.split_at(remaining);
            self.block[self.block_idx..].copy_from_slice(head);
            compress(&mut self.state, &self.block);
            input = tail;
            self.block_idx = 0;
        }

        // pre-condition: `self.block` is empty
        // compress blocks without copying them into `self.block`.
        let mut chunks = input.chunks_exact(64);
        for chunk in &mut chunks {
            compress(&mut self.state, chunk.try_into().unwrap());
        }

        let remainder = chunks.remainder();
        self.block[0..remainder.len()].copy_from_slice(remainder);
        self.block_idx = remainder.len();
    }

    pub fn digest(mut self) -> [u8; 20] {
        self.pad();
        let mut res = [0; 20];
        for i in 0..5 {
            let bytes = self.state[i].to_le_bytes();
            res[4 * i] = bytes[3];
            res[4 * i + 1] = bytes[2];
            res[4 * i + 2] = bytes[1];
            res[4 * i + 3] = bytes[0];
        }
        res
    }

    fn pad(&mut self) {
        if self.block_idx > 55 {
            // block is too small for adding padding
            self.block[self.block_idx as usize] = 0x80;
            for i in self.block_idx as usize + 1..64 {
                self.block[i] = 0;
            }
            self.block_idx = 64;
            compress(&mut self.state, &self.block);

            for i in 0..56 {
                self.block[i] = 0;
            }
            self.block_idx = 56;
        } else {
            self.block[self.block_idx as usize] = 0x80;
            for i in self.block_idx as usize + 1..56 {
                self.block[i] = 0;
            }
            self.block_idx = 56;
        }

        // add message length as padding
        self.block[56..64].copy_from_slice(&(self.len << 3).to_be_bytes());

        compress(&mut self.state, &self.block);
    }
}

fn compress(state: &mut [u32; 5], block: &[u8; 64]) {
    let mut h = *state;

    let mut w = [0; 16];
    for t in 0..16 {
        w[t] = u32::from_le_bytes([
            block[4 * t + 3],
            block[4 * t + 2],
            block[4 * t + 1],
            block[4 * t],
        ]);
    }

    const K0: u32 = 0x5a827999;
    const K1: u32 = 0x6ed9eba1;
    const K2: u32 = 0x8f1bbcdc;
    const K3: u32 = 0xca62c1d6;

    for t in 0..16 {
        h = step0::<_, K0>(h, &w, t, |b, c, d| (b & c) | ((!b) & d));
    }

    for t in 16..20 {
        h = step::<_, K0>(h, &mut w, t, |b, c, d| (b & c) | ((!b) & d));
    }

    for t in 20..40 {
        h = step::<_, K1>(h, &mut w, t, |b, c, d| b ^ c ^ d);
    }

    for t in 40..60 {
        h = step::<_, K2>(h, &mut w, t, |b, c, d| (b & c) | (b & d) | (c & d));
    }

    for t in 60..80 {
        h = step::<_, K3>(h, &mut w, t, |b, c, d| b ^ c ^ d);
    }

    state[0] = state[0].wrapping_add(h[0]);
    state[1] = state[1].wrapping_add(h[1]);
    state[2] = state[2].wrapping_add(h[2]);
    state[3] = state[3].wrapping_add(h[3]);
    state[4] = state[4].wrapping_add(h[4]);
}

const MASK: usize = 0xF;

fn step0<F, const K: u32>([a, b, c, d, mut e]: [u32; 5], w: &[u32; 16], t: usize, f: F) -> [u32; 5]
where
    F: FnOnce(u32, u32, u32) -> u32,
{
    let s = t & 0xF;
    e = a
        .rotate_left(5)
        .wrapping_add(f(b, c, d))
        .wrapping_add(e)
        .wrapping_add(w[s])
        .wrapping_add(K);
    [e, a, b.rotate_left(30), c, d]
}

fn step<F, const K: u32>(
    [a, b, c, d, mut e]: [u32; 5],
    w: &mut [u32; 16],
    t: usize,
    f: F,
) -> [u32; 5]
where
    F: FnOnce(u32, u32, u32) -> u32,
{
    let s = t & 0xF;
    w[s] = (w[(s + 13) & MASK] ^ w[(s + 8) & MASK] ^ w[(s + 2) & MASK] ^ w[s]).rotate_left(1);
    e = a
        .rotate_left(5)
        .wrapping_add(f(b, c, d))
        .wrapping_add(e)
        .wrapping_add(w[s])
        .wrapping_add(K);
    [e, a, b.rotate_left(30), c, d]
}

impl Default for Sha1 {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use crate::hex;

    use super::*;

    #[test]
    fn test_sha1() {
        assert_eq!(
            sha1(b"abc"),
            hex("a9993e364706816aba3e25717850c26c9cd0d89d").unwrap()
        );
        assert_eq!(
            sha1(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            hex("84983e441c3bd26ebaae4aa1f95129e5e54670f1").unwrap()
        );
    }

    #[test]
    fn test_sha1_1000000_updates() {
        let mut state = Sha1::new();
        for _ in 0..1000000 {
            state.update(b"a");
        }
        assert_eq!(
            state.digest(),
            hex("34aa973cd4c4daa4f61eeb2bdbad27316534016f").unwrap()
        );
    }

    #[test]
    fn test_sha1_10_updates() {
        let mut state = Sha1::new();
        for _ in 0..10 {
            state.update(b"0123456701234567012345670123456701234567012345670123456701234567");
        }
        assert_eq!(
            state.digest(),
            hex("dea356a2cddd90c7a7ecedc5ebb563934f460452").unwrap()
        );
    }
}
