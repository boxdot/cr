//! Twofish block cipher
//!
//! https://www.schneier.com/academic/twofish/
use std::convert::TryInto;
use std::ops::{Index, Range};

const NUM_ROUNDS: usize = 16;
const NUM_WHITENING_SUBKEYS: usize = 8;

pub enum Key {
    Key128([u8; 16]),
    Key192([u8; 24]),
    Key256([u8; 32]),
}

impl Key {
    fn len_u64(&self) -> usize {
        match self {
            Key::Key128(_) => 2,
            Key::Key192(_) => 3,
            Key::Key256(_) => 4,
        }
    }
}

impl Index<usize> for Key {
    type Output = u8;

    fn index(&self, index: usize) -> &Self::Output {
        match self {
            Key::Key128(bytes) => &bytes[index],
            Key::Key192(bytes) => &bytes[index],
            Key::Key256(bytes) => &bytes[index],
        }
    }
}

impl Index<Range<usize>> for Key {
    type Output = [u8];

    fn index(&self, index: Range<usize>) -> &Self::Output {
        match self {
            Key::Key128(bytes) => &bytes[index],
            Key::Key192(bytes) => &bytes[index],
            Key::Key256(bytes) => &bytes[index],
        }
    }
}

pub fn encrypt(plaintext: [u8; 16], key: Key) -> [u8; 16] {
    let schedule = expand_key(key);

    // whitening with the first 4 keys
    let mut x = [0; 4];
    for i in 0..4 {
        x[i] = u32::from_le_bytes([
            plaintext[4 * i],
            plaintext[4 * i + 1],
            plaintext[4 * i + 2],
            plaintext[4 * i + 3],
        ]) ^ schedule.subkeys[i];
    }

    for r in 0..NUM_ROUNDS {
        let t0 = g(x[0], schedule.sbox_keys());
        let t1 = g(x[1].rotate_left(8), schedule.sbox_keys());

        // PHT with shifts
        x[3] = x[3].rotate_left(1);
        x[2] ^= t0
            .wrapping_add(t1)
            .wrapping_add(schedule.subkeys[NUM_WHITENING_SUBKEYS + 2 * r]);
        x[3] ^= t0
            .wrapping_add(t1 << 1)
            .wrapping_add(schedule.subkeys[NUM_WHITENING_SUBKEYS + 2 * r + 1]);
        x[2] = x[2].rotate_right(1);

        // swap for the next round (if any)
        if r + 1 < NUM_ROUNDS {
            x.swap(0, 2);
            x.swap(1, 3);
        }
    }

    // whitening with the second 4 keys
    let mut ciphertext = [0; 16];
    for i in 0..4 {
        x[i] ^= schedule.subkeys[4 + i];
        let b = x[i].to_le_bytes();
        ciphertext[4 * i] = b[0];
        ciphertext[4 * i + 1] = b[1];
        ciphertext[4 * i + 2] = b[2];
        ciphertext[4 * i + 3] = b[3];
    }

    ciphertext
}

#[allow(dead_code)]
struct KeySchedule {
    len_u64: usize,
    sbox_keys: [u32; 4],
    subkeys: [u32; NUM_WHITENING_SUBKEYS + 2 * NUM_ROUNDS],
}

impl KeySchedule {
    fn sbox_keys(&self) -> &[u32] {
        &self.sbox_keys[0..self.len_u64]
    }
}

fn expand_key(key: Key) -> KeySchedule {
    let mut keys_odd = [0; 4];
    let mut keys_even = [0; 4];
    let mut sbox_keys = [0; 4];
    let mut subkeys = [0; NUM_WHITENING_SUBKEYS + 2 * NUM_ROUNDS];

    for i in 0..key.len_u64() {
        let offset = 8 * i;
        keys_even[i] = u32::from_le_bytes([
            key[offset],
            key[offset + 1],
            key[offset + 2],
            key[offset + 3],
        ]);
        keys_odd[i] = u32::from_le_bytes([
            key[offset + 4],
            key[offset + 5],
            key[offset + 6],
            key[offset + 7],
        ]);
        let v = key[offset..offset + 8].try_into().unwrap();
        sbox_keys[key.len_u64() - i - 1] = u32::from_le_bytes(mult_rs_matrix(v));
    }

    const SK_STEP: u32 = 0x02020202;
    const SK_BUMP: u32 = 0x01010101;
    const SK_ROTL: u32 = 9;

    for i in 0..NUM_WHITENING_SUBKEYS / 2 + NUM_ROUNDS {
        let a = h(i as u32 * SK_STEP, &keys_even[0..key.len_u64()]);
        let b = h(i as u32 * SK_STEP + SK_BUMP, &keys_odd[0..key.len_u64()]).rotate_left(8);
        subkeys[2 * i] = a.wrapping_add(b);
        subkeys[2 * i + 1] = a.wrapping_add(b.wrapping_mul(2)).rotate_left(SK_ROTL);
    }

    KeySchedule {
        len_u64: key.len_u64(),
        sbox_keys,
        subkeys,
    }
}

/// h-Functions as defined in 4.3.2
fn h(x: u32, l: &[u32]) -> u32 {
    let mut b = x.to_le_bytes();

    // 8x8 S-box application XOR key
    if l.len() == 4 {
        let k3 = l[3].to_le_bytes();
        b[0] = p1(b[0]) ^ k3[0];
        b[1] = p0(b[1]) ^ k3[1];
        b[2] = p0(b[2]) ^ k3[2];
        b[3] = p1(b[3]) ^ k3[3];
    }
    if l.len() >= 3 {
        let k2 = l[2].to_le_bytes();
        b[0] = p1(b[0]) ^ k2[0];
        b[1] = p1(b[1]) ^ k2[1];
        b[2] = p0(b[2]) ^ k2[2];
        b[3] = p0(b[3]) ^ k2[3];
    }
    let k0 = l[0].to_le_bytes();
    let k1 = l[1].to_le_bytes();
    b[0] = p1(p0(p0(b[0]) ^ k1[0]) ^ k0[0]);
    b[1] = p0(p0(p1(b[1]) ^ k1[1]) ^ k0[1]);
    b[2] = p1(p1(p0(b[2]) ^ k1[2]) ^ k0[2]);
    b[3] = p0(p1(p1(b[3]) ^ k1[3]) ^ k0[3]);

    // MDS matrix multiplication
    u32::from_le_bytes([
        b[0] ^ mult_ef(b[1]) ^ mult_5b(b[2]) ^ mult_5b(b[3]),
        mult_5b(b[0]) ^ mult_ef(b[1]) ^ mult_ef(b[2]) ^ b[3],
        mult_ef(b[0]) ^ mult_5b(b[1]) ^ b[2] ^ mult_ef(b[3]),
        mult_ef(b[0]) ^ b[1] ^ mult_ef(b[2]) ^ mult_5b(b[3]),
    ])
}

/// g-Function as defined in 4.3.3
fn g(x: u32, s: &[u32]) -> u32 {
    h(x, s)
}

fn mult_5b(x: u8) -> u8 {
    MULT_5B[x as usize]
}

fn mult_ef(x: u8) -> u8 {
    MULT_EF[x as usize]
}

fn p0(x: u8) -> u8 {
    P0[x as usize]
}

fn p1(x: u8) -> u8 {
    P1[x as usize]
}

#[allow(clippy::needless_range_loop)] // false positive
fn mult_rs_matrix(v: [u8; 8]) -> [u8; 4] {
    let mut res = [0; 4];
    for i in 0..4 {
        for j in 0..8 {
            res[i] ^= gf_mult(RS[i][j], v[j]);
        }
    }
    res
}

fn gf_mult(mut a: u8, b: u8) -> u8 {
    // arrays are used for removing branches
    const RS_GF_GEN: [u16; 2] = [0, 0x14D];
    let mut b = [0, b as u16];
    let mut prod = 0;

    // unrolled and branchles multiplication in GF-256
    prod ^= b[(a & 1) as usize];
    a >>= 1;
    b[1] = (b[1] << 1) ^ RS_GF_GEN[(b[1] >> 7 & 1) as usize];
    prod ^= b[(a & 1) as usize];
    a >>= 1;
    b[1] = (b[1] << 1) ^ RS_GF_GEN[(b[1] >> 7 & 1) as usize];
    prod ^= b[(a & 1) as usize];
    a >>= 1;
    b[1] = (b[1] << 1) ^ RS_GF_GEN[(b[1] >> 7 & 1) as usize];
    prod ^= b[(a & 1) as usize];
    a >>= 1;
    b[1] = (b[1] << 1) ^ RS_GF_GEN[(b[1] >> 7 & 1) as usize];
    prod ^= b[(a & 1) as usize];
    a >>= 1;
    b[1] = (b[1] << 1) ^ RS_GF_GEN[(b[1] >> 7 & 1) as usize];
    prod ^= b[(a & 1) as usize];
    a >>= 1;
    b[1] = (b[1] << 1) ^ RS_GF_GEN[(b[1] >> 7 & 1) as usize];
    prod ^= b[(a & 1) as usize];
    a >>= 1;
    b[1] = (b[1] << 1) ^ RS_GF_GEN[(b[1] >> 7 & 1) as usize];
    prod ^= b[(a & 1) as usize];
    a >>= 1;
    b[1] = (b[1] << 1) ^ RS_GF_GEN[(b[1] >> 7 & 1) as usize];
    prod ^= b[(a & 1) as usize];

    prod as u8
}

const RS: [[u8; 8]; 4] = [
    [0x01, 0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E],
    [0xA4, 0x56, 0x82, 0xF3, 0x1E, 0xC6, 0x68, 0xE5],
    [0x02, 0xA1, 0xFC, 0xC1, 0x47, 0xAE, 0x3D, 0x19],
    [0xA4, 0x55, 0x87, 0x5A, 0x58, 0xDB, 0x9E, 0x03],
];

const P0: [u8; 256] = [
    0xA9, 0x67, 0xB3, 0xE8, 0x04, 0xFD, 0xA3, 0x76, 0x9A, 0x92, 0x80, 0x78, 0xE4, 0xDD, 0xD1, 0x38,
    0x0D, 0xC6, 0x35, 0x98, 0x18, 0xF7, 0xEC, 0x6C, 0x43, 0x75, 0x37, 0x26, 0xFA, 0x13, 0x94, 0x48,
    0xF2, 0xD0, 0x8B, 0x30, 0x84, 0x54, 0xDF, 0x23, 0x19, 0x5B, 0x3D, 0x59, 0xF3, 0xAE, 0xA2, 0x82,
    0x63, 0x01, 0x83, 0x2E, 0xD9, 0x51, 0x9B, 0x7C, 0xA6, 0xEB, 0xA5, 0xBE, 0x16, 0x0C, 0xE3, 0x61,
    0xC0, 0x8C, 0x3A, 0xF5, 0x73, 0x2C, 0x25, 0x0B, 0xBB, 0x4E, 0x89, 0x6B, 0x53, 0x6A, 0xB4, 0xF1,
    0xE1, 0xE6, 0xBD, 0x45, 0xE2, 0xF4, 0xB6, 0x66, 0xCC, 0x95, 0x03, 0x56, 0xD4, 0x1C, 0x1E, 0xD7,
    0xFB, 0xC3, 0x8E, 0xB5, 0xE9, 0xCF, 0xBF, 0xBA, 0xEA, 0x77, 0x39, 0xAF, 0x33, 0xC9, 0x62, 0x71,
    0x81, 0x79, 0x09, 0xAD, 0x24, 0xCD, 0xF9, 0xD8, 0xE5, 0xC5, 0xB9, 0x4D, 0x44, 0x08, 0x86, 0xE7,
    0xA1, 0x1D, 0xAA, 0xED, 0x06, 0x70, 0xB2, 0xD2, 0x41, 0x7B, 0xA0, 0x11, 0x31, 0xC2, 0x27, 0x90,
    0x20, 0xF6, 0x60, 0xFF, 0x96, 0x5C, 0xB1, 0xAB, 0x9E, 0x9C, 0x52, 0x1B, 0x5F, 0x93, 0x0A, 0xEF,
    0x91, 0x85, 0x49, 0xEE, 0x2D, 0x4F, 0x8F, 0x3B, 0x47, 0x87, 0x6D, 0x46, 0xD6, 0x3E, 0x69, 0x64,
    0x2A, 0xCE, 0xCB, 0x2F, 0xFC, 0x97, 0x05, 0x7A, 0xAC, 0x7F, 0xD5, 0x1A, 0x4B, 0x0E, 0xA7, 0x5A,
    0x28, 0x14, 0x3F, 0x29, 0x88, 0x3C, 0x4C, 0x02, 0xB8, 0xDA, 0xB0, 0x17, 0x55, 0x1F, 0x8A, 0x7D,
    0x57, 0xC7, 0x8D, 0x74, 0xB7, 0xC4, 0x9F, 0x72, 0x7E, 0x15, 0x22, 0x12, 0x58, 0x07, 0x99, 0x34,
    0x6E, 0x50, 0xDE, 0x68, 0x65, 0xBC, 0xDB, 0xF8, 0xC8, 0xA8, 0x2B, 0x40, 0xDC, 0xFE, 0x32, 0xA4,
    0xCA, 0x10, 0x21, 0xF0, 0xD3, 0x5D, 0x0F, 0x00, 0x6F, 0x9D, 0x36, 0x42, 0x4A, 0x5E, 0xC1, 0xE0,
];

const P1: [u8; 256] = [
    0x75, 0xF3, 0xC6, 0xF4, 0xDB, 0x7B, 0xFB, 0xC8, 0x4A, 0xD3, 0xE6, 0x6B, 0x45, 0x7D, 0xE8, 0x4B,
    0xD6, 0x32, 0xD8, 0xFD, 0x37, 0x71, 0xF1, 0xE1, 0x30, 0x0F, 0xF8, 0x1B, 0x87, 0xFA, 0x06, 0x3F,
    0x5E, 0xBA, 0xAE, 0x5B, 0x8A, 0x00, 0xBC, 0x9D, 0x6D, 0xC1, 0xB1, 0x0E, 0x80, 0x5D, 0xD2, 0xD5,
    0xA0, 0x84, 0x07, 0x14, 0xB5, 0x90, 0x2C, 0xA3, 0xB2, 0x73, 0x4C, 0x54, 0x92, 0x74, 0x36, 0x51,
    0x38, 0xB0, 0xBD, 0x5A, 0xFC, 0x60, 0x62, 0x96, 0x6C, 0x42, 0xF7, 0x10, 0x7C, 0x28, 0x27, 0x8C,
    0x13, 0x95, 0x9C, 0xC7, 0x24, 0x46, 0x3B, 0x70, 0xCA, 0xE3, 0x85, 0xCB, 0x11, 0xD0, 0x93, 0xB8,
    0xA6, 0x83, 0x20, 0xFF, 0x9F, 0x77, 0xC3, 0xCC, 0x03, 0x6F, 0x08, 0xBF, 0x40, 0xE7, 0x2B, 0xE2,
    0x79, 0x0C, 0xAA, 0x82, 0x41, 0x3A, 0xEA, 0xB9, 0xE4, 0x9A, 0xA4, 0x97, 0x7E, 0xDA, 0x7A, 0x17,
    0x66, 0x94, 0xA1, 0x1D, 0x3D, 0xF0, 0xDE, 0xB3, 0x0B, 0x72, 0xA7, 0x1C, 0xEF, 0xD1, 0x53, 0x3E,
    0x8F, 0x33, 0x26, 0x5F, 0xEC, 0x76, 0x2A, 0x49, 0x81, 0x88, 0xEE, 0x21, 0xC4, 0x1A, 0xEB, 0xD9,
    0xC5, 0x39, 0x99, 0xCD, 0xAD, 0x31, 0x8B, 0x01, 0x18, 0x23, 0xDD, 0x1F, 0x4E, 0x2D, 0xF9, 0x48,
    0x4F, 0xF2, 0x65, 0x8E, 0x78, 0x5C, 0x58, 0x19, 0x8D, 0xE5, 0x98, 0x57, 0x67, 0x7F, 0x05, 0x64,
    0xAF, 0x63, 0xB6, 0xFE, 0xF5, 0xB7, 0x3C, 0xA5, 0xCE, 0xE9, 0x68, 0x44, 0xE0, 0x4D, 0x43, 0x69,
    0x29, 0x2E, 0xAC, 0x15, 0x59, 0xA8, 0x0A, 0x9E, 0x6E, 0x47, 0xDF, 0x34, 0x35, 0x6A, 0xCF, 0xDC,
    0x22, 0xC9, 0xC0, 0x9B, 0x89, 0xD4, 0xED, 0xAB, 0x12, 0xA2, 0x0D, 0x52, 0xBB, 0x02, 0x2F, 0xA9,
    0xD7, 0x61, 0x1E, 0xB4, 0x50, 0x04, 0xF6, 0xC2, 0x16, 0x25, 0x86, 0x56, 0x55, 0x09, 0xBE, 0x91,
];

const MULT_5B: [u8; 256] = [
    0x00, 0x5B, 0xB6, 0xED, 0x05, 0x5E, 0xB3, 0xE8, 0x0A, 0x51, 0xBC, 0xE7, 0x0F, 0x54, 0xB9, 0xE2,
    0x14, 0x4F, 0xA2, 0xF9, 0x11, 0x4A, 0xA7, 0xFC, 0x1E, 0x45, 0xA8, 0xF3, 0x1B, 0x40, 0xAD, 0xF6,
    0x28, 0x73, 0x9E, 0xC5, 0x2D, 0x76, 0x9B, 0xC0, 0x22, 0x79, 0x94, 0xCF, 0x27, 0x7C, 0x91, 0xCA,
    0x3C, 0x67, 0x8A, 0xD1, 0x39, 0x62, 0x8F, 0xD4, 0x36, 0x6D, 0x80, 0xDB, 0x33, 0x68, 0x85, 0xDE,
    0x50, 0x0B, 0xE6, 0xBD, 0x55, 0x0E, 0xE3, 0xB8, 0x5A, 0x01, 0xEC, 0xB7, 0x5F, 0x04, 0xE9, 0xB2,
    0x44, 0x1F, 0xF2, 0xA9, 0x41, 0x1A, 0xF7, 0xAC, 0x4E, 0x15, 0xF8, 0xA3, 0x4B, 0x10, 0xFD, 0xA6,
    0x78, 0x23, 0xCE, 0x95, 0x7D, 0x26, 0xCB, 0x90, 0x72, 0x29, 0xC4, 0x9F, 0x77, 0x2C, 0xC1, 0x9A,
    0x6C, 0x37, 0xDA, 0x81, 0x69, 0x32, 0xDF, 0x84, 0x66, 0x3D, 0xD0, 0x8B, 0x63, 0x38, 0xD5, 0x8E,
    0xA0, 0xFB, 0x16, 0x4D, 0xA5, 0xFE, 0x13, 0x48, 0xAA, 0xF1, 0x1C, 0x47, 0xAF, 0xF4, 0x19, 0x42,
    0xB4, 0xEF, 0x02, 0x59, 0xB1, 0xEA, 0x07, 0x5C, 0xBE, 0xE5, 0x08, 0x53, 0xBB, 0xE0, 0x0D, 0x56,
    0x88, 0xD3, 0x3E, 0x65, 0x8D, 0xD6, 0x3B, 0x60, 0x82, 0xD9, 0x34, 0x6F, 0x87, 0xDC, 0x31, 0x6A,
    0x9C, 0xC7, 0x2A, 0x71, 0x99, 0xC2, 0x2F, 0x74, 0x96, 0xCD, 0x20, 0x7B, 0x93, 0xC8, 0x25, 0x7E,
    0xF0, 0xAB, 0x46, 0x1D, 0xF5, 0xAE, 0x43, 0x18, 0xFA, 0xA1, 0x4C, 0x17, 0xFF, 0xA4, 0x49, 0x12,
    0xE4, 0xBF, 0x52, 0x09, 0xE1, 0xBA, 0x57, 0x0C, 0xEE, 0xB5, 0x58, 0x03, 0xEB, 0xB0, 0x5D, 0x06,
    0xD8, 0x83, 0x6E, 0x35, 0xDD, 0x86, 0x6B, 0x30, 0xD2, 0x89, 0x64, 0x3F, 0xD7, 0x8C, 0x61, 0x3A,
    0xCC, 0x97, 0x7A, 0x21, 0xC9, 0x92, 0x7F, 0x24, 0xC6, 0x9D, 0x70, 0x2B, 0xC3, 0x98, 0x75, 0x2E,
];

const MULT_EF: [u8; 256] = [
    0x00, 0xEF, 0xB7, 0x58, 0x07, 0xE8, 0xB0, 0x5F, 0x0E, 0xE1, 0xB9, 0x56, 0x09, 0xE6, 0xBE, 0x51,
    0x1C, 0xF3, 0xAB, 0x44, 0x1B, 0xF4, 0xAC, 0x43, 0x12, 0xFD, 0xA5, 0x4A, 0x15, 0xFA, 0xA2, 0x4D,
    0x38, 0xD7, 0x8F, 0x60, 0x3F, 0xD0, 0x88, 0x67, 0x36, 0xD9, 0x81, 0x6E, 0x31, 0xDE, 0x86, 0x69,
    0x24, 0xCB, 0x93, 0x7C, 0x23, 0xCC, 0x94, 0x7B, 0x2A, 0xC5, 0x9D, 0x72, 0x2D, 0xC2, 0x9A, 0x75,
    0x70, 0x9F, 0xC7, 0x28, 0x77, 0x98, 0xC0, 0x2F, 0x7E, 0x91, 0xC9, 0x26, 0x79, 0x96, 0xCE, 0x21,
    0x6C, 0x83, 0xDB, 0x34, 0x6B, 0x84, 0xDC, 0x33, 0x62, 0x8D, 0xD5, 0x3A, 0x65, 0x8A, 0xD2, 0x3D,
    0x48, 0xA7, 0xFF, 0x10, 0x4F, 0xA0, 0xF8, 0x17, 0x46, 0xA9, 0xF1, 0x1E, 0x41, 0xAE, 0xF6, 0x19,
    0x54, 0xBB, 0xE3, 0x0C, 0x53, 0xBC, 0xE4, 0x0B, 0x5A, 0xB5, 0xED, 0x02, 0x5D, 0xB2, 0xEA, 0x05,
    0xE0, 0x0F, 0x57, 0xB8, 0xE7, 0x08, 0x50, 0xBF, 0xEE, 0x01, 0x59, 0xB6, 0xE9, 0x06, 0x5E, 0xB1,
    0xFC, 0x13, 0x4B, 0xA4, 0xFB, 0x14, 0x4C, 0xA3, 0xF2, 0x1D, 0x45, 0xAA, 0xF5, 0x1A, 0x42, 0xAD,
    0xD8, 0x37, 0x6F, 0x80, 0xDF, 0x30, 0x68, 0x87, 0xD6, 0x39, 0x61, 0x8E, 0xD1, 0x3E, 0x66, 0x89,
    0xC4, 0x2B, 0x73, 0x9C, 0xC3, 0x2C, 0x74, 0x9B, 0xCA, 0x25, 0x7D, 0x92, 0xCD, 0x22, 0x7A, 0x95,
    0x90, 0x7F, 0x27, 0xC8, 0x97, 0x78, 0x20, 0xCF, 0x9E, 0x71, 0x29, 0xC6, 0x99, 0x76, 0x2E, 0xC1,
    0x8C, 0x63, 0x3B, 0xD4, 0x8B, 0x64, 0x3C, 0xD3, 0x82, 0x6D, 0x35, 0xDA, 0x85, 0x6A, 0x32, 0xDD,
    0xA8, 0x47, 0x1F, 0xF0, 0xAF, 0x40, 0x18, 0xF7, 0xA6, 0x49, 0x11, 0xFE, 0xA1, 0x4E, 0x16, 0xF9,
    0xB4, 0x5B, 0x03, 0xEC, 0xB3, 0x5C, 0x04, 0xEB, 0xBA, 0x55, 0x0D, 0xE2, 0xBD, 0x52, 0x0A, 0xE5,
];

#[cfg(test)]
mod tests {
    use super::*;
    use hex::FromHex;

    #[test]
    fn test_expand_key_128_key() {
        let key = Key::Key128([0; 16]);
        let schedule = expand_key(key);

        assert_eq!(schedule.len_u64, 2);
        assert_eq!(schedule.sbox_keys, [0, 0, 0, 0]);

        const EXPECTED: [u32; 40] = [
            0x52C54DDE, 0x11F0626D, 0x7CAC9D4A, 0x4D1B4AAA, 0xB7B83A10, 0x1E7D0BEB, 0xEE9C341F,
            0xCFE14BE4, 0xF98FFEF9, 0x9C5B3C17, 0x15A48310, 0x342A4D81, 0x424D89FE, 0xC14724A7,
            0x311B834C, 0xFDE87320, 0x3302778F, 0x26CD67B4, 0x7A6C6362, 0xC2BAF60E, 0x3411B994,
            0xD972C87F, 0x84ADB1EA, 0xA7DEE434, 0x54D2960F, 0xA2F7CAA8, 0xA6B8FF8C, 0x8014C425,
            0x6A748D1C, 0xEDBAF720, 0x928EF78C, 0x0338EE13, 0x9949D6BE, 0xC8314176, 0x07C07D68,
            0xECAE7EA7, 0x1FE71844, 0x85C05C89, 0xF298311E, 0x696EA672,
        ];
        assert_eq!(schedule.subkeys, EXPECTED);
    }

    #[test]
    fn test_expand_key_192_key() {
        let key_bytes =
            <[u8; 24]>::from_hex("0123456789ABCDEFFEDCBA98765432100011223344556677").unwrap();
        let key = Key::Key192(key_bytes);
        let schedule = expand_key(key);
        assert_eq!(schedule.len_u64, 3);
        assert_eq!(schedule.sbox_keys, [0x45661061, 0xB255BC4B, 0xB89FF6F2, 0]);

        const EXPECTED: [u32; 40] = [
            0x38394A24, 0xC36D1175, 0xE802528F, 0x219BFEB4, 0xB9141AB4, 0xBD3E70CD, 0xAF609383,
            0xFD36908A, 0x03EFB931, 0x1D2EE7EC, 0xA7489D55, 0x6E44B6E8, 0x714AD667, 0x653AD51F,
            0xB6315B66, 0xB27C05AF, 0xA06C8140, 0x9853D419, 0x4016E346, 0x8D1C0DD4, 0xF05480BE,
            0xB6AF816F, 0x2D7DC789, 0x45B7BD3A, 0x57F8A163, 0x2BEFDA69, 0x26AE7271, 0xC2900D79,
            0xED323794, 0x3D3FFD80, 0x5DE68E49, 0x9C3D2478, 0xDF326FE3, 0x5911F70D, 0xC229F13B,
            0xB1364772, 0x4235364D, 0x0CEC363A, 0x57C8DD1F, 0x6A1AD61E,
        ];
        assert_eq!(schedule.subkeys, EXPECTED);
    }

    #[test]
    fn test_expand_key_256_key() {
        let key_bytes = <[u8; 32]>::from_hex(
            "0123456789ABCDEFFEDCBA987654321000112233445566778899AABBCCDDEEFF",
        )
        .unwrap();
        let key = Key::Key256(key_bytes);
        let schedule = expand_key(key);
        assert_eq!(schedule.len_u64, 4);
        assert_eq!(
            schedule.sbox_keys,
            [0x8E4447F7, 0x45661061, 0xB255BC4B, 0xB89FF6F2]
        );

        const EXPECTED: [u32; 40] = [
            0x5EC769BF, 0x44D13C60, 0x76CD39B1, 0x16750474, 0x349C294B, 0xEC21F6D6, 0x4FBD10B4,
            0x578DA0ED, 0xC3479695, 0x9B6958FB, 0x6A7FBC4E, 0x0BF1830B, 0x61B5E0FB, 0xD78D9730,
            0x7C6CF0C4, 0x2F9109C8, 0xE69EA8D1, 0xED99BDFF, 0x35DC0BBD, 0xA03E5018, 0xFB18EA0B,
            0x38BD43D3, 0x76191781, 0x37A9A0D3, 0x72427BEA, 0x911CC0B8, 0xF1689449, 0x71009CA9,
            0xB6363E89, 0x494D9855, 0x590BBC63, 0xF95A28B5, 0xFB72B4E1, 0x2A43505C, 0xBFD34176,
            0x5C133D12, 0x3A9247F7, 0x9A3331DD, 0xEE7515E6, 0xF0D54DCD,
        ];
        assert_eq!(schedule.subkeys, EXPECTED);
    }

    #[test]
    fn test_encrypt_128() {
        let key = Key::Key128([0; 16]);
        let ciphertext = encrypt([0; 16], key);
        let expected = <[u8; 16]>::from_hex("9F589F5CF6122C32B6BFEC2F2AE8C35A").unwrap();
        assert_eq!(ciphertext, expected);
    }

    #[test]
    fn test_encrypt_192() {
        let key_bytes =
            <[u8; 24]>::from_hex("0123456789ABCDEFFEDCBA98765432100011223344556677").unwrap();
        let key = Key::Key192(key_bytes);
        let ciphertext = encrypt([0; 16], key);
        let expected = <[u8; 16]>::from_hex("CFD1D2E5A9BE9CDF501F13B892BD2248").unwrap();
        assert_eq!(ciphertext, expected);
    }

    #[test]
    fn test_encrypt_256() {
        let key_bytes = <[u8; 32]>::from_hex(
            "0123456789ABCDEFFEDCBA987654321000112233445566778899AABBCCDDEEFF",
        )
        .unwrap();
        let key = Key::Key256(key_bytes);
        let ciphertext = encrypt([0; 16], key);
        let expected = <[u8; 16]>::from_hex("37527BE0052334B89F0CFCCAE87CFA20").unwrap();
        assert_eq!(ciphertext, expected);
    }
}
