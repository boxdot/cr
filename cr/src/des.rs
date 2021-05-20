//! Data Encryption Standard (DES) block cipher
//!
//! https://csrc.nist.gov/csrc/media/publications/fips/46/3/archive/1999-10-25/documents/fips46-3.pdf

pub fn encrypt(plaintext: u64, key: u64) -> u64 {
    des(plaintext, round_keys(key))
}

pub fn decrypt(ciphertext: u64, key: u64) -> u64 {
    let round_keys: Vec<u64> = round_keys(key).collect();
    des(ciphertext, round_keys.into_iter().rev())
}

pub fn des(plaintext: u64, round_keys: impl Iterator<Item = u64>) -> u64 {
    let preoutput = permute(&IP_BITS, plaintext);

    // Note: the output is swapped
    let (right, left) = round_keys.fold(
        (preoutput as u32, (preoutput >> 32) as u32),
        |(left, right), round_key| (right, left ^ feistel(right, round_key)),
    );

    let preoutput = (right as u64) << 32 | left as u64;
    permute(&IP_INV_BITS, preoutput)
}

fn round_keys(key: u64) -> impl Iterator<Item = u64> {
    let key = permute(&PC1_BITS, key);
    let mut left_key = key & 0xfffffff; // 28 lower bits
    let mut right_key = key >> 28;

    (0..16).map(move |round| {
        left_key = rotate_key_left(left_key, LEFT_SHIFTS[round]);
        right_key = rotate_key_left(right_key, LEFT_SHIFTS[round]);
        permute(&PC2_BITS, (right_key << 28) | left_key) // 48 bits
    })
}

fn feistel(block: u32, round_key: u64) -> u32 {
    let mut mixed = expand(block) ^ round_key;
    let mut res = 0;
    for i in 0..8 {
        let block = mixed as u8 & 0b111111; // 6 bits block
        res = res << 4 | (s(block, i) as u32); // 4 bits block output
        mixed >>= 6;
    }
    permute(&P_BITS, res as u64) as u32
}

fn expand(block: u32) -> u64 {
    permute(&E_BITS, block as u64)
}

fn permute(perm: &[usize], block: u64) -> u64 {
    let mut res = 0;
    for bit in perm.iter().rev().map(|&b| b - 1) {
        res <<= 1;
        if (block >> bit) & 1 == 1 {
            res |= 1;
        }
    }
    res
}

fn s(block: u8, n: usize) -> u8 {
    let i = block >> 4 | (block & 1); // 6th and 1st bits
    let j = (block >> 1) & 0b1111; // 2-5 bits
    let idx = i as usize * 16 + j as usize;
    S_BOXES[n][idx]
}

fn rotate_key_left(mut bits: u64, n: usize) -> u64 {
    for _ in 0..n {
        let b = bits >> 27 & 1;
        bits = bits << 1 | b;
    }
    bits & 0xfffffff
}

/// Initial permutation
const IP_BITS: [usize; 64] = [
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61,
    53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
];

/// Inverse initial permutation
const IP_INV_BITS: [usize; 64] = [
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
];

/// Expansion permutation
const E_BITS: [usize; 48] = [
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18,
    19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
];

/// Permuted choice 1
const PC1_BITS: [usize; 56] = [
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60,
    52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4,
];

const LEFT_SHIFTS: [usize; 16] = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];

/// Permuted choice 2
const PC2_BITS: [usize; 48] = [
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52,
    31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
];

const S_BOXES: [[u8; 64]; 8] = [
    [
        14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12,
        11, 9, 5, 3, 8, 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, 15, 12, 8, 2, 4, 9,
        1, 7, 5, 11, 3, 14, 10, 0, 6, 13,
    ],
    [
        15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1,
        10, 6, 9, 11, 5, 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, 13, 8, 10, 1, 3, 15,
        4, 2, 11, 6, 7, 12, 0, 5, 14, 9,
    ],
    [
        10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5,
        14, 12, 11, 15, 1, 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7, 1, 10, 13, 0, 6,
        9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,
    ],
    [
        7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2,
        12, 1, 10, 14, 9, 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4, 3, 15, 0, 6, 10, 1,
        13, 8, 9, 4, 5, 11, 12, 7, 2, 14,
    ],
    [
        2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15,
        10, 3, 9, 8, 6, 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, 11, 8, 12, 7, 1, 14,
        2, 13, 6, 15, 0, 9, 10, 4, 5, 3,
    ],
    [
        12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13,
        14, 0, 11, 3, 8, 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, 4, 3, 2, 12, 9, 5,
        15, 10, 11, 14, 1, 7, 6, 0, 8, 13,
    ],
    [
        4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5,
        12, 2, 15, 8, 6, 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, 6, 11, 13, 8, 1, 4,
        10, 7, 9, 5, 0, 15, 14, 2, 3, 12,
    ],
    [
        13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6,
        11, 0, 14, 9, 2, 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8, 2, 1, 14, 7, 4, 10,
        8, 13, 15, 12, 9, 0, 3, 5, 6, 11,
    ],
];

/// Primitive permutation
const P_BITS: [usize; 32] = [
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19,
    13, 30, 6, 22, 11, 4, 25,
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex;

    #[test]
    fn test_encrypt() {
        let plaintext: u64 = u64::from_le_bytes(hex("0000000000C0FFEE").unwrap());
        let key: u64 = u64::from_le_bytes(hex("000000000000F00D").unwrap());
        let ciphertext: u64 = u64::from_le_bytes(hex("a271e9bac8862997").unwrap());

        assert_eq!(encrypt(plaintext, key), ciphertext);
        assert_eq!(decrypt(ciphertext, key), plaintext);
    }

    #[test]
    fn test_rotate_key_left() {
        assert_eq!(rotate_key_left(1, 1), 2);
        assert_eq!(rotate_key_left(1, 2), 4);
        assert_eq!(rotate_key_left(1 << 27, 1), 1);
        assert_eq!(rotate_key_left(1 << 27, 2), 2);
        assert_eq!(rotate_key_left((1 << 28) - 1, 2), (1 << 28) - 1);
    }
}
