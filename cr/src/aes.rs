//! Advanced Encryption Standard (AES) block cipher
//!
//! https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
//!
// Note: all non-byte array types values (e.g. u32/u64) represent bytes in LE order.

// AES-128: Nk = 4, Nb = 4, Nr = 10
//

const NK: usize = 4; // Key size in words
const NB: usize = 4; // Block size in words
const NR: usize = 10; // Number of rounds

pub fn encrypt_128(plaintext: [u8; 4 * NB], key: [u8; 4 * NK]) -> [u8; 4 * NB] {
    let round_keys = key_expansion(key);
    encrypt_impl(plaintext, round_keys)
}

fn encrypt_impl(plaintext: [u8; 4 * NB], round_keys: [u32; NB * (NR + 1)]) -> [u8; 4 * NB] {
    let mut state = plaintext;

    add_round_key(&mut state, &round_keys[0..NB]);

    for round in 1..NR {
        sub_bytes(&mut state);
        mix_columns(&mut state);
        add_round_key(&mut state, &round_keys[round * NB..(round + 1) * NB]);
    }

    sub_bytes(&mut state);
    shift_rows(&mut state);
    add_round_key(&mut state, &round_keys[NR * NB..(NR + 1) * NB]);

    state
}

fn sub_bytes(state: &mut [u8; 4 * NB]) {
    for b in state {
        *b = s_box(*b);
    }
}

fn mix_columns(state: &mut [u8; 4 * NB]) {
    let mut s = [0; 4]; // copy of a state column
    let mut s2 = [0; 4]; // elements of a state column mult by 2
    for c in 0..4 {
        // mutiplication in GF(2^8) defined by irreducible polynomial x^8 + x^4 + x^3 + x + 1
        for i in 0..4 {
            let x = state[4 * c + i];
            s[i] = x;
            let h = x >> 7 & 1; // x >= 128
            s2[i] = x << 1; // * 2
            s2[i] ^= h * 0x1B; // + {0|1} * x^8 + x^4 + x^3 + x + 1
        }
        state[4 * c + 0] = s2[0] ^ s[3] ^ s[2] ^ s2[1] ^ s[1];
        state[4 * c + 1] = s2[1] ^ s[0] ^ s[3] ^ s2[2] ^ s[2];
        state[4 * c + 2] = s2[2] ^ s[1] ^ s[0] ^ s2[3] ^ s[3];
        state[4 * c + 3] = s2[3] ^ s[2] ^ s[1] ^ s2[0] ^ s[0];
    }
}

fn shift_rows(state: &mut [u8; 4 * NB]) {
    // 1 row: untouched
    // 2 row: 1-left shift
    let s_1_0 = at(state, 1, 0);
    *at_mut(state, 1, 0) = at(state, 1, 1);
    *at_mut(state, 1, 1) = at(state, 1, 2);
    *at_mut(state, 1, 2) = at(state, 1, 3);
    *at_mut(state, 1, 3) = s_1_0;
    // 3 row: 2-left shift
    let s_2_0 = at(state, 2, 0);
    let s_2_1 = at(state, 2, 1);
    *at_mut(state, 2, 0) = at(state, 2, 2);
    *at_mut(state, 2, 1) = at(state, 2, 3);
    *at_mut(state, 2, 2) = s_2_0;
    *at_mut(state, 2, 3) = s_2_1;
    // 4 row: 3-left shift <=> 1-right shift
    let s_3_3 = at(state, 3, 3);
    *at_mut(state, 3, 3) = at(state, 3, 2);
    *at_mut(state, 3, 2) = at(state, 3, 1);
    *at_mut(state, 3, 1) = at(state, 3, 0);
    *at_mut(state, 3, 0) = s_3_3;
}

fn at(state: &[u8; 4 * NB], row: usize, col: usize) -> u8 {
    state[row + 4 * col]
}

fn at_mut(state: &mut [u8; 4 * NB], row: usize, col: usize) -> &mut u8 {
    &mut state[row + 4 * col]
}

fn add_round_key(state: &mut [u8; 4 * NB], round_keys: &[u32]) {
    let state_128 = u128::from_le_bytes(*state);
    let mut key_bytes = [0; 4 * NB];
    for (col, round_key) in round_keys.iter().enumerate() {
        let bytes = round_key.to_le_bytes();
        key_bytes[4 * col] = bytes[0];
        key_bytes[4 * col + 1] = bytes[1];
        key_bytes[4 * col + 2] = bytes[2];
        key_bytes[4 * col + 3] = bytes[3];
    }
    let key_128 = u128::from_le_bytes(key_bytes);
    *state = (state_128 ^ key_128).to_le_bytes();
}

fn key_expansion(key: [u8; 4 * NK]) -> [u32; NB * (NR + 1)] {
    let mut res = [0; NB * (NR + 1)];

    for i in 0..NK {
        res[i] = u32::from_le_bytes([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
    }

    let mut tmp;
    for i in NK..NB * (NR + 1) {
        tmp = res[i - 1];
        if i % NK == 0 {
            tmp = sub_word(rot_word(tmp)) ^ RCON[i / NK];
        } else if NK > 6 && i % NK == 4 {
            tmp = sub_word(tmp);
        }
        res[i] = res[i - NK] ^ tmp;
    }

    res
}

fn rot_word(w: u32) -> u32 {
    // LE bytes representation: rotate left => rotate right
    w.rotate_right(8)
}

fn sub_word(w: u32) -> u32 {
    let mut bytes = w.to_le_bytes();
    for b in &mut bytes {
        *b = s_box(*b);
    }
    u32::from_le_bytes(bytes)
}

fn s_box(b: u8) -> u8 {
    let row = (b >> 4) as usize;
    let col = (b & 0xF) as usize;
    S_BOX[row][col]
}

#[rustfmt::skip]
const S_BOX: [[u8; 16]; 16] = [
    [0x63,  0x7c,  0x77,  0x7b,  0xf2,  0x6b,  0x6f,  0xc5,  0x30,  0x01,  0x67,  0x2b,  0xfe,  0xd7,  0xab,  0x76],
    [0xca,  0x82,  0xc9,  0x7d,  0xfa,  0x59,  0x47,  0xf0,  0xad,  0xd4,  0xa2,  0xaf,  0x9c,  0xa4,  0x72,  0xc0],
    [0xb7,  0xfd,  0x93,  0x26,  0x36,  0x3f,  0xf7,  0xcc,  0x34,  0xa5,  0xe5,  0xf1,  0x71,  0xd8,  0x31,  0x15],
    [0x04,  0xc7,  0x23,  0xc3,  0x18,  0x96,  0x05,  0x9a,  0x07,  0x12,  0x80,  0xe2,  0xeb,  0x27,  0xb2,  0x75],
    [0x09,  0x83,  0x2c,  0x1a,  0x1b,  0x6e,  0x5a,  0xa0,  0x52,  0x3b,  0xd6,  0xb3,  0x29,  0xe3,  0x2f,  0x84],
    [0x53,  0xd1,  0x00,  0xed,  0x20,  0xfc,  0xb1,  0x5b,  0x6a,  0xcb,  0xbe,  0x39,  0x4a,  0x4c,  0x58,  0xcf],
    [0xd0,  0xef,  0xaa,  0xfb,  0x43,  0x4d,  0x33,  0x85,  0x45,  0xf9,  0x02,  0x7f,  0x50,  0x3c,  0x9f,  0xa8],
    [0x51,  0xa3,  0x40,  0x8f,  0x92,  0x9d,  0x38,  0xf5,  0xbc,  0xb6,  0xda,  0x21,  0x10,  0xff,  0xf3,  0xd2],
    [0xcd,  0x0c,  0x13,  0xec,  0x5f,  0x97,  0x44,  0x17,  0xc4,  0xa7,  0x7e,  0x3d,  0x64,  0x5d,  0x19,  0x73],
    [0x60,  0x81,  0x4f,  0xdc,  0x22,  0x2a,  0x90,  0x88,  0x46,  0xee,  0xb8,  0x14,  0xde,  0x5e,  0x0b,  0xdb],
    [0xe0,  0x32,  0x3a,  0x0a,  0x49,  0x06,  0x24,  0x5c,  0xc2,  0xd3,  0xac,  0x62,  0x91,  0x95,  0xe4,  0x79],
    [0xe7,  0xc8,  0x37,  0x6d,  0x8d,  0xd5,  0x4e,  0xa9,  0x6c,  0x56,  0xf4,  0xea,  0x65,  0x7a,  0xae,  0x08],
    [0xba,  0x78,  0x25,  0x2e,  0x1c,  0xa6,  0xb4,  0xc6,  0xe8,  0xdd,  0x74,  0x1f,  0x4b,  0xbd,  0x8b,  0x8a],
    [0x70,  0x3e,  0xb5,  0x66,  0x48,  0x03,  0xf6,  0x0e,  0x61,  0x35,  0x57,  0xb9,  0x86,  0xc1,  0x1d,  0x9e],
    [0xe1,  0xf8,  0x98,  0x11,  0x69,  0xd9,  0x8e,  0x94,  0x9b,  0x1e,  0x87,  0xe9,  0xce,  0x55,  0x28,  0xdf],
    [0x8c,  0xa1,  0x89,  0x0d,  0xbf,  0xe6,  0x42,  0x68,  0x41,  0x99,  0x2d,  0x0f,  0xb0,  0x54,  0xbb,  0x16],
];

/// Round constants
///
/// Constants are in LE bytes representation.
/// First constant is unused, since the counting starts at 1.
///
/// AES-128: uses up to RCON[10]
/// AES-192: uses up to RCON[8]
/// AES-256: uses up to RCON[7]
const RCON: [u32; 11] = [0, 1, 2, 4, 8, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

#[cfg(test)]
mod tests {
    use super::*;

    use std::convert::TryInto;

    #[test]
    fn test_shift_rows() {
        let mut state = [
            1, 1, 1, 1, // column
            2, 2, 2, 2, //
            3, 3, 3, 3, //
            4, 4, 4, 4,
        ];
        let expected = [
            1, 2, 3, 4, //
            2, 3, 4, 1, //
            3, 4, 1, 2, //
            4, 1, 2, 3,
        ];
        shift_rows(&mut state);
        assert_eq!(state, expected);
    }

    #[test]
    fn test_key_expansion_128() {
        const EXPECTED_ROUND_KEYS_BE: [u32; NB * (NR + 1)] = [
            0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c, 0xa0fafe17, 0x88542cb1, 0x23a33939,
            0x2a6c7605, 0xf2c295f2, 0x7a96b943, 0x5935807a, 0x7359f67f, 0x3d80477d, 0x4716fe3e,
            0x1e237e44, 0x6d7a883b, 0xef44a541, 0xa8525b7f, 0xb671253b, 0xdb0bad00, 0xd4d1c6f8,
            0x7c839d87, 0xcaf2b8bc, 0x11f915bc, 0x6d88a37a, 0x110b3efd, 0xdbf98641, 0xca0093fd,
            0x4e54f70e, 0x5f5fc9f3, 0x84a64fb2, 0x4ea6dc4f, 0xead27321, 0xb58dbad2, 0x312bf560,
            0x7f8d292f, 0xac7766f3, 0x19fadc21, 0x28d12941, 0x575c006e, 0xd014f9a8, 0xc9ee2589,
            0xe13f0cc8, 0xb6630ca6,
        ];
        let expected_round_keys: Vec<_> = EXPECTED_ROUND_KEYS_BE
            .iter()
            .map(|x| x.swap_bytes())
            .collect();

        let key = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
        let round_keys = key_expansion(key.try_into().unwrap());
        assert_eq!(round_keys, &expected_round_keys[..]);
    }

    #[test]
    fn test_mix_columns() {
        let expected = hex::decode("046681e5e0cb199a48f8d37a2806264c").unwrap();
        let state = hex::decode("d4bf5d30e0b452aeb84111f11e2798e5").unwrap();
        let mut state = state.try_into().unwrap();
        mix_columns(&mut state);
        assert_eq!(state, &expected[..]);
    }

    #[test]
    fn test_encrypt_128() {
        let plaintext = hex::decode("3243f6a8885a308d313198a2e0370734").unwrap();
        let key = hex::decode("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
        let ciphertext = encrypt_128(plaintext.try_into().unwrap(), key.try_into().unwrap());

        let expected_ciphertext = hex::decode("3925841d02dc09fbdc118597196a0b32").unwrap();
        assert_eq!(ciphertext, &expected_ciphertext[..]);
    }
}
