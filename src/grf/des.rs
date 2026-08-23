//! Gravity GRF DES (not stock DES). Ported from PHP `GrfDES.php`.

const BLOCK: usize = 8;

const IP: [u8; 64] = [
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61,
    53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
];

const FP: [u8; 64] = [
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
];

const TP: [u8; 32] = [
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19,
    13, 30, 6, 22, 11, 4, 25,
];

const MASK: [u8; 8] = [0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01];

const S: [[u8; 64]; 4] = [
    [
        0xef, 0x03, 0x41, 0xfd, 0xd8, 0x74, 0x1e, 0x47, 0x26, 0xef, 0xfb, 0x22, 0xb3, 0xd8, 0x84,
        0x1e, 0x39, 0xac, 0xa7, 0x60, 0x62, 0xc1, 0xcd, 0xba, 0x5c, 0x96, 0x90, 0x59, 0x05, 0x3b,
        0x7a, 0x85, 0x40, 0xfd, 0x1e, 0xc8, 0xe7, 0x8a, 0x8b, 0x21, 0xda, 0x43, 0x64, 0x9f, 0x2d,
        0x14, 0xb1, 0x72, 0xf5, 0x5b, 0xc8, 0xb6, 0x9c, 0x37, 0x76, 0xec, 0x39, 0xa0, 0xa3, 0x05,
        0x52, 0x6e, 0x0f, 0xd9,
    ],
    [
        0xa7, 0xdd, 0x0d, 0x78, 0x9e, 0x0b, 0xe3, 0x95, 0x60, 0x36, 0x36, 0x4f, 0xf9, 0x60, 0x5a,
        0xa3, 0x11, 0x24, 0xd2, 0x87, 0xc8, 0x52, 0x75, 0xec, 0xbb, 0xc1, 0x4c, 0xba, 0x24, 0xfe,
        0x8f, 0x19, 0xda, 0x13, 0x66, 0xaf, 0x49, 0xd0, 0x90, 0x06, 0x8c, 0x6a, 0xfb, 0x91, 0x37,
        0x8d, 0x0d, 0x78, 0xbf, 0x49, 0x11, 0xf4, 0x23, 0xe5, 0xce, 0x3b, 0x55, 0xbc, 0xa2, 0x57,
        0xe8, 0x22, 0x74, 0xce,
    ],
    [
        0x2c, 0xea, 0xc1, 0xbf, 0x4a, 0x24, 0x1f, 0xc2, 0x79, 0x47, 0xa2, 0x7c, 0xb6, 0xd9, 0x68,
        0x15, 0x80, 0x56, 0x5d, 0x01, 0x33, 0xfd, 0xf4, 0xae, 0xde, 0x30, 0x07, 0x9b, 0xe5, 0x83,
        0x9b, 0x68, 0x49, 0xb4, 0x2e, 0x83, 0x1f, 0xc2, 0xb5, 0x7c, 0xa2, 0x19, 0xd8, 0xe5, 0x7c,
        0x2f, 0x83, 0xda, 0xf7, 0x6b, 0x90, 0xfe, 0xc4, 0x01, 0x5a, 0x97, 0x61, 0xa6, 0x3d, 0x40,
        0x0b, 0x58, 0xe6, 0x3d,
    ],
    [
        0x4d, 0xd1, 0xb2, 0x0f, 0x28, 0xbd, 0xe4, 0x78, 0xf6, 0x4a, 0x0f, 0x93, 0x8b, 0x17, 0xd1,
        0xa4, 0x3a, 0xec, 0xc9, 0x35, 0x93, 0x56, 0x7e, 0xcb, 0x55, 0x20, 0xa0, 0xfe, 0x6c, 0x89,
        0x17, 0x62, 0x17, 0x62, 0x4b, 0xb1, 0xb4, 0xde, 0xd1, 0x87, 0xc9, 0x14, 0x3c, 0x4a, 0x7e,
        0xa8, 0xe2, 0x7d, 0xa0, 0x9f, 0xf6, 0x5c, 0x6a, 0x09, 0x8d, 0xf0, 0x0f, 0xe3, 0x53, 0x25,
        0x95, 0x36, 0x28, 0xcb,
    ],
];

fn permute(src: &[u8; 8], table: &[u8], out: &mut [u8; 8]) {
    *out = [0; 8];
    for (i, &t) in table.iter().enumerate() {
        let j = (t as usize) - 1;
        if src[(j >> 3) & 7] & MASK[j & 7] != 0 {
            out[(i >> 3) & 7] |= MASK[i & 7];
        }
    }
}

fn round_function(src: &mut [u8; 8]) {
    let mut block = [0u8; 8];
    block[0] = ((src[7] << 5) | (src[4] >> 3)) & 0x3f;
    block[1] = ((src[4] << 1) | (src[5] >> 7)) & 0x3f;
    block[2] = ((src[4] << 5) | (src[5] >> 3)) & 0x3f;
    block[3] = ((src[5] << 1) | (src[6] >> 7)) & 0x3f;
    block[4] = ((src[5] << 5) | (src[6] >> 3)) & 0x3f;
    block[5] = ((src[6] << 1) | (src[7] >> 7)) & 0x3f;
    block[6] = ((src[6] << 5) | (src[7] >> 3)) & 0x3f;
    block[7] = ((src[7] << 1) | (src[4] >> 7)) & 0x3f;

    for i in 0..4 {
        let a = block[i * 2] as usize;
        let b = block[i * 2 + 1] as usize;
        block[i] = (S[i][a] & 0xf0) | (S[i][b] & 0x0f);
    }
    block[4] = 0;
    block[5] = 0;
    block[6] = 0;
    block[7] = 0;

    for i in 0..32 {
        let j = (TP[i] as usize) - 1;
        if block[j >> 3] & MASK[j & 7] != 0 {
            block[(i >> 3) + 4] |= MASK[i & 7];
        }
    }

    src[0] ^= block[4];
    src[1] ^= block[5];
    src[2] ^= block[6];
    src[3] ^= block[7];
}

pub fn decrypt_block(block: &[u8; 8]) -> [u8; 8] {
    let mut src = *block;
    let mut tmp = [0u8; 8];
    permute(&src, &IP, &mut tmp);
    src = tmp;
    round_function(&mut src);
    permute(&src, &FP, &mut tmp);
    tmp
}

fn apply_blocks(data: &mut [u8], max_blocks: usize, mut visit: impl FnMut(usize, &mut [u8])) {
    let n = (data.len() / BLOCK).min(max_blocks);
    for i in 0..n {
        let off = i * BLOCK;
        visit(i, &mut data[off..off + BLOCK]);
    }
}

pub fn decrypt_header(data: &mut [u8]) {
    apply_blocks(data, 20, |_i, chunk| {
        let mut b = [0u8; 8];
        b.copy_from_slice(chunk);
        let d = decrypt_block(&b);
        chunk.copy_from_slice(&d);
    });
}

pub fn decrypt_mixed(data: &mut [u8], mut cycle: usize, is_data_crypted: bool) {
    if !is_data_crypted {
        if cycle < 3 {
            cycle = 3;
        } else if cycle < 5 {
            cycle += 1;
        } else if cycle < 7 {
            cycle += 9;
        } else {
            cycle += 15;
        }
    }

    let mut cnt = 0usize;
    let decrypt_blocks = data.len() / BLOCK;
    for i in 0..decrypt_blocks {
        let off = i * BLOCK;
        if i < 20 || (!is_data_crypted && i % cycle == 0) {
            let mut b = [0u8; 8];
            b.copy_from_slice(&data[off..off + 8]);
            let d = decrypt_block(&b);
            data[off..off + 8].copy_from_slice(&d);
        } else {
            if cnt == 7 && !is_data_crypted {
                cnt = 0;
                let tmp = {
                    let mut t = [0u8; 8];
                    t.copy_from_slice(&data[off..off + 8]);
                    t
                };
                data[off] = tmp[3];
                data[off + 1] = tmp[4];
                data[off + 2] = tmp[6];
                data[off + 3] = tmp[0];
                data[off + 4] = tmp[1];
                data[off + 5] = tmp[2];
                data[off + 6] = tmp[5];
                data[off + 7] = shuffle_last(tmp[7]);
            }
            cnt += 1;
        }
    }
}

fn shuffle_last(a: u8) -> u8 {
    match a {
        0x00 => 0x2b,
        0x2b => 0x00,
        0x01 => 0x68,
        0x68 => 0x01,
        0x48 => 0x77,
        0x77 => 0x48,
        0x60 => 0xff,
        0xff => 0x60,
        0x6c => 0x80,
        0x80 => 0x6c,
        0xb9 => 0xc0,
        0xc0 => 0xb9,
        0xeb => 0xfe,
        0xfe => 0xeb,
        x => x,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decrypt_block_is_deterministic() {
        let b = [1, 2, 3, 4, 5, 6, 7, 8];
        let a = decrypt_block(&b);
        let c = decrypt_block(&b);
        assert_eq!(a, c);
        assert_ne!(a, b);
    }
}
