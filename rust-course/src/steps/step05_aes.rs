//! Adım 5 — AES-128 ve AES-256 (kütüphanesiz).
//!
//! Bu dosya FIPS-197'nin elle yazılmış, okunabilir bir uygulamasıdır.
//! Gerçek üründe `aes` / `aes-gcm` crate'leri kullanılır; burası öğrenme.
//!
//! # Blok her zaman 16 byte (128 bit)
//! Anahtar boyutu değişir:
//! - AES-128: 16 byte anahtar, 10 tur
//! - AES-256: 32 byte anahtar, 14 tur
//!
//! # Bir turda olanlar
//! 1. SubBytes     — her byte S-box'tan geçer (doğrusal olmayan karışım)
//! 2. ShiftRows    — satırlar kayar (byte'lar yer değiştirir)
//! 3. MixColumns   — sütunlar GF(2^8) içinde karışır (son turda YOK)
//! 4. AddRoundKey  — tur anahtarı ile XOR (Adım 4'teki fikir)
//!
//! Şifre çözme aynı adımların tersi sırada.

use crate::util::to_hex;

const BLOCK: usize = 16;

const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

const INV_SBOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

pub fn run() {
    println!("\n--- Adim 5: AES-128 / AES-256 (elle) ---");
    println!("Uyari: bu kod ogrenme icindir, gercek sirri bununla saklama.\n");

    // FIPS-197 Appendix C.1 — AES-128
    let key128 = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    let plain = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];
    let aes128 = Aes128::new(&key128);
    let c128 = aes128.encrypt_block(&plain);
    let p128 = aes128.decrypt_block(&c128);
    println!("AES-128");
    println!("  acik    {}", to_hex(&plain));
    println!("  sifreli {}", to_hex(&c128));
    println!("  cozulen {}", to_hex(&p128));

    // FIPS-197 Appendix C.3 — AES-256
    let key256 = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    let aes256 = Aes256::new(&key256);
    let c256 = aes256.encrypt_block(&plain);
    let p256 = aes256.decrypt_block(&c256);
    println!("AES-256");
    println!("  acik    {}", to_hex(&plain));
    println!("  sifreli {}", to_hex(&c256));
    println!("  cozulen {}", to_hex(&p256));

    // Pratik: 16 byte olmayan bir metni PKCS#7 ile doldurup ECB'de dolaştır.
    let mesaj = b"Merhaba Rust!";
    let sifreli = aes128.encrypt_ecb(mesaj);
    let cozulmus = aes128.decrypt_ecb(&sifreli).expect("padding bozuk");
    println!("\nMetin (AES-128 ECB, ogrenme modu)");
    println!("  acik     {}", String::from_utf8_lossy(mesaj));
    println!("  sifreli  {}", to_hex(&sifreli));
    println!("  cozulmus {}", String::from_utf8_lossy(&cozulmus));
}

/// AES-128: 16 byte anahtar, 10 tur, 11 tur anahtarı (176 byte).
pub struct Aes128 {
    round_keys: [u8; 176],
}

impl Aes128 {
    pub fn new(key: &[u8; 16]) -> Self {
        Self {
            round_keys: expand_key(key, 4, 10).try_into().expect("176 byte"),
        }
    }

    pub fn encrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        encrypt_block(block, &self.round_keys, 10)
    }

    pub fn decrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        decrypt_block(block, &self.round_keys, 10)
    }

    pub fn encrypt_ecb(&self, plaintext: &[u8]) -> Vec<u8> {
        encrypt_ecb(plaintext, |b| self.encrypt_block(b))
    }

    pub fn decrypt_ecb(&self, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        decrypt_ecb(ciphertext, |b| self.decrypt_block(b))
    }
}

/// AES-256: 32 byte anahtar, 14 tur, 15 tur anahtarı (240 byte).
pub struct Aes256 {
    round_keys: [u8; 240],
}

impl Aes256 {
    pub fn new(key: &[u8; 32]) -> Self {
        Self {
            round_keys: expand_key(key, 8, 14).try_into().expect("240 byte"),
        }
    }

    pub fn encrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        encrypt_block(block, &self.round_keys, 14)
    }

    pub fn decrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        decrypt_block(block, &self.round_keys, 14)
    }

    pub fn encrypt_ecb(&self, plaintext: &[u8]) -> Vec<u8> {
        encrypt_ecb(plaintext, |b| self.encrypt_block(b))
    }

    pub fn decrypt_ecb(&self, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        decrypt_ecb(ciphertext, |b| self.decrypt_block(b))
    }
}

fn encrypt_block(input: &[u8; 16], round_keys: &[u8], nr: usize) -> [u8; 16] {
    let mut s = *input;
    add_round_key(&mut s, &round_keys[0..16]);

    for round in 1..nr {
        sub_bytes(&mut s);
        shift_rows(&mut s);
        mix_columns(&mut s);
        add_round_key(&mut s, &round_keys[round * 16..(round + 1) * 16]);
    }

    sub_bytes(&mut s);
    shift_rows(&mut s);
    add_round_key(&mut s, &round_keys[nr * 16..(nr + 1) * 16]);
    s
}

fn decrypt_block(input: &[u8; 16], round_keys: &[u8], nr: usize) -> [u8; 16] {
    let mut s = *input;
    add_round_key(&mut s, &round_keys[nr * 16..(nr + 1) * 16]);
    inv_shift_rows(&mut s);
    inv_sub_bytes(&mut s);

    for round in (1..nr).rev() {
        add_round_key(&mut s, &round_keys[round * 16..(round + 1) * 16]);
        inv_mix_columns(&mut s);
        inv_shift_rows(&mut s);
        inv_sub_bytes(&mut s);
    }

    add_round_key(&mut s, &round_keys[0..16]);
    s
}

fn sub_bytes(state: &mut [u8; 16]) {
    for byte in state.iter_mut() {
        *byte = SBOX[*byte as usize];
    }
}

fn inv_sub_bytes(state: &mut [u8; 16]) {
    for byte in state.iter_mut() {
        *byte = INV_SBOX[*byte as usize];
    }
}

/// Satır r, sütun c → index `c * 4 + r` (sütun-major).
fn shift_rows(state: &mut [u8; 16]) {
    let t = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = t;

    let t = state[2];
    state[2] = state[10];
    state[10] = t;
    let t = state[6];
    state[6] = state[14];
    state[14] = t;

    let t = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = state[3];
    state[3] = t;
}

fn inv_shift_rows(state: &mut [u8; 16]) {
    let t = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = t;

    let t = state[2];
    state[2] = state[10];
    state[10] = t;
    let t = state[6];
    state[6] = state[14];
    state[14] = t;

    let t = state[3];
    state[3] = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = t;
}

fn mix_columns(state: &mut [u8; 16]) {
    for col in 0..4 {
        let i = col * 4;
        let a0 = state[i];
        let a1 = state[i + 1];
        let a2 = state[i + 2];
        let a3 = state[i + 3];
        state[i] = gf_mul(a0, 2) ^ gf_mul(a1, 3) ^ a2 ^ a3;
        state[i + 1] = a0 ^ gf_mul(a1, 2) ^ gf_mul(a2, 3) ^ a3;
        state[i + 2] = a0 ^ a1 ^ gf_mul(a2, 2) ^ gf_mul(a3, 3);
        state[i + 3] = gf_mul(a0, 3) ^ a1 ^ a2 ^ gf_mul(a3, 2);
    }
}

fn inv_mix_columns(state: &mut [u8; 16]) {
    for col in 0..4 {
        let i = col * 4;
        let a0 = state[i];
        let a1 = state[i + 1];
        let a2 = state[i + 2];
        let a3 = state[i + 3];
        state[i] = gf_mul(a0, 0x0e) ^ gf_mul(a1, 0x0b) ^ gf_mul(a2, 0x0d) ^ gf_mul(a3, 0x09);
        state[i + 1] = gf_mul(a0, 0x09) ^ gf_mul(a1, 0x0e) ^ gf_mul(a2, 0x0b) ^ gf_mul(a3, 0x0d);
        state[i + 2] = gf_mul(a0, 0x0d) ^ gf_mul(a1, 0x09) ^ gf_mul(a2, 0x0e) ^ gf_mul(a3, 0x0b);
        state[i + 3] = gf_mul(a0, 0x0b) ^ gf_mul(a1, 0x0d) ^ gf_mul(a2, 0x09) ^ gf_mul(a3, 0x0e);
    }
}

fn add_round_key(state: &mut [u8; 16], key: &[u8]) {
    for i in 0..16 {
        state[i] ^= key[i];
    }
}

/// GF(2^8) içinde `a * 2`. Taşarsa AES polinomu 0x1b ile XOR.
fn xtime(a: u8) -> u8 {
    let shifted = a << 1;
    if a & 0x80 != 0 {
        shifted ^ 0x1b
    } else {
        shifted
    }
}

/// GF(2^8) çarpımı — MixColumns'un kalbi.
fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    for _ in 0..8 {
        if b & 1 != 0 {
            p ^= a;
        }
        a = xtime(a);
        b >>= 1;
    }
    p
}

fn rot_word(word: [u8; 4]) -> [u8; 4] {
    [word[1], word[2], word[3], word[0]]
}

fn sub_word(word: [u8; 4]) -> [u8; 4] {
    [
        SBOX[word[0] as usize],
        SBOX[word[1] as usize],
        SBOX[word[2] as usize],
        SBOX[word[3] as usize],
    ]
}

fn rcon(i: usize) -> u8 {
    let mut c = 1u8;
    for _ in 1..i {
        c = xtime(c);
    }
    c
}

/// `nk`: anahtar kelime sayısı (AES-128=4, AES-256=8).
/// `nr`: tur sayısı (10 veya 14).
fn expand_key(key: &[u8], nk: usize, nr: usize) -> Vec<u8> {
    let total_words = 4 * (nr + 1);
    let mut w = vec![0u8; total_words * 4];
    w[..key.len()].copy_from_slice(key);

    let mut i = nk;
    while i < total_words {
        let mut temp = [
            w[(i - 1) * 4],
            w[(i - 1) * 4 + 1],
            w[(i - 1) * 4 + 2],
            w[(i - 1) * 4 + 3],
        ];
        if i % nk == 0 {
            temp = sub_word(rot_word(temp));
            temp[0] ^= rcon(i / nk);
        } else if nk > 6 && i % nk == 4 {
            // AES-256'ya özel: her 8 kelimede bir extra SubWord
            temp = sub_word(temp);
        }
        for j in 0..4 {
            w[i * 4 + j] = w[(i - nk) * 4 + j] ^ temp[j];
        }
        i += 1;
    }
    w
}

fn pkcs7_pad(data: &[u8]) -> Vec<u8> {
    let n = BLOCK - (data.len() % BLOCK);
    let mut out = data.to_vec();
    out.extend(std::iter::repeat(n as u8).take(n));
    out
}

fn pkcs7_unpad(data: &[u8]) -> Result<Vec<u8>, String> {
    if data.is_empty() || data.len() % BLOCK != 0 {
        return Err("sifreli veri 16'nin kati olmali".into());
    }
    let n = *data.last().unwrap() as usize;
    if n == 0 || n > BLOCK || data.len() < n {
        return Err("gecersiz padding".into());
    }
    let start = data.len() - n;
    if data[start..].iter().any(|&b| b as usize != n) {
        return Err("gecersiz padding".into());
    }
    Ok(data[..start].to_vec())
}

fn encrypt_ecb(plaintext: &[u8], encrypt: impl Fn(&[u8; 16]) -> [u8; 16]) -> Vec<u8> {
    let padded = pkcs7_pad(plaintext);
    padded
        .chunks(BLOCK)
        .map(|chunk| encrypt(chunk.try_into().unwrap()))
        .flatten()
        .collect()
}

fn decrypt_ecb(
    ciphertext: &[u8],
    decrypt: impl Fn(&[u8; 16]) -> [u8; 16],
) -> Result<Vec<u8>, String> {
    if ciphertext.len() % BLOCK != 0 {
        return Err("sifreli veri 16'nin kati olmali".into());
    }
    let mut out = Vec::with_capacity(ciphertext.len());
    for chunk in ciphertext.chunks(BLOCK) {
        out.extend_from_slice(&decrypt(chunk.try_into().unwrap()));
    }
    pkcs7_unpad(&out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::from_hex;

    fn hex16(s: &str) -> [u8; 16] {
        from_hex(s).unwrap().try_into().unwrap()
    }

    fn hex32(s: &str) -> [u8; 32] {
        from_hex(s).unwrap().try_into().unwrap()
    }

    #[test]
    fn aes128_fips197() {
        let key = hex16("000102030405060708090a0b0c0d0e0f");
        let plain = hex16("00112233445566778899aabbccddeeff");
        let expected = hex16("69c4e0d86a7b0430d8cdb78070b4c55a");
        let aes = Aes128::new(&key);
        let cipher = aes.encrypt_block(&plain);
        assert_eq!(cipher, expected);
        assert_eq!(aes.decrypt_block(&cipher), plain);
    }

    #[test]
    fn aes256_fips197() {
        let key = hex32("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let plain = hex16("00112233445566778899aabbccddeeff");
        let expected = hex16("8ea2b7ca516745bfeafc49904b496089");
        let aes = Aes256::new(&key);
        let cipher = aes.encrypt_block(&plain);
        assert_eq!(cipher, expected);
        assert_eq!(aes.decrypt_block(&cipher), plain);
    }

    #[test]
    fn aes128_ecb_roundtrip_utf8() {
        let key = [0x42u8; 16];
        let aes = Aes128::new(&key);
        let msg = "sifrelenecek turkce metin!";
        let out = aes.encrypt_ecb(msg.as_bytes());
        let back = aes.decrypt_ecb(&out).unwrap();
        assert_eq!(String::from_utf8(back).unwrap(), msg);
    }

    #[test]
    fn gf_mul_known() {
        assert_eq!(gf_mul(0x57, 0x13), 0xfe);
        assert_eq!(gf_mul(0x53, 0xca), 0x01);
    }
}
