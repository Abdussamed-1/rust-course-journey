//! Adım 3 — Byte ve bit.
//!
//! Şifreleme metinle değil, sayılarla çalışır.
//! 1 byte = 8 bit = `u8` (0..=255).
//! AES bloğu her zaman 128 bit = 16 byte.
//! AES-128 anahtarı 16 byte, AES-256 anahtarı 32 byte.

use crate::util::to_hex;

pub fn run() {
    println!("\n--- Adim 3: Byte ve bit ---");

    let letter_a: u8 = b'A';
    println!(
        "'A' nin byte degeri: {letter_a} (hex {})",
        to_hex(&[letter_a])
    );

    let x: u8 = 0b0000_1100; // 12
    println!("0b0000_1100 = {x}");
    println!("  sola kaydir << 1 => {}", x << 1); // 24, bitler kayar
    println!("  XOR 0b0000_0011 => {}", x ^ 0b0000_0011);

    println!("AES blok:  {} bit = {} byte", 128, bits_to_bytes(128));
    println!("AES-128 key: {} bit = {} byte", 128, bits_to_bytes(128));
    println!("AES-256 key: {} bit = {} byte", 256, bits_to_bytes(256));

    let hello = b"Merhaba";
    println!("'Merhaba' byte'lari: {}", to_hex(hello));
}

pub fn bits_to_bytes(bits: usize) -> usize {
    bits / 8
}

/// İki dilimi byte byte XOR'la. Uzunluklar eşit olmalı.
pub fn xor_bytes(left: &[u8], right: &[u8]) -> Result<Vec<u8>, String> {
    if left.len() != right.len() {
        return Err("XOR icin iki dilim ayni uzunlukta olmali".into());
    }
    Ok(left.iter().zip(right).map(|(a, b)| a ^ b).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes_sizes() {
        assert_eq!(bits_to_bytes(128), 16);
        assert_eq!(bits_to_bytes(256), 32);
    }

    #[test]
    fn xor_is_reversible() {
        let a = [0x10, 0x20, 0x30];
        let b = [0x01, 0x02, 0x03];
        let mixed = xor_bytes(&a, &b).unwrap();
        let back = xor_bytes(&mixed, &b).unwrap();
        assert_eq!(back, a);
    }
}
