//! Adım 4 — XOR şifre (en sade şifreleme).
//!
//! Fikir: `şifreli = açık XOR anahtar`
//! Aynı işlem geri alır: `açık = şifreli XOR anahtar`
//!
//! AES'te her turda yapılan AddRoundKey tam olarak budur.
//! Fark: AES anahtarı bir kez XOR'lamakla yetinmez; S-box, kaydırma,
//! sütun karıştırma ekler. Bu adım o karmaşadan önceki iskelet.

use crate::util::to_hex;

pub fn run() {
    println!("\n--- Adim 4: XOR sifre ---");

    let acik = b"merhaba rust";
    let anahtar = b"kurs";

    let sifreli = xor_crypt(acik, anahtar);
    let cozulmus = xor_crypt(&sifreli, anahtar);

    println!("acik     : {}", String::from_utf8_lossy(acik));
    println!("anahtar  : {}", String::from_utf8_lossy(anahtar));
    println!("sifreli  : {}", to_hex(&sifreli));
    println!("cozulmus : {}", String::from_utf8_lossy(&cozulmus));
}

/// Tekrarlayan anahtar XOR. Anahtar metinden kısaysa başa sarar.
pub fn xor_crypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    if key.is_empty() {
        return data.to_vec();
    }
    data.iter()
        .enumerate()
        .map(|(i, byte)| byte ^ key[i % key.len()])
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xor_roundtrip() {
        let text = b"sifrelenecek metin";
        let key = b"anahtar";
        let once = xor_crypt(text, key);
        let twice = xor_crypt(&once, key);
        assert_eq!(twice, text);
        assert_ne!(once, text);
    }

    #[test]
    fn empty_key_is_copy() {
        assert_eq!(xor_crypt(b"abc", b""), b"abc");
    }
}
