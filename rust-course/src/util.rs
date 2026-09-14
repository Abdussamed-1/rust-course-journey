//! Ortak, küçük yardımcılar.
//! Şimdilik sadece byte'ları hex olarak okumak / yazmak için.

/// `[0x0a, 0x1b]` -> `"0a1b"`
pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `"0a1b"` -> `[0x0a, 0x1b]`
///
/// Tek karakter, boşluk dışı garip harf veya tek sayıda karakter hata döner.
pub fn from_hex(text: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.len() % 2 != 0 {
        return Err("hex metin cift sayida karakter olmali".into());
    }

    let mut out = Vec::with_capacity(cleaned.len() / 2);
    let chars: Vec<char> = cleaned.chars().collect();
    for chunk in chars.chunks(2) {
        let pair = format!("{}{}", chunk[0], chunk[1]);
        let byte = u8::from_str_radix(&pair, 16).map_err(|_| format!("gecersiz hex: {pair}"))?;
        out.push(byte);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip() {
        let bytes = vec![0x00, 0x0f, 0x10, 0xff];
        assert_eq!(to_hex(&bytes), "000f10ff");
        assert_eq!(from_hex("000f10ff").unwrap(), bytes);
        assert_eq!(from_hex("00 0f 10 ff").unwrap(), bytes);
    }
}
