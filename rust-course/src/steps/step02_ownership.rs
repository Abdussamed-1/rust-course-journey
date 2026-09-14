//! Adım 2 — Ownership (sahiplik).
//!
//! Rust'ta her değerin bir sahibi vardır. AES yazarken 16 byte'lık bloğu
//! kopyalamak yerine `&[u8; 16]` ile ödünç alırız: veri yerinde kalır,
//! fonksiyon sadece bakar veya (mut ise) yerinde değiştirir.

pub fn run() {
    println!("\n--- Adim 2: Ownership ---");

    // String heap'te yaşar. `name` sahibi, `moved` olursa eski isim kullanılamaz.
    let name = String::from("Rust");
    let also_name = name.clone(); // bilinçli kopya: iki ayrı String
    greet(&name); // borçlanma: sahiplik name'de kalır
    println!("hala kullanabilirim: {name}, kopya: {also_name}");

    // AES state'i gibi sabit boyutlu dizi: stack'te, ucuz kopyalanır.
    let mut block = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
    xor_in_place(&mut block, 0xff);
    println!(
        "xor sonrasi ilk 4 byte: {:02x} {:02x} {:02x} {:02x}",
        block[0], block[1], block[2], block[3]
    );
}

fn greet(who: &str) {
    println!("Merhaba, {who}!");
}

/// Dilimin her byte'ını `mask` ile XOR'la. AES'teki AddRoundKey'in minik hali.
fn xor_in_place(data: &mut [u8], mask: u8) {
    for byte in data.iter_mut() {
        *byte ^= mask;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xor_in_place_is_its_own_inverse() {
        let original = [1u8, 2, 3, 4];
        let mut data = original;
        xor_in_place(&mut data, 0xab);
        xor_in_place(&mut data, 0xab);
        assert_eq!(data, original);
    }
}
