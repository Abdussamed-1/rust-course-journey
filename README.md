# Rust Course Journey — Zero to Hero

Bu repo, Rust'ı sıfırdan elle yazarak öğrenmek için. Hazır şifreleme crate'i yok:
önce senin başlangıç pratiklerin, sonra byte/bit, sonra XOR, en sonda **AES-128** ve **AES-256**.

## Nasıl çalıştırılır

```bash
cd rust-course

cargo run                           # senin main.rs pratiklerin
cargo run --bin journey             # sonraki adımlar (2-5)
cargo run --bin journey -- xor      # XOR şifre
cargo run --bin journey -- aes      # AES-128 / AES-256

cargo test                          # adım testleri
```

## Öğrenme haritası

| Adım | Dosya | Ne pratik ediyorsun |
|------|--------|---------------------|
| 1 | `src/main.rs` | senin yazdığın temeller (değişken, if, döngü, fonksiyon, dizi) |
| 2 | `src/steps/step02_ownership.rs` | sahiplik, `&`, `&mut` |
| 3 | `src/steps/step03_bytes.rs` | `u8`, kaydırma, XOR, 128/256 bit = kaç byte |
| 4 | `src/steps/step04_xor.rs` | en sade şifre; AES'teki AddRoundKey'in iskeleti |
| 5 | `src/steps/step05_aes.rs` | S-box, ShiftRows, MixColumns, key schedule, AES-128/256 |

Giriş noktaları:

- `src/main.rs` — senin başlangıç pratiklerin (`cargo run`)
- `src/bin/journey.rs` — sonraki adımları seçer (`cargo run --bin journey`)
- `src/lib.rs` — modül ağacı
- `src/util.rs` — hex yaz/oku

## AES notu

`step05_aes` FIPS-197 vektörleriyle test edilir. **Öğrenme kodudur.**
Gerçek sır, parola, token saklamak için bunu kullanma; ileride `aes-gcm` gibi
denetlenmiş bir crate'e geçeceğiz.

ECB modu da sadece pratik içindir (aynı blok aynı şifreyi üretir). Sonraki
adımda CBC / CTR eklenebilir.

## Yeni adım eklemek

1. `src/steps/step06_....rs` dosyası oluştur, içinde `pub fn run()` yaz.
2. `src/steps/mod.rs` içine `pub mod step06_...;` ekle.
3. `src/bin/journey.rs` eşlemesine bir isim daha koy.
4. `cargo test` ile küçük bir test ekle.
