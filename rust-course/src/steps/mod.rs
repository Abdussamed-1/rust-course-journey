//! Öğrenme adımları — soldan sağa, basitten karmaşığa.
//!
//! Adım 1 senin `src/main.rs` dosyan (başlangıç pratikleri).
//! Buradaki modüller onun üstüne biner:
//!
//! 2. `step02_ownership`  — sahiplik, borçlanma
//! 3. `step03_bytes`      — u8, bit işlemleri, 128/256 bit ne demek
//! 4. `step04_xor`        — en sade "şifre": XOR
//! 5. `step05_aes`        — AES-128 ve AES-256, kütüphanesiz, elle

pub mod step02_ownership;
pub mod step03_bytes;
pub mod step04_xor;
pub mod step05_aes;

pub fn run_all() {
    println!("(Adim 1: cargo run  —  src/main.rs)\n");
    step02_ownership::run();
    step03_bytes::run();
    step04_xor::run();
    step05_aes::run();
}
