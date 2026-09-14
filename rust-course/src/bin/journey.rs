//! Sonraki adımlar (ownership → AES). Başlangıç pratikleri `src/main.rs` içinde.
//!
//! ```text
//! cargo run                         # senin main.rs pratiklerin
//! cargo run --bin journey           # adım 2-5
//! cargo run --bin journey -- xor
//! cargo run --bin journey -- aes
//! ```

use rust_course::steps;

fn main() {
    println!("=== Rust Course Journey: Zero to Hero ===\n");

    let step = std::env::args().nth(1);
    match step.as_deref() {
        None => steps::run_all(),
        Some("1") | Some("basics") => {
            println!("Temel pratikler senin src/main.rs dosyanda.");
            println!("Calistir: cargo run");
        }
        Some("2") | Some("ownership") => steps::step02_ownership::run(),
        Some("3") | Some("bytes") => steps::step03_bytes::run(),
        Some("4") | Some("xor") => steps::step04_xor::run(),
        Some("5") | Some("aes") => steps::step05_aes::run(),
        Some(other) => {
            eprintln!("Bilinmeyen adim: {other}");
            eprintln!(
                "Kullanim: cargo run --bin journey -- [2|3|4|5|ownership|bytes|xor|aes]"
            );
        }
    }
}
