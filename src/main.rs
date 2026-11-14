mod auditor;
mod guard;

use std::env;
use std::path::Path;
use std::process;

fn print_usage() {
    println!("=== SKILL-GUARD: Zero-Trust AI Skill Auditor & Integrity Shield ===");
    println!("Penggunaan:");
    println!("  skill-guard audit <folder_skill>              -> Pindai malware, prompt injection & bypass tools");
    println!("  skill-guard hash <file>                       -> Hitung SHA-256 untuk mengunci integritas file");
    println!("  skill-guard run <file_skill> <sha256_valid>   -> Verifikasi environment & keaslian file sebelum jalan");
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_usage();
        process::exit(0);
    }

    match args[1].as_str() {
        "audit" => {
            if args.len() < 3 {
                eprintln!("[!] Masukkan path folder skill yang ingin diaudit.");
                process::exit(1);
            }
            let target = Path::new(&args[2]);
            println!("[*] Memindai direktori: {}", target.display());

            let findings = auditor::scan_directory(target);
            if findings.is_empty() {
                println!("[+] AMAN: Tidak ditemukan pola malware, prompt injection, atau bypass.");
            } else {
                println!(
                    "[!] DITEMUKAN {} POTENSI ANCAMAN / KECURANGAN:",
                    findings.len()
                );
                for f in findings {
                    println!(
                        "  - [{} | {}] {} -> {}",
                        f.severity, f.category, f.file, f.reason
                    );
                }
                process::exit(1);
            }
        }
        "hash" => {
            if args.len() < 3 {
                eprintln!("[!] Masukkan path file yang ingin di-hash.");
                process::exit(1);
            }
            let target = Path::new(&args[2]);
            match guard::compute_file_sha256(target) {
                Ok(h) => println!("SHA-256 ({}): {}", target.display(), h),
                Err(e) => {
                    eprintln!("[!] Error: {}", e);
                    process::exit(1);
                }
            }
        }
        "run" => {
            if args.len() < 4 {
                eprintln!("[!] Penggunaan: skill-guard run <file_skill> <sha256_valid>");
                process::exit(1);
            }
            println!("[*] Menjalankan Self-Defense & Environment Integrity Check...");
            if let Err(violations) = guard::verify_environment() {
                eprintln!("[X] AKSES DITOLAK (Environment Tidak Standar / Indikasi Bypass):");
                for v in violations {
                    eprintln!("    - [{}] {}", v.code, v.detail);
                }
                process::exit(1);
            }

            let target = Path::new(&args[2]);
            let expected_hash = &args[3];
            if let Err(v) = guard::verify_manifest_hash(target, expected_hash) {
                eprintln!("[X] AKSES DITOLAK ({}):\n    {}", v.code, v.detail);
                process::exit(1);
            }

            println!("[+] TERVERIFIKASI: Environment bersih & integritas file 100% asli.");
        }
        _ => print_usage(),
    }
}
