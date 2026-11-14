use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::path::Path;

#[derive(Debug)]
pub struct GuardViolation {
    pub code: &'static str,
    pub detail: String,
}

/// 1. Runtime Environment Integrity Check (Mendeteksi environment hasil bypass / MITM proxy)
pub fn verify_environment() -> Result<(), Vec<GuardViolation>> {
    let mut violations = Vec::new();

    let blocked_env_vars = [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "OPENAI_BASE_URL",
        "ANTHROPIC_BASE_URL",
        "GEMINI_BASE_URL",
        "NODE_TLS_REJECT_UNAUTHORIZED",
    ];

    for key in blocked_env_vars {
        if let Ok(val) = env::var(key) {
            if !val.trim().is_empty() {
                violations.push(GuardViolation {
                    code: "ENV_TAMPER",
                    detail: format!("Variabel environment tidak standar terdeteksi: {}={}", key, val),
                });
            }
        }
    }

    // Cek modifikasi file hosts Windows yang membelokkan domain resmi AI
    let hosts_path = Path::new(r"C:\Windows\System32\drivers\etc\hosts");
    if let Ok(content) = fs::read_to_string(hosts_path) {
        let protected_domains = [
            "api.openai.com",
            "api.anthropic.com",
            "generativelanguage.googleapis.com",
        ];

        for line in content.lines() {
            let clean = line.trim();
            if clean.is_empty() || clean.starts_with('#') {
                continue;
            }
            for domain in protected_domains {
                if clean.contains(domain) {
                    violations.push(GuardViolation {
                        code: "HOSTS_REDIRECT",
                        detail: format!("Pembelokan domain API terdeteksi pada file hosts: {}", domain),
                    });
                }
            }
        }
    }

    if violations.is_empty() {
        Ok(())
    } else {
        Err(violations)
    }
}

/// 2. Menghitung SHA-256 checksum sebuah file (untuk mengunci SKILL.md / skrip agar tidak dimodifikasi)
pub fn compute_file_sha256(path: &Path) -> Result<String, String> {
    let bytes = fs::read(path).map_err(|e| format!("Gagal membaca file: {}", e))?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let result = hasher.finalize();
    Ok(format!("{:x}", result))
}

/// 3. Memverifikasi apakah file cocok dengan hash kriptografis yang sah
pub fn verify_manifest_hash(path: &Path, expected_sha256: &str) -> Result<(), GuardViolation> {
    let actual = compute_file_sha256(path).map_err(|err| GuardViolation {
        code: "FILE_MISSING",
        detail: err,
    })?;

    if actual.eq_ignore_ascii_case(expected_sha256.trim()) {
        Ok(())
    } else {
        Err(GuardViolation {
            code: "HASH_MISMATCH",
            detail: format!(
                "Integritas file gagal! File telah dimodifikasi.\n    Expected: {}\n    Actual  : {}",
                expected_sha256.trim(),
                actual
            ),
        })
    }
}