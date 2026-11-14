use std::fs;
use std::path::Path;
use walkdir::WalkDir;

#[derive(Debug)]
pub struct AuditFinding {
    pub file: String,
    pub severity: &'static str,
    pub category: &'static str,
    pub reason: String,
}

pub fn scan_directory(target_dir: &Path) -> Vec<AuditFinding> {
    let mut findings = Vec::new();

    // Pola indikator pencurian kredensial, bypass token ("pecut AI"), dan prompt injection
    let rules: &[(&str, &str, &str, &str)] = &[
        // (Pola teks, Severity, Kategori, Penjelasan)
        (
            "load_dotenv",
            "HIGH",
            "CREDENTIAL_ACCESS",
            "Membaca file .env lokal (potensi pencurian API key)",
        ),
        (
            "os.environ",
            "MEDIUM",
            "CREDENTIAL_ACCESS",
            "Mengakses seluruh environment variables sistem",
        ),
        (
            ".ssh/id_rsa",
            "CRITICAL",
            "CREDENTIAL_THEFT",
            "Mencoba mengakses private SSH key pengguna",
        ),
        (
            "Login Data",
            "CRITICAL",
            "COOKIE_HARVEST",
            "Mengakses database kredensial/cookie browser",
        ),
        (
            "Cookies",
            "HIGH",
            "COOKIE_HARVEST",
            "Indikasi ekstraksi session cookie browser",
        ),
        (
            "OPENAI_BASE_URL",
            "HIGH",
            "BYPASS_PROXY",
            "Membelokkan endpoint API ke proxy tidak resmi",
        ),
        (
            "ANTHROPIC_BASE_URL",
            "HIGH",
            "BYPASS_PROXY",
            "Membelokkan endpoint API ke proxy tidak resmi",
        ),
        (
            "X-Forwarded-For",
            "MEDIUM",
            "RATE_LIMIT_BYPASS",
            "Manipulasi header IP untuk mengakali rate limit",
        ),
        (
            "ignore previous instructions",
            "CRITICAL",
            "PROMPT_INJECTION",
            "Instruksi override system prompt terdeteksi",
        ),
        (
            "ignore all prior instructions",
            "CRITICAL",
            "PROMPT_INJECTION",
            "Instruksi override system prompt terdeteksi",
        ),
        (
            "subprocess.Popen",
            "HIGH",
            "EXECUTION_RISK",
            "Menjalankan proses shell eksternal secara diam-diam",
        ),
        (
            "eval(",
            "HIGH",
            "OBFUSCATION_RISK",
            "Eksekusi kode dinamis (sering dipakai untuk payload tersembunyi)",
        ),
    ];

    for entry in WalkDir::new(target_dir).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        // Lewati folder target/ atau .git/
        if path
            .components()
            .any(|c| c.as_os_str() == "target" || c.as_os_str() == ".git")
        {
            continue;
        }

        if let Ok(content) = fs::read_to_string(path) {
            let file_display = path.display().to_string();

            // 1. Cek karakter Unicode tak kasatmata (Zero-Width Steganography / Hidden Prompt)
            if content.contains('\u{200B}')
                || content.contains('\u{200C}')
                || content.contains('\u{200D}')
            {
                findings.push(AuditFinding {
                    file: file_display.clone(),
                    severity: "CRITICAL",
                    category: "HIDDEN_UNICODE",
                    reason: "Ditemukan karakter zero-width tak kasatmata (indikasi instruksi tersembunyi)".to_string(),
                });
            }

            // 2. Cek kecocokan aturan berbahaya & bypass
            let lower_content = content.to_lowercase();
            for &(pattern, severity, category, reason) in rules {
                if lower_content.contains(&pattern.to_lowercase()) {
                    findings.push(AuditFinding {
                        file: file_display.clone(),
                        severity,
                        category,
                        reason: format!("{} (pola: `{}`)", reason, pattern),
                    });
                }
            }
        }
    }

    findings
}
