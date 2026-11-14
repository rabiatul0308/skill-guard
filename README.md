# skill-guard

CLI utility written in Rust to audit third-party AI skills and scripts before execution, and lock their integrity at runtime. Compiled as a standalone ~182 KB binary with zero external dependencies.

## What it does

- **`audit`**: Scans directories for `.env`/SSH key reads, browser cookie access, `eval()` obfuscation, prompt-injection patterns, and invisible zero-width Unicode characters (`U+200B`/`U+200C`/`U+200D`). Decodes both UTF-8 and UTF-16 LE/BE (BOM) files to catch encoding-evasion tricks.
- **`hash`**: Outputs the SHA-256 digest of a verified skill file.
- **`run`**: Checks that the target file still matches its expected SHA-256 hash and blocks execution if proxy/endpoint override variables (`OPENAI_BASE_URL`, `ANTHROPIC_BASE_URL`, etc.) are active in the environment.

## Install

Grab `skill-guard.exe` from the [Releases](https://github.com/rabiatul0308/skill-guard/releases) page, or build it yourself:

```bash
git clone [https://github.com/rabiatul0308/skill-guard.git](https://github.com/rabiatul0308/skill-guard.git)
cd skill-guard
cargo build --release
