# ListMiner – Password Artifact Generator

`listminer.py` turns **raw password dumps / potfiles** into a full toolkit of **Hashcat-ready artifacts** in a single run:

- High-quality **Hashcat rule sets** ranked by real-world frequency  
- Cleaned **base wordlist** derived from cracked passwords  
- **Corporate-style pattern rules** (company names, cities, Wi-Fi names, etc.)  
- **Keyboard walk rules** based on observed patterns  
- **Mask candidates** with empirical frequency counts  
- **Year + season helpers** for coverage of predictable patterns  
- A **stats report** for quick target profiling  

Designed for red-teamers and password-cracking workflows where you want to squeeze as much value as possible out of recovered passwords.

---

## ✨ Features

- **Understands potfiles**  
  - Parses `hash:plaintext` lines  
  - Decodes `$HEX[...]` and `\xNN` escape sequences  
  - Handles plain wordlists as well as Hashcat / John potfiles

- **Smart affix mining**  
  - Tracks up to 6-character **prefixes** and **suffixes** across all passwords  
  - Scores longer, higher-value affixes much more heavily  
  - Builds **Hashcat rules** that prepend (`^`) and append (`$`) those affixes

- **Surround rule synthesis**  
  - Combines common prefixes/suffixes into **smart surround rules** (prefix + suffix)  
  - Limited to short, high-impact affixes for better speed/effectiveness

- **Static “killer” rules** baked in  
  - Curated 2025-style best-guess patterns (capitalization, punctuation, etc.)  
  - Year-based add-ons (full and 2-digit years, with optional `!`)

- **Multi-artifact output**  
  From one command, you get:
  - 3 rule sets (elite / extended / complete)  
  - Real-world base wordlist  
  - Corporate pattern rules  
  - Keyboard walk rules  
  - Mask candidates with counts  
  - Year/season helper rules  
  - Target stats report

- **Nice UX**  
  - Optional **tqdm** progress bar (auto-disabled if not available)  
  - Clean logging and Ctrl-C handling (graceful exit)

---

## 🔧 Requirements

### Runtime

- **Python 3.8+**
- Recommended on **Linux / macOS / WSL** (uses `/bin/bash` and standard Unix tools)

### Python packages

- Standard library only **plus** (optional):
  - `tqdm` for progress bars

Install:

```bash
pip install tqdm
```

### External tools (for `00_real_bases.txt`)

Uses typical Unix tools (cat, tr, sed, grep, sort, uniq, awk, wc).  
On Windows, run through WSL.

---

## 📂 Input Formats

Works on:
- Single file (`-f`)
- Directory of files (`-d`)

Supports:
- `.txt`, `.pot`, `.potfile`, `.lst`, `.list`, extensionless

Understands `hash:plaintext`, `$HEX[...]`, `\xNN`.

---

## 🚀 Quick Start

```bash
python3 listminer.py -f cracked.pot
python3 listminer.py -d dumps/
python3 listminer.py -d dumps/ -o outdir/
```

---

## 📦 Output Artifacts

All written to output directory:

| File | Type | Description |
|------|------|-------------|
| `00_real_bases.txt` | wordlist | Clean normalized base words |
| `01_elite.rule` | rule | Top ~15k |
| `02_extended_50k.rule` | rule | Top ~50k |
| `03_complete.rule` | rule | Full deduped rule set |
| `04_corp_patterns.rule` | rule | Company/city/SSID-based patterns |
| `05_keyboard_walks.rule` | rule | Keyboard-walk derived rules |
| `06_mask_candidates.hcmask` | mask | Top 100 masks with counts |
| `07_years_seasons.rule` | rule | Year + season rules |
| `stats.txt` | report | Summary of prefix/suffix stats |

---

## 🧪 Hashcat Examples

```bash
hashcat -m 1000 -a 0 hashes.txt 00_real_bases.txt -r 01_elite.rule
hashcat -m 1000 -a 0 hashes.txt bases.txt -r 03_complete.rule
hashcat -m 1000 -a 3 hashes.txt ?l?l?l?d?d?d
```

---

## 🔍 How It Works

1. Load potfiles / wordlists  
2. Decode plaintext  
3. Mine prefix/suffix distributions  
4. Score & generate rules  
5. Generate artifacts  
6. Produce stats

---

## ⚠️ Legal Use

For authorized security testing and research only.

