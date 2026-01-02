# ListMiner — PasswordRuleMiner — Password Artifact Generator

**Version:** 2026 (Enhanced Edition with Advanced Rule Generation + John the Ripper Support)

## Overview

`PasswordRuleMiner` (also known as **ListMiner**) is a Python-based tool designed to generate **Hashcat and John the Ripper (JtR) rules, masks, and username-based password artifacts** from existing password datasets.

**Key Features:**

* Process single or multiple potfiles and hash files (directory recursion supported)
* **NEW: Generate rules for both Hashcat AND John the Ripper** with `--rules` option
* Generate prepend and append rules based on real usernames
* Extract robust usernames from various hash formats including DOMAIN\USER, NTLM, SHA, and Kerberos
* Generate masks and year/season rules for faster cracking
* Output statistics, base wordlists, and multiple pre-scored rule files
* **NEW: Parallel processing** for accelerated rule generation using `concurrent.futures`
* **NEW: Leet-speak mutation rules** for character substitution attacks (a→@, e→3, s→$, etc.)
* **NEW: BFS-based complex rule generation** for multi-step transformation coverage
* **NEW: Trie-based base analysis** for enhanced password pattern extraction
* **NEW: Levenshtein distance-based scoring** for optimal transformation effort calculation
* **NEW: Advanced Hashcat operations** including toggle at position (T), bitwise shifts (L/R), swaps, insertions
* **NEW: Custom wordlist integration** with optional spell-checking (`pyenchant`)
* **NEW: Statistical analysis and rule effectiveness tracking**
* **NEW: Advanced operations** - multi-character swaps, numeric sequences, combined prepend/append
* **NEW: Verbose debug mode** with detailed execution logging
* Detailed progress updates with `tqdm` progress bars and thread-safe logging

---

## Installation

Requires Python 3.8+ and optional dependencies for enhanced features.

### Basic Installation

```bash
pip install tqdm
```

### Optional: Spell-Checking Support

For enhanced wordlist generation with spell-checking:

```bash
pip install pyenchant
```

Save `listminer.py` to your working directory.

---

## Usage

### Command-line options

```text
usage: listminer.py [-h] -p POT [POT ...] [-hf [HASHFILE ...]] [-o OUTPUT] 
                    [--no-cache] [--clear-cache] [--max-workers MAX_WORKERS]
                    [-w [WORDLIST ...]] [-v] [--rules {hashcat,john,both}]

PasswordRuleMiner — Artifact Generator with Advanced Features

options:
  -h, --help            show this help message and exit
  -p POT, --pot POT     Potfile(s) or directory of potfiles (required)
  -hf HASHFILE, --hashfile HASHFILE
                        Hashfile(s) or directory of hash files
  -o OUTPUT, --output OUTPUT
                        Output directory (default: listminer)
  --no-cache            Disable caching of processed files
  --clear-cache         Clear cache and exit
  --max-workers MAX_WORKERS
                        Maximum number of parallel workers (default: min(8, CPU count))
  -w WORDLIST, --wordlist WORDLIST
                        Custom wordlist file(s) for enhanced base generation
  -v, --verbose         Enable verbose/debug mode with detailed logging
  --rules {hashcat,john,both}
                        Output rule format: 'hashcat' (default), 'john' (John the Ripper), or 'both'
```

### Caching Updates

ListMiner now includes intelligent file caching to improve efficiency during repeated executions. Caching speeds up subsequent tasks by skipping unchanged files.
---

Other features and examples remain the same as detailed in the document including new enhancements key.