# ListMiner — PasswordRuleMiner — Password Artifact Generator

**Version:** 2025 (Enhanced Edition)

## Overview

`PasswordRuleMiner` (also known as **ListMiner**) is a Python-based tool designed to generate **Hashcat rules, masks, and username-based password artifacts** from existing potfiles and hashfiles. It is built for red teamers, penetration testers, and security researchers who want to generate highly targeted password mutation rules and candidate wordlists.

**Key Features:**

* Process single or multiple potfiles and hash files (directory recursion supported)
* Generate Hashcat prepend and append rules based on real usernames
* Extract robust usernames from various hash formats including DOMAIN\USER, NTLM, SHA, and Kerberos
* Generate masks and year/season rules for faster cracking
* Output statistics, base wordlists, and multiple pre-scored rule files
* **NEW: Parallel processing** for accelerated rule generation using concurrent.futures
* **NEW: Leet-speak mutation rules** for character substitution attacks (a→@, e→3, s→$, etc.)
* **NEW: BFS-based complex rule generation** for multi-step transformation coverage
* **NEW: Trie-based base analysis** for enhanced password pattern extraction
* Detailed progress updates with tqdm progress bars and thread-safe logging

---

## Installation

Requires Python 3.8+ and optional `tqdm` for progress bars.

```bash
pip install tqdm
```

Save `listminer.py` to your working directory.

---

## Usage

### Command-line options

```text
usage: listminer.py [-h] -p POT [POT ...] [-hf [HASHFILE ...]] [-o OUTPUT] 
                    [--no-cache] [--clear-cache] [--max-workers MAX_WORKERS]

PasswordRuleMiner — Artifact Generator

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
```

### Caching

**NEW:** ListMiner now includes intelligent file caching to speed up processing when files haven't changed.

- **Automatic caching**: Processed potfiles and hashfiles are cached by default
- **Cache validation**: Uses file size and modification time to detect changes
- **Cache location**: Stored in `.listminer_cache/` within the output directory
- **Performance**: Significantly faster for repeated runs with unchanged files

**Cache options:**
```bash
# Normal run with caching (default)
python3 listminer.py -p potfile.pot -hf hashfile.txt -o output

# Disable caching for a single run
python3 listminer.py -p potfile.pot --no-cache -o output

# Clear all cached data
python3 listminer.py -p potfile.pot -o output --clear-cache
```

### Parallel Processing

**NEW:** ListMiner now supports parallel processing to significantly speed up rule generation tasks.

- **Automatic worker detection**: By default, uses up to 8 workers or the number of CPU cores (whichever is lower). The 8-worker cap prevents excessive thread overhead and context switching on high-core systems.
- **Configurable workers**: Use `--max-workers` to set a custom number of parallel workers
- **Environment variable**: Set `LISTMINER_MAX_WORKERS` environment variable for system-wide configuration
- **Thread-safe logging**: All parallel operations maintain clear, synchronized logging output
- **Performance boost**: Significant speedup for large password datasets

**Parallel processing examples:**
```bash
# Use default parallel workers (auto-detected)
python3 listminer.py -p potfile.pot -o output

# Use specific number of workers
python3 listminer.py -p potfile.pot -o output --max-workers 16

# Set environment variable for all runs
export LISTMINER_MAX_WORKERS=12
python3 listminer.py -p potfile.pot -o output

# Single-threaded mode (for debugging)
python3 listminer.py -p potfile.pot -o output --max-workers 1
```

**Operations that are parallelized:**
- Password transformation analysis
- Base word extraction from passwords
- Leet-speak rule generation
- Trie-based password pattern analysis

### Examples

#### Generate rules from a potfile directory:

```bash
python listminer.py -p ~/hashes/potfiles/ -o output_rules
```

#### Generate rules from a single potfile and multiple hash files:

```bash
python listminer.py -p ~/hashes/potfile.txt -hf ~/hashes/hashes1.txt ~/hashes/hashes2.txt -o output_rules
```

#### Minimal output directory (default `rules`):

```bash
python listminer.py -p ~/hashes/potfile.txt
```

---

## Output Files

All artifacts are written to the specified output directory.

| File                        | Description                                                          |
| --------------------------- | -------------------------------------------------------------------- |
| `00_real_bases.txt`         | Top base words extracted from potfiles (filtered 4+ character words) |
| `00_trie_bases.txt`         | **NEW:** Enhanced base words using trie-based pattern analysis       |
| `00_analyzed_bases.txt`     | Base words from comprehensive password transformation analysis       |
| `00_unified_passwords.txt`  | **Unified file:** All bases + usernames combined, sorted, and unique |
| `usernames.txt`             | Unique usernames parsed from hashfiles                               |
| `01_elite.rule`             | Top 15,000 pre-scored Hashcat rules (includes advanced features)     |
| `02_extended_50k.rule`      | Top 50,000 pre-scored Hashcat rules (includes advanced features)     |
| `03_complete.rule`          | Complete set of scored rules (includes all features)                 |
| `04_mask_candidates.hcmask` | Top 100 mask candidates generated from passwords                     |
| `05_years_seasons.rule`     | Year and season mutation rules                                       |
| `stats.txt`                 | Summary of total passwords, prefixes, and suffixes                   |

---

## Internal Workflow

1. **Potfile Processing**

   * Reads potfiles recursively
   * Decodes `$HEX[...]` and `\xHH` sequences
   * Builds prefix and suffix frequency counters
   * Populates trie structure for pattern analysis

2. **Hashfile Processing**

   * Parses usernames from hash files using robust regex patterns
   * Supports DOMAIN\USER, emails, NTLM, SHA, and Kerberos hashes
   * Strips domains and cleans invalid entries

3. **Rule Generation** (Parallelized)

   * Prepend (reversed) and append (normal) rules based on usernames
   * Prefix/suffix rules from potfile statistics
   * Surround rules combining prefixes and suffixes
   * Static and year rules for common patterns
   * **NEW:** Leet-speak mutation rules using character substitution (parallelized)
   * **NEW:** BFS-based complex rules for multi-step transformations
   * **NEW:** Trie-enhanced base word extraction (parallelized)
   * **NEW:** Parallel password transformation analysis for faster processing
   * Thread-safe operations ensure data integrity during parallel execution

4. **Masks and Season/Year Rules**

   * Generates character class masks based on passwords
   * Generates year (1990–2030) and season/month rules

5. **Final Artifact Writing**

   * Writes rule files, username wordlists, masks, and statistics
   * All rules are scored and sorted by effectiveness

---

## Advanced Features

### Leet-Speak Mutation Rules

The tool automatically generates leet-speak (1337) character substitution rules based on common patterns found in password databases:

* `a` → `@`, `4`
* `e` → `3`
* `i` → `1`, `!`
* `o` → `0`
* `s` → `$`, `5`
* `t` → `7`, `+`
* `l` → `1`
* `g` → `9`
* `b` → `8`

These rules use Hashcat's `s` (substitute) command to generate variants like:
- `password` → `p@ssword`, `passw0rd`, `p@ssw0rd`
- `elite` → `3lite`, `elit3`, `3lit3`

### BFS-Based Complex Rule Generation

Uses breadth-first search to explore combinations of Hashcat operations:

* Combines operations like lowercase (`l`), uppercase (`u`), capitalize (`c`), reverse (`r`), duplicate (`d`)
* Generates multi-step transformations: `l c`, `l r`, `c t`, etc.
* Creates composite rules with prepend/append operations
* Explores transformation sequences up to depth 3

### Trie-Based Base Analysis

Implements a trie (prefix tree) data structure for efficient password pattern analysis:

* Identifies common password bases by stripping numbers and special characters
* Finds frequently occurring prefixes and patterns
* Extracts high-quality base words with better accuracy than simple filtering
* Outputs enhanced base wordlist in `00_trie_bases.txt`
* **Parallelized for large datasets** to improve processing speed

### Parallel Processing Architecture

Leverages Python's `concurrent.futures` module for high-performance parallel execution:

* **ThreadPoolExecutor**: Used for I/O-bound and CPU-bound tasks with GIL-friendly operations
* **Batch processing**: Large datasets are split into batches for optimal parallel distribution
* **Thread-safe operations**: Uses locks to ensure data integrity when merging results
* **Progress tracking**: Maintains clear logging for each parallel batch with completion status
* **Adaptive worker count**: Automatically detects optimal worker count based on CPU cores
* **Error handling**: Gracefully handles exceptions in parallel workers without stopping execution

**Performance improvements:**
- Password transformation analysis: Up to 4-8x faster on multi-core systems
- Base word extraction: 3-6x speedup for large password lists
- Leet-speak rule generation: 2-4x faster with parallel batch processing
- Overall tool execution: 2-5x faster depending on dataset size and CPU cores

---

---

## Regex Patterns Used for Username Extraction

* `r'^([^:\\]+)\\([^:]+):'` — DOMAIN\USER format
* `r'^([^:]+):[0-9a-fA-F]{16,}$'` — Plain hex hashes
* `r'^([^:]+):\$[0-9A-Za-z].+'` — MD5, SHA, crypt hashes
* `r'^([^:]+):[0-9a-fA-F]{16,}:[0-9a-fA-F]{32,}:.+'` — NetNTLM v1/v2
* `r'^([^:]+):\$krb5[a-z0-9]+\$.*'` — Kerberos tickets

Kerberos lines starting with `$krb5` are skipped unless embedded in username:hash.

---

## Logging & Progress

* Progress bars are displayed if `tqdm` is installed and stdout is a terminal
* Logs include info on processed files, number of passwords, usernames, and generated rules
* Detailed progress updates for all generation phases including new advanced features

---

## Notes

* Designed to work on Linux/WSL/macOS; Windows may require `bash` for certain shell commands if you add advanced pipelines
* Fully compatible with special characters and multi-part usernames
* Username append and prepend rules are scored and optimized for Hashcat

---

**Author:** Adam Willard
**License:** MIT
**Year:** 2025
