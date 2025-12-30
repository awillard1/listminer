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
* **NEW: Leet-speak mutation rules** for character substitution attacks (a→@, e→3, s→$, etc.)
* **NEW: BFS-based complex rule generation** for multi-step transformation coverage
* **NEW: Trie-based base analysis** for enhanced password pattern extraction
* Detailed progress updates with tqdm progress bars

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
                    [--no-cache] [--clear-cache]

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
| `00_unified_wordlist.txt`   | **NEW:** Merged and deduplicated wordlist from all base sources      |
| `00_real_bases.txt`         | Top base words extracted from potfiles (filtered 4+ character words) |
| `00_analyzed_bases.txt`     | Base words from comprehensive password transformation analysis       |
| `00_trie_bases.txt`         | Enhanced base words using trie-based pattern analysis                |
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

3. **Rule Generation**

   * Prepend (reversed) and append (normal) rules based on usernames
   * Prefix/suffix rules from potfile statistics
   * Surround rules combining prefixes and suffixes
   * Static and year rules for common patterns
   * **NEW:** Leet-speak mutation rules using character substitution
   * **NEW:** BFS-based complex rules for multi-step transformations
   * **NEW:** Trie-enhanced base word extraction

4. **Masks and Season/Year Rules**

   * Generates character class masks based on passwords
   * Generates year (1990–2030) and season/month rules

5. **Final Artifact Writing**

   * Writes rule files, username wordlists, masks, and statistics
   * All rules are scored and sorted by effectiveness

---

## Advanced Features

### Enhanced Leet-Speak Mutation Rules

The tool now features **comprehensive leet-speak (1337) transformation capabilities** based on common patterns found in password databases:

#### Expanded Character Mappings

* **Lowercase and Uppercase Support (ASCII-safe only):**
  * `a/A` → `@`, `4`
  * `e/E` → `3`, `&`
  * `i/I` → `1`, `!`, `|`
  * `o/O` → `0`
  * `s/S` → `$`, `5`, `z`
  * `t/T` → `7`, `+`
  * `l/L` → `1`, `|`
  * `g/G` → `9`, `6`
  * `b/B` → `8`, `6`
  * `z/Z` → `2`, `5`
  * `h/H` → `#`
  * `c/C` → `(`, `<`, `{`
  * `y/Y` → `j`
  * `x/X` → `%`
  * `p/P`, `q/Q` → `9`
  * `d/D` → `6`
  * `f/F` → `#`
  * `k/K` → `X`

#### Real-World Pattern Dictionary

Pre-defined transformations for common words with realistic leet-speak variants:
- `password` → `p@ssword`, `passw0rd`, `p@ssw0rd`, `p@55w0rd`, `pa55word`, `pa55w0rd`
- `admin` → `@dmin`, `4dmin`, `adm1n`, `@dm1n`, `4dm!n`, `@dm!n`
- `welcome` → `w3lcome`, `welc0me`, `w3lc0me`, `w3lc0m3`
- `elite` → `3lite`, `elit3`, `3lit3`, `31337`
- And many more...

#### Dynamic Multi-Character Transformations

* **Single Substitutions:** High-probability transformations (`a→@`, `e→3`, `o→0`) scored 800,000
* **Double Substitutions:** Medium-probability combinations scored 300,000-500,000
* **Triple Substitutions:** Comprehensive coverage scored 200,000

#### Rule Prioritization

Rules are assigned weights based on their real-world probability:
- Real-world pattern matches: 1,000,000
- Common single substitutions: 400,000-800,000
- Double substitutions: 300,000-500,000
- Triple substitutions: 200,000
- Hybrid transformations: Adjusted based on base score

#### Hybrid Leet Rules

Combines leet transformations with other operations:
1. **Leet + Case:** `l {leet}`, `c {leet}`, `u {leet}`
2. **Leet + Suffix:** Common suffixes appended after leet transformation
3. **Leet + Year:** Year patterns (2024, 2025, etc.) with leet
4. **Leet + Duplication:** `{leet} d` for doubled passwords

### BFS-Based Leet Exploration

Uses breadth-first search to dynamically explore leet-transform combinations:
* Combines leet substitutions with case operations (`l`, `c`, `u`, `t`)
* Adds common append/prepend operations (`$!`, `$1`, `^!`, `^1`)
* Explores duplication with leet variants
* Limits depth to maintain practical rule efficiency
* Generates 1000s of targeted transformation rules

### Unified Wordlist Generation

**NEW:** Automatically merges and deduplicates all base word sources:
- Usernames from hashfiles
- Real bases from potfiles
- Analyzed bases from transformation analysis
- Trie-based bases from pattern analysis

Output: `00_unified_wordlist.txt` with unique, sorted entries

These rules use Hashcat's `s` (substitute) command to generate variants efficiently.

### Original BFS-Based Complex Rule Generation

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
