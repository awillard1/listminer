# ListMiner — PasswordRuleMiner — Password Artifact Generator

**Version:** 2025 (Enhanced Edition with Advanced Rule Generation)

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
* **NEW: Levenshtein distance-based scoring** for optimal transformation effort calculation
* **NEW: Advanced Hashcat operations** including toggle at position (T), bitwise shifts (L/R), swaps, insertions
* **NEW: Custom wordlist integration** with optional spell-checking (pyenchant)
* **NEW: Statistical analysis and rule effectiveness tracking**
* **NEW: Advanced operations** - multi-character swaps, numeric sequences, combined prepend/append
* **NEW: Verbose debug mode** with detailed execution logging
* Detailed progress updates with tqdm progress bars and thread-safe logging

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
                    [-w [WORDLIST ...]] [-v]

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

### Custom Wordlists and Verbose Mode

**NEW:** Load external wordlists and enable detailed logging:

```bash
# Use custom wordlists for enhanced base generation
python3 listminer.py -p potfile.pot -w rockyou.txt custom_words.txt -o output

# Enable verbose/debug mode
python3 listminer.py -p potfile.pot -v -o output

# Combine custom wordlists with verbose mode
python3 listminer.py -p potfile.pot -w wordlist.txt -v --max-workers 16 -o output
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

| File                               | Description                                                                |
| ---------------------------------- | -------------------------------------------------------------------------- |
| `00_real_bases.txt`                | Top base words extracted from potfiles (filtered 4+ character words)       |
| `00_analyzed_bases.txt`            | **NEW:** Base words identified through transformation analysis             |
| `00_trie_bases.txt`                | **NEW:** Enhanced base words using trie-based pattern analysis             |
| `00_spell_checked_bases.txt`       | **NEW:** Spell-checked suggestions (if pyenchant available)                |
| `usernames.txt`                    | Unique usernames parsed from hashfiles                                     |
| `01_elite.rule`                    | Top 15,000 pre-scored Hashcat rules (includes advanced features)           |
| `02_extended_50k.rule`             | Top 50,000 pre-scored Hashcat rules (includes advanced features)           |
| `03_complete.rule`                 | Complete set of scored rules (includes all features)                       |
| `04_mask_candidates.hcmask`        | Top 100 mask candidates generated from passwords                           |
| `05_years_seasons.rule`            | Year and season mutation rules                                             |
| `stats.txt`                        | Summary of total passwords, prefixes, and suffixes                         |
| `rule_effectiveness_stats.txt`     | **NEW:** Statistical analysis of rule effectiveness with Levenshtein scores|

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

3. **Rule Generation** (Parallelized with Advanced Features)

   * Prepend (reversed) and append (normal) rules based on usernames
   * Prefix/suffix rules from potfile statistics
   * Surround rules combining prefixes and suffixes
   * Static and year rules for common patterns
   * **NEW:** Leet-speak mutation rules using character substitution (parallelized)
   * **NEW:** BFS-based complex rules for multi-step transformations with advanced operations
   * **NEW:** Trie-enhanced base word extraction (parallelized)
   * **NEW:** Parallel password transformation analysis with Levenshtein distance scoring
   * **NEW:** Advanced Hashcat operations: toggle at position (T), bitwise shifts (L/R), swaps (*), insertions (i)
   * **NEW:** Multi-character swap rules, numeric sequence manipulation
   * **NEW:** Combined prepend/append rules with case transformations
   * **NEW:** Custom wordlist integration and spell-checking (if available)
   * Thread-safe operations ensure data integrity during parallel execution

4. **Masks and Season/Year Rules**

   * Generates character class masks based on passwords
   * Generates year (1990–2030) and season/month rules

5. **Final Artifact Writing**

   * Writes rule files, username wordlists, masks, and statistics
   * All rules are scored and sorted by effectiveness

---

## Advanced Features

### Levenshtein Distance-Based Scoring

**NEW:** The tool uses Levenshtein distance to calculate the transformation effort between password candidates:

* Measures the minimum number of single-character edits required to transform one string to another
* Scores transformations based on their complexity (lower distance = simpler transformation)
* Helps identify the most impactful and efficient password rules
* Used in rule effectiveness tracking and statistical analysis

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

### Advanced Hashcat Rule Generation

**NEW:** Support for advanced Hashcat transformations:

* **Toggle case at position** (`TN`): Toggle case of character at position N
* **Bitwise shift left** (`L`): Shift all characters left by one bit
* **Bitwise shift right** (`R`): Shift all characters right by one bit
* **Swap characters** (`*NM`): Swap characters at positions N and M
* **Insert at position** (`iNX`): Insert character X at position N
* **Overwrite at position** (`oNX`): Overwrite character at position N with X
* **Delete at position** (`DN`): Delete character at position N
* **Extract range** (`xNM`): Extract substring from position N with length M
* **Purge character** (`@X`): Remove all instances of character X

### BFS-Based Complex Rule Generation

Uses breadth-first search to explore combinations of Hashcat operations:

* Combines operations like lowercase (`l`), uppercase (`u`), capitalize (`c`), reverse (`r`), duplicate (`d`)
* **NEW:** Includes advanced operations: bitwise shifts (`L`, `R`), rotations (`{`, `}`), swaps
* Generates multi-step transformations: `l c`, `l r`, `c t`, etc.
* Creates composite rules with prepend/append operations
* **NEW:** Rotation and swap combination rules for interesting password variants
* Explores transformation sequences up to depth 3

### Multi-Character Swaps and Numeric Sequences

**NEW:** Advanced operations for comprehensive password coverage:

* **Multi-character swaps**: Swap characters at common positions (0,1), (0,2), (1,2), etc.
* **Numeric sequence manipulation**: Common number patterns (123, 321, 456, etc.)
* **Combined prepend/append**: Intelligent combination of prefixes, suffixes, and case transformations
* Optimized for real-world password patterns

### Custom Wordlist Integration

**NEW:** Load external wordlists for enhanced base generation:

* Supports multiple wordlist files via `-w` / `--wordlist` option
* Filters and validates words (3-20 characters, alphabetic)
* Generates prepend/append rules from custom word bases
* Integrates seamlessly with existing rule generation pipeline

### Spell-Checking Library Integration

**NEW:** Optional spell-checking support using `pyenchant`:

* Automatically detects and corrects common misspellings in password bases
* Generates suggestions for non-dictionary words found in passwords
* Outputs spell-checked suggestions to `00_spell_checked_bases.txt`
* Helps identify word-based password patterns
* Install with: `pip install pyenchant`

### Statistical Analysis and Rule Pruning

**NEW:** Track and analyze rule effectiveness:

* **RuleEffectivenessTracker**: Records transformation statistics for each rule
* Calculates average Levenshtein distance per rule
* Identifies most effective rules based on usage frequency and transformation simplicity
* Generates detailed statistics report in `rule_effectiveness_stats.txt`
* Shows top 20 most effective rules with metrics

### Trie-Based Base Analysis

Implements a trie (prefix tree) data structure for efficient password pattern analysis:

* Identifies common password bases by stripping numbers and special characters
* Finds frequently occurring prefixes and patterns
* Extracts high-quality base words with better accuracy than simple filtering
* Outputs enhanced base wordlist in `00_trie_bases.txt`
* **Parallelized for large datasets** to improve processing speed

### Verbose Debug Mode

**NEW:** Enhanced logging with `-v` / `--verbose` flag:

* Detailed execution logging for troubleshooting
* Debug-level messages for spell-checking, word processing, and rule generation
* Progress tracking for each processing stage
* Thread-safe logging in parallel operations
* Helps identify performance bottlenecks and processing issues

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