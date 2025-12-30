#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PasswordRuleMiner — Password Artifact Generator

Features:
- Single or multiple potfiles (directory recursion)
- Single or multiple hash files (directory recursion)
- Generates Hashcat prepend/append rules, masks, and year/season rules
- Fully compatible with complex usernames and special characters
- Robust logging for every processed file and generation step
"""
import argparse
import hashlib
import logging
import pickle
import re
import signal
import sys
from collections import Counter, defaultdict, deque
from datetime import datetime
from pathlib import Path
from typing import List, Iterable, Dict, Set, Tuple, Optional

# =============================================
# PROGRESS BAR
# =============================================
try:
    from tqdm import tqdm as _tqdm
    TQDM = True
except ImportError:
    TQDM = False

def progress(it, **kw):
    return _tqdm(it, **kw) if TQDM and sys.stdout.isatty() else it

# =============================================
# Logging
# =============================================
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger(__name__)

def sigint_handler(signum, frame):
    log.warning("\nInterrupted by user — exiting cleanly")
    sys.exit(0)
signal.signal(signal.SIGINT, sigint_handler)

# =============================================
# FILE CACHE
# =============================================
class FileCache:
    """
    Caching system for processed potfiles and hashfiles.
    Uses file modification time and size for cache validation.
    """
    
    def __init__(self, cache_dir: Path):
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.enabled = True
    
    def _get_file_key(self, filepath: Path) -> str:
        """Generate a unique cache key for a file"""
        stat = filepath.stat()
        # Use path, size, and mtime for cache key
        key_str = f"{filepath.resolve()}:{stat.st_size}:{stat.st_mtime}"
        return hashlib.md5(key_str.encode()).hexdigest()
    
    def _get_cache_path(self, filepath: Path, cache_type: str) -> Path:
        """Get the cache file path for a given file"""
        key = self._get_file_key(filepath)
        return self.cache_dir / f"{cache_type}_{key}.pkl"
    
    def get(self, filepath: Path, cache_type: str) -> Optional[any]:
        """Retrieve cached data for a file if valid"""
        if not self.enabled:
            return None
        
        cache_path = self._get_cache_path(filepath, cache_type)
        if not cache_path.exists():
            return None
        
        try:
            with cache_path.open('rb') as f:
                cached_data = pickle.load(f)
            log.info(f"  → Using cached data for {filepath.name}")
            return cached_data
        except (pickle.PickleError, EOFError, FileNotFoundError):
            # Cache corrupted or invalid
            cache_path.unlink(missing_ok=True)
            return None
    
    def set(self, filepath: Path, cache_type: str, data: any):
        """Store data in cache for a file"""
        if not self.enabled:
            return
        
        cache_path = self._get_cache_path(filepath, cache_type)
        try:
            with cache_path.open('wb') as f:
                pickle.dump(data, f)
        except (pickle.PickleError, OSError) as e:
            log.warning(f"Failed to cache {filepath.name}: {e}")
    
    def clear(self):
        """Clear all cache files"""
        for cache_file in self.cache_dir.glob("*.pkl"):
            cache_file.unlink(missing_ok=True)
        log.info("Cache cleared")

# =============================================
# Password decoding
# =============================================
HEX_BRACKET_RE = re.compile(r'\$HEX\[[0-9a-fA-F]+\]')
HEX_ESCAPE_RE = re.compile(r'\\x[0-9a-fA-F]{2}')

def decode_plaintext(text: str) -> str:
    r"""Decode $HEX[...] and \xHH sequences"""
    if not text:
        return ""
    if text.startswith("$HEX[") and text.endswith("]"):
        try:
            return bytes.fromhex(text[5:-1]).decode("latin-1")
        except ValueError:
            return ""
    return HEX_ESCAPE_RE.sub(lambda m: chr(int(m.group(0)[2:], 16)), text)

def extract_password_from_pot(line: str) -> str:
    line = line.strip()
    if not line or line.startswith("#"):
        return ""
    return decode_plaintext(line.rsplit(":", 1)[-1])

def extract_password_from_wordlist(line: str) -> str:
    return decode_plaintext(line.strip())

# =============================================
# Hashcat Rule Helpers
# =============================================
def is_ascii_safe(text: str) -> bool:
    """Check if text contains only ASCII characters (safe for Hashcat rules)"""
    return all(ord(c) < 128 for c in text)

def hashcat_prepend(word: str, reverse: bool = True) -> str:
    """Generate Hashcat prepend rule (^ per char), optionally reversed"""
    if not is_ascii_safe(word):
        return None
    if reverse:
        word = word[::-1]
    return " ".join(f"^{c}" for c in word)

def hashcat_append(word: str) -> str:
    """Generate Hashcat append rule ($ per char)"""
    if not is_ascii_safe(word):
        return None
    return " ".join(f"${c}" for c in word)

# =============================================
# ADVANCED FEATURES: LEET MAPPING
# =============================================
LEET_MAP = {
    'a': ['@', '4'],
    'e': ['3'],
    'i': ['1', '!'],
    'o': ['0'],
    's': ['$', '5'],
    't': ['7', '+'],
    'l': ['1'],
    'g': ['9'],
    'b': ['8'],
}

def generate_leet_rules(word: str, max_substitutions: int = 2) -> List[str]:
    """
    Generate leet-speak Hashcat substitution rules for a word.
    Uses 's' command for character substitution.
    """
    rules = []
    word_lower = word.lower()
    positions = [(i, c) for i, c in enumerate(word_lower) if c in LEET_MAP]
    
    if not positions:
        return rules
    
    # Single substitutions
    for _, char in positions:
        for leet_char in LEET_MAP[char]:
            rule = f"s{char}{leet_char}"
            rules.append(rule)
    
    # Double substitutions (if enough positions)
    if len(positions) >= 2 and max_substitutions >= 2:
        for i in range(len(positions)):
            for j in range(i + 1, min(i + 4, len(positions))):
                _, char1 = positions[i]
                _, char2 = positions[j]
                for leet1 in LEET_MAP[char1]:
                    for leet2 in LEET_MAP[char2]:
                        rule = f"s{char1}{leet1} s{char2}{leet2}"
                        rules.append(rule)
    
    return rules

# =============================================
# ADVANCED FEATURES: BFS RULE GENERATION
# =============================================
class BFSRuleGenerator:
    """
    Generate complex Hashcat rules using BFS exploration.
    Combines multiple operations in sequence for comprehensive coverage.
    """
    
    # Basic Hashcat operations
    OPERATIONS = [
        ('l', 'lowercase'),
        ('u', 'uppercase'),
        ('c', 'capitalize'),
        ('C', 'invert capitalize'),
        ('t', 'toggle case'),
        ('r', 'reverse'),
        ('d', 'duplicate'),
        ('{', 'rotate left'),
        ('}', 'rotate right'),
    ]
    
    def __init__(self, max_depth: int = 3):
        self.max_depth = max_depth
        self.rules: Set[str] = set()
    
    def generate(self, base_ops: Optional[List[str]] = None) -> List[Tuple[int, str]]:
        """
        Generate rules using BFS with scoring.
        Returns list of (score, rule) tuples.
        """
        if base_ops is None:
            base_ops = [op[0] for op in self.OPERATIONS[:6]]  # First 6 ops
        
        scored_rules = []
        queue = deque([("", 0)])  # (rule, depth)
        seen = {""}
        
        while queue:
            current_rule, depth = queue.popleft()
            
            if depth > 0:
                # Score based on complexity and depth
                score = 500_000 // (depth + 1)
                scored_rules.append((score, current_rule.strip()))
            
            if depth >= self.max_depth:
                continue
            
            # Expand with each operation
            for op in base_ops:
                new_rule = f"{current_rule} {op}".strip() if current_rule else op
                if new_rule not in seen:
                    seen.add(new_rule)
                    queue.append((new_rule, depth + 1))
        
        return scored_rules
    
    def generate_append_prepend_combos(self, common_strings: List[str], limit: int = 100) -> List[Tuple[int, str]]:
        """
        Generate BFS-style combinations of prepend and append operations.
        """
        scored_rules = []
        
        for s in common_strings[:limit]:
            if len(s) < 1 or len(s) > 4:
                continue
            
            # Prepend only
            prep = hashcat_prepend(s)
            if not prep:
                continue
            scored_rules.append((300_000, prep))
            
            # Append only
            app = hashcat_append(s)
            if not app:
                continue
            scored_rules.append((300_000, app))
            
            # Prepend + append same
            scored_rules.append((250_000, f"{prep} {app}"))
            
            # With case operations
            scored_rules.append((280_000, f"l {app}"))
            scored_rules.append((275_000, f"c {app}"))
            scored_rules.append((270_000, f"l {prep}"))
            scored_rules.append((265_000, f"c {prep}"))
        
        return scored_rules

# =============================================
# ADVANCED FEATURES: TRIE-BASED BASE ANALYSIS
# =============================================
class TrieNode:
    """Node for Trie data structure"""
    def __init__(self):
        self.children: Dict[str, 'TrieNode'] = {}
        self.is_end = False
        self.frequency = 0
        self.word = ""

class PasswordTrie:
    """
    Trie-based structure for efficient password pattern analysis.
    Helps identify common base words and patterns in passwords.
    """
    
    def __init__(self):
        self.root = TrieNode()
        self.total_words = 0
    
    def insert(self, word: str, frequency: int = 1):
        """Insert a word into the trie with its frequency"""
        if not word:
            return
        
        node = self.root
        for char in word:
            if char not in node.children:
                node.children[char] = TrieNode()
            node = node.children[char]
        
        node.is_end = True
        node.frequency += frequency
        node.word = word
        self.total_words += frequency
    
    def find_common_prefixes(self, min_length: int = 3, min_freq: int = 5) -> List[Tuple[str, int]]:
        """Find common prefixes that appear frequently"""
        prefixes = []
        
        def dfs(node: TrieNode, prefix: str):
            # Check children count (branching factor)
            if len(prefix) >= min_length:
                child_freq = sum(self._count_words(child) for child in node.children.values())
                if child_freq >= min_freq:
                    prefixes.append((prefix, child_freq))
            
            for char, child in node.children.items():
                dfs(child, prefix + char)
        
        dfs(self.root, "")
        return sorted(prefixes, key=lambda x: x[1], reverse=True)
    
    def _count_words(self, node: TrieNode) -> int:
        """Count total words under a node"""
        count = node.frequency if node.is_end else 0
        for child in node.children.values():
            count += self._count_words(child)
        return count
    
    def get_all_words(self, min_freq: int = 1) -> List[Tuple[str, int]]:
        """Get all complete words from trie with their frequencies"""
        words = []
        
        def dfs(node: TrieNode):
            if node.is_end and node.frequency >= min_freq:
                words.append((node.word, node.frequency))
            
            for child in node.children.values():
                dfs(child)
        
        dfs(self.root)
        return sorted(words, key=lambda x: x[1], reverse=True)
    
    def extract_base_words(self, passwords: List[str]) -> List[Tuple[str, int]]:
        """
        Extract and analyze base words from passwords.
        Strips common patterns and returns high-quality bases.
        """
        word_counter = Counter()
        
        for pwd in passwords:
            # Clean the password - remove numbers, special chars at ends
            cleaned = re.sub(r'^[^a-zA-Z]+', '', pwd)
            cleaned = re.sub(r'[^a-zA-Z]+$', '', cleaned)
            cleaned = re.sub(r'\d{2,}', '', cleaned)  # Remove number sequences
            
            # Extract alpha sequences
            alpha_parts = re.findall(r'[a-zA-Z]{3,}', cleaned)
            for part in alpha_parts:
                part_lower = part.lower()
                if 3 <= len(part_lower) <= 15:
                    word_counter[part_lower] += 1
                    self.insert(part_lower, 1)
        
        return word_counter.most_common()

# =============================================
# MAIN CLASS — PASSWORD RULE MINER
# =============================================
class PasswordRuleMiner:
    def __init__(self, output_dir: Path, use_cache: bool = True):
        self.out = output_dir
        self.out.mkdir(parents=True, exist_ok=True)
        self.scored_rules = []
        self.passwords: List[str] = []
        self.prefix = Counter()
        self.suffix = Counter()
        self.usernames: Dict[str, List[str]] = defaultdict(list)
        
        # Advanced features
        self.trie = PasswordTrie()
        self.bfs_generator = BFSRuleGenerator(max_depth=3)
        
        # Caching
        cache_dir = self.out / ".listminer_cache"
        self.cache = FileCache(cache_dir)
        self.cache.enabled = use_cache

        # ======= Fix: Compile the USER_PATTERNS =======
        self.COMPILED_USER_RE = [re.compile(p) for p in self.USER_PATTERNS]

        # Email cleanup regex
        self.EMAIL_RE = re.compile(r'^([^@]+)@.+$')

    # -------------------------------
    # File parsing
    # -------------------------------
    def mine_potfiles(self, files: Iterable[Path]):
        total = 0
        log.info("Phase 1/3: Mining potfiles...")
        for f in files:
            fpath = f.expanduser().resolve()
            if fpath.is_dir():
                for subfile in progress(list(fpath.rglob("*")), desc=f"{fpath.name} (dir)", leave=False):
                    if subfile.is_file() and subfile.stat().st_size > 0:
                        log.info(f"Reading potfile: {subfile}")
                        total += self._parse_potfile(subfile)
            elif fpath.is_file():
                log.info(f"Reading potfile: {fpath}")
                total += self._parse_potfile(fpath)
        log.info(f"Collected {total:,} plaintext passwords from potfiles.")

        # Build prefix/suffix counters
        for pwd in self.passwords:
            n = min(6, len(pwd))
            for i in range(1, n + 1):
                self.prefix[pwd[:i]] += 1
                self.suffix[pwd[-i:]] += 1

    def _parse_potfile(self, path: Path) -> int:
        # Check cache first
        cached_data = self.cache.get(path, "potfile")
        if cached_data is not None:
            passwords, count = cached_data
            self.passwords.extend(passwords)
            return count
        
        # Parse file
        count = 0
        passwords = []
        with path.open("r", encoding="utf-8", errors="ignore") as f:
            for line in progress(f, desc=path.stem[:30], leave=False):
                pwd = extract_password_from_pot(line)
                if pwd and len(pwd) >= 1:
                    passwords.append(pwd)
                    count += 1
        
        # Store in cache
        self.cache.set(path, "potfile", (passwords, count))
        self.passwords.extend(passwords)
        return count

    def mine_hashfiles(self, files: Iterable[Path]):
        total = 0
        log.info("Phase 1b: Mining hash files for usernames...")
        for f in files:
            fpath = Path(f).expanduser().resolve()
            if fpath.is_dir():
                for subfile in progress(list(fpath.rglob("*")), desc=f"{fpath.name} (dir)", leave=False):
                    if subfile.is_file() and subfile.stat().st_size > 0:
                        log.info(f"Reading hashfile: {subfile}")
                        total += self._parse_hashfile(subfile)
            elif fpath.is_file():
                log.info(f"Reading hashfile: {fpath}")
                total += self._parse_hashfile(fpath)
        log.info(f"Collected {total:,} usernames from hash files.")

    # =============================================
    # USERNAME EXTRACTION (robust)
    # =============================================
    USER_PATTERNS = [
        # DOMAIN\username:hash → capture username (group 2)
        r'^([^:\\]+)\\([^:]+):',

        # username:NTLM/SHA1/SHA256/... hash (hex only)
        r'^([^:]+):[0-9a-fA-F]{16,}$',

        # username:$id$hash (e.g., MD5, SHA512, crypt hashes)
        r'^([^:]+):\$[0-9A-Za-z].+',

        # username:NetNTLMv1/v2 → 16+ hex + 32+ hex + extra
        r'^([^:]+):[0-9a-fA-F]{16,}:[0-9a-fA-F]{32,}:.+',

        # username:Kerberos AS-REP or TGS tickets
        r'^([^:]+):\$krb5[a-z0-9]+\$.*',
    ]

    # Kerberos ticket that starts with $krb5 → skip (service ticket / garbage)
    KERB_SKIP_RE = re.compile(r'^\$krb5', re.IGNORECASE)

    # Kerberos inside user:hash → allowed
    KERB_USER_RE = re.compile(r':\$krb5', re.IGNORECASE)

    # =============================================
    # File parsing — updated _parse_hashfile
    # =============================================
    def _parse_hashfile(self, path: Path) -> int:
        # Check cache first
        cached_data = self.cache.get(path, "hashfile")
        if cached_data is not None:
            usernames_dict, count = cached_data
            for username in usernames_dict:
                self.usernames[username].append("")
            return count
        
        # Parse file
        count = 0
        usernames_dict = {}
        with path.open("r", encoding="utf-8", errors="ignore") as f:
            for line in progress(f, desc=path.stem[:30], leave=False):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                # If line STARTS with $krb5 → no username → skip
                if self.KERB_SKIP_RE.match(line):
                    continue

                username = None

                # Apply extraction patterns
                for pat in self.COMPILED_USER_RE:
                    m = pat.match(line)
                    if m:
                        # DOMAIN\Alice → real username is group 2
                        if len(m.groups()) > 1:
                            username = m.group(2)
                        else:
                            username = m.group(1)
                        break

                if not username:
                    continue

                # Clean email → user@domain.com → user
                mail = self.EMAIL_RE.match(username)
                if mail:
                    username = mail.group(1)

                username = username.strip().lower()

                # Reject invalid usernames (SPNs, host$, paths, junk)
                if (not username
                    or "/" in username
                    or "," in username
                    or username.startswith("$")
                    or username.endswith("$")):
                    continue

                # Store the username
                usernames_dict[username] = True
                self.usernames[username].append("")
                count += 1
        
        # Store in cache
        self.cache.set(path, "hashfile", (usernames_dict, count))
        return count

    # -------------------------------
    # Rule generation
    # -------------------------------
    def generate_user_context_rules(self):
        log.info("Generating per-username context rules...")
        context_count = 0

        for username in self.usernames:
            # Split DOMAIN\USER or email-style usernames
            parts = re.split(r'[\.\-\_\s@\\]+', username)
            for part in parts:
                if len(part) < 3:
                    continue
                
                # Skip non-ASCII usernames
                if not is_ascii_safe(part):
                    continue
                    
                low = part.lower()
                cap = part.capitalize()

                # Prepend username (reversed)
                prep_low = hashcat_prepend(low)
                prep_cap = hashcat_prepend(cap)
                app_low = hashcat_append(low)
                app_cap = hashcat_append(cap)
                
                if prep_low:
                    self.scored_rules.append((10_000_000, prep_low))
                if prep_cap:
                    self.scored_rules.append((9_900_000, prep_cap))
                if app_low:
                    self.scored_rules.append((9_900_000, app_low))
                if app_cap:
                    self.scored_rules.append((9_800_000, app_cap))

                context_count += 1

        log.info(f"Injected {context_count:,} per-user context rules")
        
    def generate_real_bases(self, top_n: int = 2_000_000):
        log.info("Generating 00_real_bases.txt (base words from potfile passwords)...")

        counter = Counter()
        for pwd in self.passwords:
            pwd = pwd.lower()
            # Remove years, special chars, trailing numbers
            pwd = re.sub(r'(202[0-9]|19[0-9]{2}|[!@#$%^&*]+|[0-9]{3,}$)', '', pwd, flags=re.I)
            if re.fullmatch(r'[a-z]{4,}', pwd):
                counter[pwd] += 1

        # Keep top_n most common
        top_bases = [word for word, _ in counter.most_common(top_n)]

        out_file = self.out / "00_real_bases.txt"
        out_file.write_text("\n".join(top_bases) + "\n", encoding="utf-8")
        log.info(f" → 00_real_bases.txt ({len(top_bases):,} bases)")
    
    def generate_prefix_suffix_rules(self):
        log.info("Generating prefix/suffix rules from potfile passwords...")
        for prefix, count in self.prefix.most_common(2000):
            if len(prefix) >= 2 and is_ascii_safe(prefix):
                rule = hashcat_prepend(prefix)
                if rule:
                    score = int(count * (len(prefix) ** 3.6) * 38)
                    self.scored_rules.append((score, rule))
        for suffix, count in self.suffix.most_common(1600):
            if len(suffix) >= 2 and is_ascii_safe(suffix):
                rule = hashcat_append(suffix)
                if rule:
                    score = int(count * (len(suffix) ** 3.3) * 32)
                    self.scored_rules.append((score, rule))

    def generate_surround_rules(self):
        log.info("Generating surround rules...")
        seen = set()
        for prefix, pc in self.prefix.most_common(500):
            if not 2 <= len(prefix) <= 5 or not is_ascii_safe(prefix):
                continue
            pre = hashcat_prepend(prefix)
            if not pre:
                continue
            for suffix, sc in self.suffix.most_common(500):
                if not 2 <= len(suffix) <= 5 or not is_ascii_safe(suffix):
                    continue
                app = hashcat_append(suffix)
                if not app:
                    continue
                rule = f"{pre} {app}".strip()
                if rule not in seen:
                    seen.add(rule)
                    self.scored_rules.append((int((pc + sc) * 18), rule))

    def generate_static_and_year_rules(self):
        log.info("Generating static and year rules...")
        static_rules = [
            "l c $2 $0 $2 $4 $!", "l c $2 $0 $2 $5", "l c $1 $2 $3 $!",
            "l c $!", "l $!", "c $!", "$! $!", "$2 $0 $2 $4", "$2 $0 $2 $5"
        ]
        for r in static_rules:
            self.scored_rules.append((999_999, r))
        for year in range(2018, 2031):
            for y in [str(year), str(year)[-2:]]:
                app = hashcat_append(y)
                self.scored_rules.extend([
                    (920_000, f"l{app}"),
                    (910_000, f"l c{app}"),
                    (900_000, f"l{app} $!"),
                    (895_000, f"l c{app} $!"),
                ])
    
    def generate_leet_rules(self):
        """Generate leet-speak mutation rules"""
        log.info("Generating leet-speak mutation rules...")
        
        # Get top base words from passwords
        base_words = []
        word_counter = Counter()
        for pwd in progress(self.passwords, desc="Analyzing for leet", leave=False):
            # Extract alphabetic base
            cleaned = re.sub(r'[^a-zA-Z]', '', pwd.lower())
            if 4 <= len(cleaned) <= 12:
                word_counter[cleaned] += 1
        
        # Get top 500 words for leet generation
        top_words = [word for word, _ in word_counter.most_common(500)]
        
        leet_count = 0
        for word in progress(top_words, desc="Generating leet rules", leave=False):
            leet_variants = generate_leet_rules(word, max_substitutions=2)
            for rule in leet_variants:
                # Score based on word frequency and rule complexity
                freq = word_counter[word]
                score = int(freq * 5000)
                self.scored_rules.append((score, rule))
                leet_count += 1
        
        log.info(f"Generated {leet_count:,} leet-speak mutation rules")
    
    def generate_bfs_complex_rules(self):
        """Generate complex rules using BFS exploration"""
        log.info("Generating BFS-based complex rules...")
        
        # Generate basic BFS rules
        bfs_rules = self.bfs_generator.generate()
        self.scored_rules.extend(bfs_rules)
        log.info(f"Generated {len(bfs_rules):,} BFS exploration rules")
        
        # Generate BFS combinations with common strings (ASCII only)
        common_strings = [s for s, _ in self.suffix.most_common(50) if is_ascii_safe(s)]
        common_strings.extend([p for p, _ in self.prefix.most_common(50) if is_ascii_safe(p)])
        
        combo_rules = self.bfs_generator.generate_append_prepend_combos(common_strings, limit=50)
        self.scored_rules.extend(combo_rules)
        log.info(f"Generated {len(combo_rules):,} BFS combination rules")
    
    def generate_trie_based_bases(self):
        """Generate enhanced base wordlist using trie analysis"""
        log.info("Generating trie-based base word analysis...")
        
        # Extract base words using trie
        trie_bases = self.trie.extract_base_words(self.passwords)
        
        # Get high-quality words
        quality_bases = []
        for word, freq in trie_bases:
            if freq >= 2 and 4 <= len(word) <= 15:
                quality_bases.append((word, freq))
        
        # Also find common prefixes for pattern analysis
        common_prefixes = self.trie.find_common_prefixes(min_length=3, min_freq=10)
        
        log.info(f"Trie analysis found {len(quality_bases):,} quality base words")
        log.info(f"Identified {len(common_prefixes):,} common prefixes")
        
        # Write enhanced base file
        out_file = self.out / "00_trie_bases.txt"
        bases_text = "\n".join([word for word, _ in quality_bases[:5_000_000]])
        out_file.write_text(bases_text + "\n", encoding="utf-8")
        log.info(f" → 00_trie_bases.txt ({len(quality_bases[:5_000_000]):,} bases)")
        
        return quality_bases, common_prefixes
    def write_username_wordlist(self):
        """
        Write a wordlist of unique usernames to a file.
        """
        out_file = self.out / "usernames.txt"
        # Take all keys from self.usernames, sorted
        usernames = sorted(self.usernames.keys())
        out_file.write_text("\n".join(usernames) + "\n", encoding="utf-8")
        log.info(f" → {out_file.name} ({len(usernames):,} unique usernames)")
    
    def write_rules(self):
        log.info("Writing rule files...")
        self.scored_rules.sort(key=lambda x: x[0], reverse=True)
        seen = set()
        unique_rules = [r for _, r in self.scored_rules if r not in seen and not seen.add(r)]

        def write_file(path, data):
            path.write_text("\n".join(data) + "\n", encoding="utf-8")
            log.info(f" → {path.name} ({len(data):,} lines)")

        write_file(self.out / "01_elite.rule", unique_rules[:15_000])
        write_file(self.out / "02_extended_50k.rule", unique_rules[:50_000])
        write_file(self.out / "03_complete.rule", unique_rules)

    def generate_masks_and_years(self):
        log.info("Generating masks and year/season rules...")
        # Mask candidates
        mask_counter = Counter()
        for pwd in self.passwords:
            mask = "".join(
                "?l" if c.islower() else "?u" if c.isupper() else "?d" if c.isdigit() else "?s"
                for c in pwd
            )
            mask_counter[mask] += 1
        top_masks = [f"{m},{c}" for m, c in mask_counter.most_common(100)]
        (self.out / "04_mask_candidates.hcmask").write_text("\n".join(top_masks) + "\n")
        log.info(f" → 04_mask_candidates.hcmask (top 100 masks)")

        # Year/season rules
        year_rules = []
        for y in range(1990, 2031):
            digits = hashcat_append(str(y))
            year_rules.extend([f"l{digits}", f"l c{digits}", f"l{digits} $!", f"l c{digits} $!"])
        for y in range(20, 31):
            short = f"{y:02d}"
            digits = hashcat_append(short)
            year_rules.extend([f"l{digits}", f"l c{digits}", f"l{digits} $!", f"l c{digits} $!"])
        seasons = ["spring","summer","fall","winter","jan","feb","mar","apr","may","jun",
                   "jul","aug","sep","oct","nov","dec"]
        for word in seasons:
            cap = word.capitalize()
            for yr in ["2024","2025","2026"]:
                ydigits = hashcat_append(yr)
                base_low = hashcat_append(word)
                base_cap = hashcat_append(cap)
                year_rules.extend([
                    f"l c{base_low}{ydigits}",
                    f"l c{base_cap}{ydigits}",
                    f"l c{base_low} $!",
                ])
        year_rules = list(dict.fromkeys(year_rules))[:10000]
        (self.out / "05_years_seasons.rule").write_text("\n".join(year_rules) + "\n")
        log.info(f" → 05_years_seasons.rule ({len(year_rules)})")

        # Stats
        stats = f"""
Target Analysis Report — {datetime.now():%Y-%m-%d %H:%M}
Total passwords parsed: {len(self.passwords):,}
Top prefixes: {', '.join(k for k, _ in self.prefix.most_common(15))}
Top suffixes: {', '.join(k for k, _ in self.suffix.most_common(15))}
        """.strip()
        (self.out / "stats.txt").write_text(stats + "\n")
        log.info(f" → stats.txt")

    # -------------------------------
    # Full artifact generation
    # -------------------------------
    def generate_all_artifacts(self):
        log.info("Phase 2/3: Generating artifacts with advanced features...")
        
        # Original features
        self.generate_real_bases()
        self.generate_user_context_rules()
        self.write_username_wordlist() 
        self.generate_prefix_suffix_rules()
        self.generate_surround_rules()
        self.generate_static_and_year_rules()
        
        # Advanced features
        self.generate_leet_rules()
        self.generate_bfs_complex_rules()
        self.generate_trie_based_bases()
        
        # Write outputs
        self.write_rules()
        self.generate_masks_and_years()
        
        log.info("Phase 3/3: All artifacts generated successfully!")
        log.info(f"\nALL DONE! → {self.out.resolve()}")

# =============================================
# CLI
# =============================================
def find_files(paths: List[str]) -> List[Path]:
    out = []
    for p in paths:
        ppath = Path(p).expanduser()
        if ppath.is_dir():
            out.extend(ppath.rglob("*"))
        elif ppath.is_file():
            out.append(ppath)
    return sorted([f for f in out if f.is_file() and f.stat().st_size > 0])

def main():
    parser = argparse.ArgumentParser(description="PasswordRuleMiner — Artifact Generator")
    parser.add_argument("-p", "--pot", nargs="+", required=True, help="Potfile(s) or directory of potfiles")
    parser.add_argument("-hf", "--hashfile", nargs="*", help="Hashfile(s) or directory of hash files")
    parser.add_argument("-o", "--output", type=Path, default=Path("listminer"), help="Output directory")
    parser.add_argument("--no-cache", action="store_true", help="Disable caching of processed files")
    parser.add_argument("--clear-cache", action="store_true", help="Clear cache and exit")
    args = parser.parse_args()
    
    # Handle cache clearing
    if args.clear_cache:
        cache_dir = args.output / ".listminer_cache"
        cache = FileCache(cache_dir)
        cache.clear()
        return

    pot_files = find_files(args.pot)
    if not pot_files:
        log.error("No potfiles found! Exiting.")
        sys.exit(1)

    hash_files = find_files(args.hashfile) if args.hashfile else []

    use_cache = not args.no_cache
    if use_cache:
        log.info("File caching enabled (use --no-cache to disable)")
    
    miner = PasswordRuleMiner(args.output, use_cache=use_cache)
    miner.mine_potfiles(pot_files)
    if hash_files:
        miner.mine_hashfiles(hash_files)
    miner.generate_all_artifacts()

if __name__ == "__main__":
    main()
