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
import os
import pickle
import re
import signal
import sys
from collections import Counter, defaultdict, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from threading import Lock
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
# PARALLEL PROCESSING CONFIGURATION
# =============================================
# Fallback CPU count when os.cpu_count() returns None (unknown system)
FALLBACK_CPU_COUNT = 4

# Determine optimal worker count (CPU count or environment variable)
DEFAULT_WORKERS = min(8, (os.cpu_count() or FALLBACK_CPU_COUNT))
MAX_WORKERS = int(os.environ.get('LISTMINER_MAX_WORKERS', DEFAULT_WORKERS))

# Batch multiplier for load balancing across workers
# Higher values create more batches for better distribution and progress tracking
BATCH_MULTIPLIER = 4

# Minimum batch sizes for different operation types
MIN_PASSWORD_BATCH_SIZE = 1000  # For password processing operations
MIN_WORD_BATCH_SIZE = 10  # For word-level operations (smaller datasets)

# =============================================
# Logging
# =============================================
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger(__name__)

# Thread-safe logging lock for parallel operations
_log_lock = Lock()

def parallel_log(message: str):
    """Thread-safe logging for parallel operations"""
    with _log_lock:
        log.info(message)

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

def hashcat_prepend(word: str, reverse: bool = True, max_length: int = 6) -> str:
    """
    Generate efficient Hashcat prepend rule using only Hashcat syntax.
    Uses ^X for each character (reversed order for proper prepending).
    Limited to max_length characters for practical rule efficiency.
    """
    if not is_ascii_safe(word) or len(word) > max_length or len(word) == 0:
        return None
    
    # For single character, use ^X
    if len(word) == 1:
        return f"^{word}"
    
    # For multiple characters, use individual ^ commands (reversed for correct order)
    if reverse:
        word = word[::-1]
    return " ".join(f"^{c}" for c in word)

def hashcat_append(word: str, max_length: int = 6) -> str:
    """
    Generate efficient Hashcat append rule using only Hashcat syntax.
    Uses $X for each character (Hashcat standard).
    Limited to max_length characters for practical rule efficiency.
    """
    if not is_ascii_safe(word) or len(word) > max_length or len(word) == 0:
        return None
    
    # For single character, use $X
    if len(word) == 1:
        return f"${word}"
    
    # For multiple characters, use individual $ commands
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
    
    # Basic Hashcat operations (including Hashcat 7+ features)
    OPERATIONS = [
        ('l', 'lowercase'),
        ('u', 'uppercase'),
        ('c', 'capitalize'),
        ('C', 'invert capitalize'),
        ('E', 'title case'),  # Hashcat 7+
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
    
    def extract_base_words(self, passwords: List[str], max_workers: int = None) -> List[Tuple[str, int]]:
        """
        Extract and analyze base words from passwords.
        Strips common patterns and returns high-quality bases.
        Now parallelized for improved performance.
        """
        if max_workers is None:
            max_workers = MAX_WORKERS
        
        # Create batches for parallel processing
        batch_size = PasswordRuleMiner._calculate_batch_size_for_workers(len(passwords), max_workers)
        password_batches = [
            passwords[i:i + batch_size]
            for i in range(0, len(passwords), batch_size)
        ]
        
        def process_batch(batch):
            """Process a batch of passwords to extract base words"""
            batch_counter = Counter()
            for pwd in batch:
                # Clean the password - remove numbers, special chars at ends
                cleaned = re.sub(r'^[^a-zA-Z]+', '', pwd)
                cleaned = re.sub(r'[^a-zA-Z]+$', '', cleaned)
                cleaned = re.sub(r'\d{2,}', '', cleaned)  # Remove number sequences
                
                # Extract alpha sequences
                alpha_parts = re.findall(r'[a-zA-Z]{3,}', cleaned)
                for part in alpha_parts:
                    part_lower = part.lower()
                    if 3 <= len(part_lower) <= 15:
                        batch_counter[part_lower] += 1
            return batch_counter
        
        # Process batches in parallel
        word_counter = Counter()
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(process_batch, batch): idx
                for idx, batch in enumerate(password_batches)
            }
            
            for future in as_completed(futures):
                batch_idx = futures[future]
                try:
                    batch_counter = future.result()
                    word_counter.update(batch_counter)
                    # Insert into trie sequentially for thread safety
                    # Note: Trie insertion is done here rather than in parallel workers
                    # to avoid the complexity and overhead of thread-safe trie operations.
                    # This sequential insertion is fast enough since it's just updating
                    # the already-computed word counts.
                    for word, count in batch_counter.items():
                        self.insert(word, count)
                except Exception as e:
                    parallel_log(f"Error processing trie batch {batch_idx}: {e}")
        
        return word_counter.most_common()

# =============================================
# MAIN CLASS — PASSWORD RULE MINER
# =============================================
class PasswordRuleMiner:
    def __init__(self, output_dir: Path, use_cache: bool = True, max_workers: int = None):
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
        
        # Parallel processing configuration
        self.max_workers = max_workers if max_workers is not None else MAX_WORKERS
        self._rules_lock = Lock()  # Thread-safe access to scored_rules

        # ======= Fix: Compile the USER_PATTERNS =======
        self.COMPILED_USER_RE = [re.compile(p) for p in self.USER_PATTERNS]

        # Email cleanup regex
        self.EMAIL_RE = re.compile(r'^([^@]+)@.+$')

    # -------------------------------
    # File parsing
    # -------------------------------
    @staticmethod
    def _calculate_batch_size_for_workers(items_count: int, max_workers: int, min_batch_size: int = MIN_PASSWORD_BATCH_SIZE) -> int:
        """
        Calculate optimal batch size for parallel processing.
        Uses BATCH_MULTIPLIER to ensure enough batches for load balancing.
        Ensures minimum batch size of 1 to prevent division errors.
        """
        if items_count == 0:
            return 1
        calculated_size = items_count // (max_workers * BATCH_MULTIPLIER)
        # Return the maximum of 1 and min_batch_size, but use calculated_size if it's larger
        return max(1, max(min_batch_size if calculated_size < min_batch_size else calculated_size, 1))
    
    def _calculate_batch_size(self, items_count: int, min_batch_size: int = MIN_PASSWORD_BATCH_SIZE) -> int:
        """Calculate optimal batch size for parallel processing using instance workers"""
        return self._calculate_batch_size_for_workers(items_count, self.max_workers, min_batch_size)
    
    def _add_scored_rules(self, rules: List[Tuple[int, str]]):
        """Thread-safe method to add scored rules"""
        with self._rules_lock:
            self.scored_rules.extend(rules)
    
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

        # Build prefix/suffix counters (max 6 chars, never full password)
        for pwd in self.passwords:
            pwd_len = len(pwd)
            # Extract prefixes and suffixes, but never the full password
            # Maximum of 6 characters
            max_extract = min(6, pwd_len - 1) if pwd_len > 1 else 0
            for i in range(1, max_extract + 1):
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
                # Limit to reasonable username length (3-10 chars)
                if len(part) < 3 or len(part) > 10:
                    continue
                
                # Skip non-ASCII usernames
                if not is_ascii_safe(part):
                    continue
                    
                low = part.lower()
                cap = part.capitalize()

                # Prepend username (reversed) - max 6 chars enforced in hashcat_prepend
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
        log.info(f"Using {self.max_workers} parallel workers for base extraction")

        def process_password_batch_for_bases(batch):
            """Process a batch of passwords to extract bases"""
            batch_counter = Counter()
            for pwd in batch:
                # Try multiple extraction strategies
                bases = self._extract_simple_bases(pwd)
                for base in bases:
                    if len(base) >= 4:
                        batch_counter[base] += 1
            return batch_counter
        
        # Create batches for parallel processing
        batch_size = self._calculate_batch_size(len(self.passwords))
        password_batches = [
            self.passwords[i:i + batch_size]
            for i in range(0, len(self.passwords), batch_size)
        ]
        
        parallel_log(f"Processing {len(self.passwords):,} passwords in {len(password_batches)} batches")
        
        counter = Counter()
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(process_password_batch_for_bases, batch): idx
                for idx, batch in enumerate(password_batches)
            }
            
            for future in as_completed(futures):
                batch_idx = futures[future]
                try:
                    batch_counter = future.result()
                    counter.update(batch_counter)
                    parallel_log(f"Base extraction batch {batch_idx + 1}/{len(password_batches)} complete: "
                               f"{len(batch_counter):,} bases found")
                except Exception as e:
                    parallel_log(f"Error processing base extraction batch {batch_idx}: {e}")

        # Keep top_n most common
        top_bases = [word for word, _ in counter.most_common(top_n)]

        out_file = self.out / "00_real_bases.txt"
        out_file.write_text("\n".join(top_bases) + "\n", encoding="utf-8")
        log.info(f" → 00_real_bases.txt ({len(top_bases):,} bases)")
    
    def _extract_simple_bases(self, password: str) -> List[str]:
        """
        Extract base words from a password using multiple simple strategies.
        Returns a list of potential base words.
        """
        bases = []
        
        # Strategy 1: Unleet and extract alphabetic sequences
        unleeted = self._unleet_string(password).lower()
        
        # Extract all alphabetic sequences of 4+ characters
        for match in re.finditer(r'[a-z]{4,}', unleeted):
            base = match.group()
            # Skip if it's mostly consonants (likely not a word)
            vowels = sum(1 for c in base if c in 'aeiouy')
            if vowels >= len(base) * 0.2:  # At least 20% vowels
                bases.append(base)
        
        # Strategy 2: Remove all non-alphabetic and extract longest sequences
        # First unleet the password
        unleeted_pwd = self._unleet_string(password)
        # Remove all numbers and special chars
        cleaned = re.sub(r'[^a-zA-Z]+', '', unleeted_pwd)
        if len(cleaned) >= 4:
            bases.append(cleaned.lower())
        
        # Strategy 3: Strip edges and extract core
        # Remove leading/trailing non-alpha
        stripped = re.sub(r'^[^a-zA-Z]+|[^a-zA-Z]+$', '', password)
        if stripped:
            # Unleet it
            unleeted_stripped = self._unleet_string(stripped)
            # Remove any remaining non-alpha from middle
            cleaned_stripped = re.sub(r'[^a-zA-Z]+', '', unleeted_stripped)
            if len(cleaned_stripped) >= 4:
                bases.append(cleaned_stripped.lower())
        
        # Strategy 4: Extract word-like patterns (sequences with vowels)
        # Find all alphabetic sequences in the unleeted password
        all_alpha_sequences = re.findall(r'[a-z]{4,}', unleeted)
        for seq in all_alpha_sequences:
            # Check if it looks like a real word (has vowels)
            vowels = sum(1 for c in seq if c in 'aeiouy')
            if vowels >= 2 or vowels >= len(seq) * 0.25:
                bases.append(seq)
        
        # Remove duplicates and sort by length (longest first)
        unique_bases = list(dict.fromkeys(bases))
        # Filter out bases that are substrings of longer bases
        filtered_bases = []
        for base in sorted(unique_bases, key=len, reverse=True):
            # Check if this base is a substring of any already added base
            if not any(base in existing and base != existing for existing in filtered_bases):
                filtered_bases.append(base)
        
        return filtered_bases
    
    def _unleet_char(self, char: str) -> str:
        """Convert a leet character back to its original form"""
        leet_reverse = {
            '@': 'a', '4': 'a',
            '3': 'e',
            '1': 'i', '!': 'i',
            '0': 'o',
            '$': 's', '5': 's',
            '7': 't', '+': 't',
            '9': 'g',
            '8': 'b'
        }
        return leet_reverse.get(char, char)
    
    def _unleet_string(self, text: str) -> str:
        """
        Convert a leet-speak string back to normal text.
        Only unleets characters that are clearly leet (special chars and single digits within letters).
        """
        result = []
        for i, char in enumerate(text):
            # Check if this is a leet character
            if char in '@!$+':
                # Always unleet special chars
                result.append(self._unleet_char(char))
            elif char in '0134578' and i > 0 and i < len(text) - 1:
                # Only unleet digits if they're surrounded by letters (leet within word)
                prev_is_alpha = i > 0 and text[i-1].isalpha()
                next_is_alpha = i < len(text) - 1 and text[i+1].isalpha()
                if prev_is_alpha or next_is_alpha:
                    result.append(self._unleet_char(char))
                else:
                    result.append(char)
            else:
                result.append(char)
        return ''.join(result)
    
    def _extract_base_candidates(self, password: str) -> List[Tuple[str, int, int]]:
        """
        Extract all possible base word candidates from a password.
        Returns list of (base_word, start_pos, end_pos) tuples.
        """
        candidates = []
        
        # Strategy 1: Unleet the password first
        unleeted = self._unleet_string(password)
        
        # Strategy 2: Check for duplicated words (e.g., "passwordpassword")
        pwd_len = len(password)
        # Try splitting at different points to see if it's a duplication
        for split_point in range(pwd_len // 2, min(pwd_len, pwd_len // 2 + 2)):
            first_half = password[:split_point]
            second_half = password[split_point:]
            
            # Check if they're the same (case-insensitive)
            if first_half.lower() == second_half.lower() and len(first_half) >= 4:
                candidates.append((first_half.lower(), 0, split_point))
            
            # Check if unleeted versions are the same
            first_unleeted = self._unleet_string(first_half)
            second_unleeted = self._unleet_string(second_half)
            if first_unleeted.lower() == second_unleeted.lower() and len(first_unleeted) >= 4:
                candidates.append((first_unleeted.lower(), 0, len(first_unleeted)))
        
        # Strategy 3: Find all alphabetic sequences (length 4+)
        for match in re.finditer(r'[a-zA-Z]{4,}', unleeted):
            base = match.group().lower()
            candidates.append((base, match.start(), match.end()))
        
        # Strategy 4: Try removing common suffixes/prefixes
        # Remove trailing numbers and special chars
        cleaned = re.sub(r'[0-9!@#$%^&*()_+=\-\[\]{}|;:,.<>?/~`]+$', '', unleeted)
        if len(cleaned) >= 4 and cleaned.isalpha():
            candidates.append((cleaned.lower(), 0, len(cleaned)))
        
        # Remove leading numbers and special chars
        cleaned = re.sub(r'^[0-9!@#$%^&*()_+=\-\[\]{}|;:,.<>?/~`]+', '', unleeted)
        if len(cleaned) >= 4 and cleaned.isalpha():
            start = len(unleeted) - len(cleaned)
            candidates.append((cleaned.lower(), start, len(unleeted)))
        
        # Remove both leading and trailing non-alpha
        cleaned = re.sub(r'^[^a-zA-Z]+|[^a-zA-Z]+$', '', unleeted)
        if len(cleaned) >= 4 and cleaned.isalpha():
            candidates.append((cleaned.lower(), -1, -1))
        
        # Strategy 5: Split on common separators and take longest part
        parts = re.split(r'[0-9!@#$%^&*()_+=\-\[\]{}|;:,.<>?/~`]+', unleeted)
        for part in parts:
            if len(part) >= 4 and part.isalpha():
                candidates.append((part.lower(), -1, -1))  # Position unknown
        
        # Strategy 6: Try to identify compound words (e.g., "PasswordManager")
        # Find sequences with capital letters
        for match in re.finditer(r'[A-Z][a-z]+', password):
            word = match.group().lower()
            if len(word) >= 4:
                candidates.append((word, match.start(), match.end()))
        
        # Strategy 7: Look for repeated patterns within the password
        # Check if the password contains the same word twice with slight variations
        for i in range(4, len(unleeted) // 2 + 1):
            pattern = unleeted[:i]
            if len(pattern) >= 4 and pattern.lower() in unleeted[i:].lower():
                candidates.append((pattern.lower(), 0, i))
        
        # Remove duplicates while preserving order
        seen = set()
        unique_candidates = []
        for base, start, end in candidates:
            if base not in seen and len(base) >= 4:
                seen.add(base)
                unique_candidates.append((base, start, end))
        
        # Sort by length (longest first) - longer bases are usually better
        unique_candidates.sort(key=lambda x: len(x[0]), reverse=True)
        
        return unique_candidates
    
    def analyze_password_transformations(self):
        """
        Comprehensive password analysis to identify base words and rules.
        Uses multiple strategies to find the best base word candidates.
        Optimized for speed with early termination and efficient algorithms.
        Now parallelized for improved performance.
        """
        log.info("Performing comprehensive password transformation analysis...")
        log.info(f"Using {self.max_workers} parallel workers for analysis")
        
        base_to_rules = defaultdict(Counter)  # base -> Counter of rules
        identified_bases = Counter()
        password_to_base = {}  # Track which base was used for each password
        
        analyzed_count = 0
        skipped_count = 0
        
        # Create batches for parallel processing
        batch_size = self._calculate_batch_size(len(self.passwords))
        password_batches = [
            self.passwords[i:i + batch_size] 
            for i in range(0, len(self.passwords), batch_size)
        ]
        
        parallel_log(f"Processing {len(self.passwords):,} passwords in {len(password_batches)} batches")
        
        def process_password_batch(batch):
            """Process a batch of passwords and return results"""
            batch_bases = Counter()
            batch_base_rules = defaultdict(Counter)
            batch_pwd_base = {}
            batch_analyzed = 0
            batch_skipped = 0
            
            for pwd in batch:
                # Skip very short passwords (quick check)
                if len(pwd) < 4:
                    batch_skipped += 1
                    continue
                
                # Get all possible base candidates (optimized extraction)
                candidates = self._extract_base_candidates(pwd)
                
                if not candidates:
                    batch_skipped += 1
                    continue
                
                # Try each candidate and pick the best one (early termination on first good match)
                best_base = None
                best_rules = None
                best_score = 0
                
                # Only try top 3 candidates for speed (most relevant ones)
                for base_candidate, start, end in candidates[:3]:
                    rules = self._infer_comprehensive_rules(base_candidate, pwd, start, end)
                    
                    if rules:
                        # Score based on base length and rule simplicity
                        score = len(base_candidate) * 100 - rules.count(' ') * 2
                        
                        if score > best_score:
                            best_base = base_candidate
                            best_rules = rules
                            best_score = score
                            
                            # Early termination: if we find a good match (long base, simple rules), stop
                            if len(base_candidate) >= 6 and rules.count(' ') <= 10:
                                break
                
                if best_base and best_rules:
                    batch_bases[best_base] += 1
                    batch_base_rules[best_base][best_rules] += 1
                    batch_pwd_base[pwd] = (best_base, best_rules)
                    batch_analyzed += 1
            
            return batch_bases, batch_base_rules, batch_pwd_base, batch_analyzed, batch_skipped
        
        # Process batches in parallel
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(process_password_batch, batch): idx 
                for idx, batch in enumerate(password_batches)
            }
            
            for future in as_completed(futures):
                batch_idx = futures[future]
                try:
                    batch_bases, batch_base_rules, batch_pwd_base, batch_analyzed, batch_skipped = future.result()
                    
                    # Merge results
                    identified_bases.update(batch_bases)
                    for base, rules in batch_base_rules.items():
                        base_to_rules[base].update(rules)
                    password_to_base.update(batch_pwd_base)
                    analyzed_count += batch_analyzed
                    skipped_count += batch_skipped
                    
                    parallel_log(f"Batch {batch_idx + 1}/{len(password_batches)} complete: "
                               f"{batch_analyzed:,} analyzed, {batch_skipped:,} skipped")
                except Exception as e:
                    parallel_log(f"Error processing batch {batch_idx}: {e}")
        
        log.info(f"Successfully analyzed {analyzed_count:,} passwords")
        log.info(f"Identified {len(identified_bases):,} unique base words")
        log.info(f"Skipped {skipped_count:,} passwords (too short or no base found)")
        
        # Write base words to a file
        base_file = self.out / "00_analyzed_bases.txt"
        sorted_bases = [base for base, _ in identified_bases.most_common()]
        base_file.write_text("\n".join(sorted_bases) + "\n", encoding="utf-8")
        log.info(f" → 00_analyzed_bases.txt ({len(sorted_bases):,} bases)")
        
        # Generate rules based on the most common transformations
        rule_count = 0
        for base, rule_counter in sorted(base_to_rules.items(), key=lambda x: sum(x[1].values()), reverse=True):
            # Get the most common rules for this base
            for rule, count in rule_counter.most_common(3):  # Top 3 rules per base
                if count >= 2:  # Only include if seen at least twice
                    # Score based on frequency and base popularity
                    score = count * 100000 + identified_bases[base] * 1000
                    self.scored_rules.append((score, rule))
                    rule_count += 1
        
        log.info(f"Generated {rule_count:,} transformation-based rules from analysis")
    
    def _infer_comprehensive_rules(self, base: str, password: str, start_hint: int = -1, end_hint: int = -1) -> str:
        """
        Comprehensive rule inference that handles:
        - Leet-speak substitutions
        - Case transformations
        - Prefix/suffix additions
        - Duplication (d command)
        - Position-based insertions
        """
        rules = []
        
        # Check for duplication pattern first
        base_lower = base.lower()
        pwd_lower = password.lower()
        unleeted_pwd = self._unleet_string(password).lower()
        
        # Check if password is a duplicate of the base
        pwd_len = len(password)
        base_len = len(base)
        
        # Pattern 1: Exact duplicate (e.g., "passwordpassword")
        if pwd_len == base_len * 2:
            first_half = password[:base_len]
            second_half = password[base_len:]
            
            # Check if both halves match the base (with case/leet variations)
            first_unleeted = self._unleet_string(first_half).lower()
            second_unleeted = self._unleet_string(second_half).lower()
            
            if first_unleeted == base_lower and second_unleeted == base_lower:
                # It's a duplication! Build the rule
                # Apply case to first half
                if first_half.islower():
                    rules.append('l')
                elif first_half.isupper():
                    rules.append('u')
                elif first_half[0].isupper() and first_half[1:].islower():
                    rules.append('c')
                
                # Apply leet to first half
                for i, (base_char, pwd_char) in enumerate(zip(base_lower, first_half.lower())):
                    unleeted_char = self._unleet_char(pwd_char)
                    if base_char == unleeted_char and base_char != pwd_char:
                        rules.append(f's{base_char}{pwd_char}')
                
                # Duplicate
                rules.append('d')
                
                # Check if second half needs different case
                if second_half != first_half:
                    # Second half has different case - might need toggle or other transformation
                    # For simplicity, we'll skip complex duplication rules
                    if second_half[0].isupper() and first_half[0].islower():
                        # Can't easily represent this, skip
                        return ""
                
                return " ".join(rules) if rules else ""
        
        # Pattern 2: Standard password (non-duplicated)
        # Find where the base appears
        base_start = -1
        base_end = -1
        
        if start_hint >= 0 and end_hint > start_hint:
            base_start = start_hint
            base_end = end_hint
        elif base_lower in unleeted_pwd:
            base_start = unleeted_pwd.index(base_lower)
            base_end = base_start + len(base_lower)
        else:
            # Try to find partial match
            for i in range(len(unleeted_pwd) - len(base_lower) + 1):
                segment = unleeted_pwd[i:i+len(base_lower)]
                # Allow for some character differences (for leet that we missed)
                matches = sum(1 for a, b in zip(segment, base_lower) if a == b)
                if matches >= len(base_lower) * 0.7:  # 70% match threshold
                    base_start = i
                    base_end = i + len(base_lower)
                    break
        
        if base_start == -1:
            return ""  # Can't find base in password
        
        # Extract parts
        prefix = password[:base_start]
        base_part = password[base_start:base_end]
        suffix = password[base_end:]
        
        # Complexity check
        if len(prefix) > 10 or len(suffix) > 10:
            return ""
        
        if prefix and not is_ascii_safe(prefix):
            return ""
        if suffix and not is_ascii_safe(suffix):
            return ""
        
        # Build the rule
        rules = []
        
        # Step 1: Prepend prefix (in reverse order)
        if prefix:
            for char in reversed(prefix):
                rules.append(f'^{char}')
        
        # Step 2: Case transformation
        if base_part.islower():
            rules.append('l')
        elif base_part.isupper():
            rules.append('u')
        elif len(base_part) > 0 and base_part[0].isupper():
            if len(base_part) == 1 or base_part[1:].islower():
                rules.append('c')
            else:
                # Mixed case - check pattern
                if sum(1 for c in base_part if c.isupper()) > len(base_part) / 2:
                    rules.append('t')  # Toggle
        
        # Step 3: Leet substitutions (compare actual password chars with base)
        for i in range(min(len(base_lower), len(base_part))):
            base_char = base_lower[i]
            pwd_char = base_part[i].lower()
            
            # Check if this is a leet substitution
            unleeted_char = self._unleet_char(pwd_char)
            if base_char == unleeted_char and base_char != pwd_char:
                # This is a leet substitution
                rules.append(f's{base_char}{pwd_char}')
        
        # Step 4: Append suffix
        if suffix:
            for char in suffix:
                rules.append(f'${char}')
        
        # Validate rule length
        if len(rules) > 50:
            return ""  # Too complex
        
        return " ".join(rules)
    
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
        """Generate leet-speak mutation rules with parallel processing"""
        log.info("Generating leet-speak mutation rules...")
        log.info(f"Using {self.max_workers} parallel workers for leet rule generation")
        
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
        
        def process_word_batch(words_batch):
            """Process a batch of words and generate leet rules"""
            batch_rules = []
            for word in words_batch:
                leet_variants = generate_leet_rules(word, max_substitutions=2)
                for rule in leet_variants:
                    # Score based on word frequency and rule complexity
                    freq = word_counter[word]
                    score = int(freq * 5000)
                    batch_rules.append((score, rule))
            return batch_rules
        
        # Create batches for parallel processing (smaller batches for word processing)
        batch_size = self._calculate_batch_size(len(top_words), MIN_WORD_BATCH_SIZE)
        word_batches = [
            top_words[i:i + batch_size]
            for i in range(0, len(top_words), batch_size)
        ]
        
        parallel_log(f"Processing {len(top_words)} words in {len(word_batches)} batches")
        
        leet_count = 0
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {
                executor.submit(process_word_batch, batch): idx
                for idx, batch in enumerate(word_batches)
            }
            
            for future in as_completed(futures):
                batch_idx = futures[future]
                try:
                    batch_rules = future.result()
                    self._add_scored_rules(batch_rules)
                    leet_count += len(batch_rules)
                    parallel_log(f"Leet batch {batch_idx + 1}/{len(word_batches)} complete: "
                               f"{len(batch_rules):,} rules generated")
                except Exception as e:
                    parallel_log(f"Error processing leet batch {batch_idx}: {e}")
        
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
        log.info(f"Using {self.max_workers} parallel workers for trie operations")
        
        # Extract base words using trie with parallel processing
        trie_bases = self.trie.extract_base_words(self.passwords, max_workers=self.max_workers)
        
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
    
    def write_unified_wordlist(self):
        """
        Create a unified wordlist combining all base wordlists and usernames.
        Reads from: 00_real_bases.txt, 00_analyzed_bases.txt, 00_trie_bases.txt, usernames.txt
        Outputs: 00_unified_wordlist.txt (deduplicated and sorted)
        """
        log.info("Generating unified wordlist from all base sources...")
        
        unified_words = set()
        
        # List of source files to combine
        source_files = [
            self.out / "00_real_bases.txt",
            self.out / "00_analyzed_bases.txt",
            self.out / "00_trie_bases.txt",
            self.out / "usernames.txt"
        ]
        
        # Read each source file and add to unified set
        for source_file in source_files:
            if source_file.exists():
                try:
                    with source_file.open('r', encoding='utf-8') as f:
                        for line in f:
                            word = line.strip()
                            if word:  # Only add non-empty words
                                unified_words.add(word)
                    log.info(f"  → Loaded {source_file.name}")
                except Exception as e:
                    log.warning(f"  → Could not read {source_file.name}: {e}")
            else:
                log.warning(f"  → Skipping {source_file.name} (not found)")
        
        # Sort and write unified wordlist
        out_file = self.out / "00_unified_wordlist.txt"
        sorted_words = sorted(unified_words)
        out_file.write_text("\n".join(sorted_words) + "\n", encoding="utf-8")
        log.info(f" → 00_unified_wordlist.txt ({len(sorted_words):,} unique words)")
    
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
        
        # NEW: Comprehensive password analysis
        self.analyze_password_transformations()
        
        # Write outputs
        self.write_rules()
        self.generate_masks_and_years()
        
        # Generate unified wordlist after all bases are created
        self.write_unified_wordlist()
        
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
    parser.add_argument("--max-workers", type=int, default=None, 
                        help=f"Maximum number of parallel workers (default: {MAX_WORKERS})")
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
    
    max_workers = args.max_workers if args.max_workers else MAX_WORKERS
    log.info(f"Parallel processing enabled with {max_workers} workers")
    
    miner = PasswordRuleMiner(args.output, use_cache=use_cache, max_workers=max_workers)
    miner.mine_potfiles(pot_files)
    if hash_files:
        miner.mine_hashfiles(hash_files)
    miner.generate_all_artifacts()

if __name__ == "__main__":
    main()