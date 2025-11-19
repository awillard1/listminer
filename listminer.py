#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PasswordRuleMiner — Ultimate 2025 Artifact Generator

Features:
- Single or multiple potfiles (directory recursion)
- Single or multiple hash files (directory recursion)
- Generates Hashcat prepend/append rules, masks, and year/season rules
- Fully compatible with complex usernames and special characters
- Robust logging for every processed file and generation step
"""
import argparse
import logging
import re
import signal
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import List, Iterable, Dict

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
def hashcat_prepend(word: str, reverse: bool = True) -> str:
    """Generate Hashcat prepend rule (^ per char), optionally reversed"""
    if reverse:
        word = word[::-1]
    return " ".join(f"^{c}" for c in word)

def hashcat_append(word: str) -> str:
    """Generate Hashcat append rule ($ per char)"""
    return " ".join(f"${c}" for c in word)

# =============================================
# MAIN CLASS — PASSWORD RULE MINER
# =============================================
class PasswordRuleMiner:
    def __init__(self, output_dir: Path):
        self.out = output_dir
        self.out.mkdir(parents=True, exist_ok=True)
        self.scored_rules = []
        self.passwords: List[str] = []
        self.prefix = Counter()
        self.suffix = Counter()
        self.usernames: Dict[str, List[str]] = defaultdict(list)

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
        count = 0
        with path.open("r", encoding="utf-8", errors="ignore") as f:
            for line in progress(f, desc=path.stem[:30], leave=False):
                pwd = extract_password_from_pot(line)
                if pwd and len(pwd) >= 1:
                    self.passwords.append(pwd)
                    count += 1
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
        count = 0
        with path.open("r", encoding="utf-8", errors="ignore") as f:
            for line in progress(f, desc=path.stem[:30], leave=False):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                # If line STARTS with $krb5 → no username → skip
                if KERB_SKIP_RE.match(line):
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
                mail = EMAIL_RE.match(username)
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
                self.usernames[username].append("")
                count += 1

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
                low = part.lower()
                cap = part.capitalize()

                # Prepend username (reversed)
                self.scored_rules.append((10_000_000, hashcat_prepend(low)))
                self.scored_rules.append((9_900_000, hashcat_prepend(cap)))

                # Append username (normal order)
                self.scored_rules.append((9_900_000, hashcat_append(low)))
                self.scored_rules.append((9_800_000, hashcat_append(cap)))

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
            if len(prefix) >= 2:
                rule = hashcat_prepend(prefix)
                score = int(count * (len(prefix) ** 3.6) * 38)
                self.scored_rules.append((score, rule))
        for suffix, count in self.suffix.most_common(1600):
            if len(suffix) >= 2:
                rule = hashcat_append(suffix)
                score = int(count * (len(suffix) ** 3.3) * 32)
                self.scored_rules.append((score, rule))

    def generate_surround_rules(self):
        log.info("Generating surround rules...")
        seen = set()
        for prefix, pc in self.prefix.most_common(500):
            if not 2 <= len(prefix) <= 5:
                continue
            pre = hashcat_prepend(prefix)
            for suffix, sc in self.suffix.most_common(500):
                if not 2 <= len(suffix) <= 5:
                    continue
                app = hashcat_append(suffix)
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
        (self.out / "06_mask_candidates.hcmask").write_text("\n".join(top_masks) + "\n")
        log.info(f" → 06_mask_candidates.hcmask (top 100 masks)")

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
        (self.out / "07_years_seasons.rule").write_text("\n".join(year_rules) + "\n")
        log.info(f" → 07_years_seasons.rule ({len(year_rules)})")

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
        self.generate_real_bases()
        self.generate_user_context_rules()
        self.write_username_wordlist() 
        self.generate_prefix_suffix_rules()
        self.generate_surround_rules()
        self.generate_static_and_year_rules()
        self.write_rules()
        self.generate_masks_and_years()
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
    parser.add_argument("-o", "--output", type=Path, default=Path("rules"), help="Output directory")
    args = parser.parse_args()

    pot_files = find_files(args.pot)
    if not pot_files:
        log.error("No potfiles found! Exiting.")
        sys.exit(1)

    hash_files = find_files(args.hashfile) if args.hashfile else []

    miner = PasswordRuleMiner(args.output)
    miner.mine_potfiles(pot_files)
    if hash_files:
        miner.mine_hashfiles(hash_files)
    miner.generate_all_artifacts()

if __name__ == "__main__":
    main()
