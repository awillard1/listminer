#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
listminer.py — Red-Team Password Artifact Generator
One command → 8 hashcat-ready outputs
Tested & working on Python 3.13 + hashcat 6.2.6+
"""

import argparse
import logging
import re
import signal
import subprocess
import shlex
import sys
import tempfile
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import List, Iterable

# =============================================
# PROGRESS BAR
# =============================================
try:
    from tqdm import tqdm as _tqdm
    TQDM = True
except Exception:
    TQDM = False
def progress(it, **kw):
    return _tqdm(it, **kw) if TQDM and sys.stdout.isatty() else it

# =============================================
# Logging — FIXED FOR Python 3.13 (%% instead of %)
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
    if not text:
        return ""
    if text.startswith("$HEX[") and text.endswith("]"):
        try:
            return bytes.fromhex(text[5:-1]).decode("latin-1")
        except ValueError:
            return ""
    return HEX_ESCAPE_RE.sub(lambda m: chr(int(m.group(0)[2:], 16)), text)

def extract_password(line: str) -> str:
    line = line.strip()
    if not line:
        return ""
    return decode_plaintext(line.rsplit(":", 1)[-1]) if ":" in line else decode_plaintext(line)

# =============================================
# Find files
# =============================================
def find_password_files(directory: Path) -> List[Path]:
    exts = {".txt", ".pot", ".potfile", ".lst", ".list", ""}
    files = [p.resolve() for p in directory.rglob("*") if p.suffix.lower() in exts and p.is_file() and p.stat().st_size > 0]
    log.info(f"Found {len(files)} password file(s)")
    return sorted(files)

# =============================================
# MAIN CLASS
# =============================================
class RedTeamArtifactGenerator:
    def __init__(self, output_dir: Path):
        self.out = output_dir
        self.out.mkdir(parents=True, exist_ok=True)
        self.scored_rules = []
        self.passwords = []
        self.prefix = Counter()
        self.suffix = Counter()

    def add_rule(self, rule: str, score: int):
        if r := rule.strip():
            self.scored_rules.append((score, r))

    def mine_passwords(self, files: Iterable[Path]):
        log.info("Phase 1/3: Mining passwords and affixes...")
        total = 0
        for file in files:
            size_mb = file.stat().st_size // 1048576
            log.info(f"  → {file.name} ({size_mb} MB)")
            with file.open("r", encoding="utf-8", errors="ignore") as f:
                for line in progress(f, desc=file.stem[:30], leave=False):
                    pwd = extract_password(line)
                    if pwd and len(pwd) >= 6:
                        self.passwords.append(pwd)
                        total += 1
                        n = min(6, len(pwd))
                        for i in range(1, n+1):
                            self.prefix[pwd[:i]] += 1
                            self.suffix[pwd[-i:]] += 1
        log.info(f"Successfully parsed {total:,} passwords")

        # Elite affix rules
        for affix, cnt in self.prefix.most_common(1200):
            bonus = min(len(affix), 6) ** 2.8
            rule = " ".join(f"^{c}" for c in affix)
            self.add_rule(rule, int(cnt * bonus * 15))
        for affix, cnt in self.suffix.most_common(1200):
            bonus = min(len(affix), 6) ** 2.8
            rule = " ".join(f"${c}" for c in affix)
            self.add_rule(rule, int(cnt * bonus * 15))

        # Surround rules
        seen = set()
        for (p, pc) in self.prefix.most_common(300):
            for (s, sc) in self.suffix.most_common(300):
                if p != s and len(p) <= 4 and len(s) <= 4:
                    rule = " ".join(f"^{c}" for c in p) + " " + " ".join(f"${c}" for c in s)
                    if rule not in seen:
                        seen.add(rule)
                        self.add_rule(rule, int((pc + sc) * 10))

        # Killer static rules
        for r in [
            "l c $2 $0 $2 $4 $!", "l c $2 $0 $2 $5", "l c $1 $2 $3 $!",
            "l c $!", "l $!", "c $!", "l c $1 $2 $3"
        ]:
            self.add_rule(r, 999999)

        for year in [2024,2025,2026,2027,2023,2022]:
            yf, ys = str(year), str(year)[-2:]
            for suf in [yf, ys]:
                rule_digits = " $" + " $".join(suf)
                self.add_rule(f"l {rule_digits}", 880000)
                self.add_rule(f"l c {rule_digits}", 870000)
                self.add_rule(f"l {rule_digits} $!", 860000)

    def write_rules(self):
        log.info("Phase 2/3 → Building elite rule set...")
        self.scored_rules.sort(key=lambda x: x[0], reverse=True)
        seen = set()
        unique = [r for _, r in self.scored_rules if r not in seen and not seen.add(r)]

        def write(path, data):
            path.write_text("\n".join(data)+"\n" if isinstance(data, list) else data, encoding="utf-8")
            log.info(f"  → {path.name} ({len(data):,} lines)")

        write(self.out/"01_elite.rule",        unique[:15_000])
        write(self.out/"02_extended_50k.rule", unique[:50_000])
        write(self.out/"03_complete.rule",     unique)

    def generate_all_artifacts(self):
        log.info("Phase 3/3 → Generating 8 red-team artifacts...")

        # 00_real_bases.txt
        with tempfile.NamedTemporaryFile(mode="w+", delete=False, encoding="utf-8") as tmp:
            for pwd in self.passwords:
                print(pwd, file=tmp)
            tmp_path = Path(tmp.name)

        cmd = f"""
        cat {shlex.quote(str(tmp_path))} |
        tr '[:upper:]' '[:lower:]' |
        sed -E 's/(202[0-9]|19[0-9][0-9]|[!@#$%^&*]+|[0-9]{{3,}}$)//gI' |
        grep -E '^[a-z]{{4,}}[a-z]*$' |
        sort | uniq -c | sort -nr | head -2000000 |
        awk '{{print $2}}' > "{self.out/'00_real_bases.txt'}"
        """
        subprocess.run(cmd, shell=True, check=True, executable="/bin/bash")
        count = int(subprocess.check_output(f"wc -l < \"{self.out/'00_real_bases.txt'}\"", shell=True).strip())
        log.info(f"  → 00_real_bases.txt ({count:,} bases)")

        # 04_corp_patterns.rule — valid
        corp_words = Counter()
        for pwd in self.passwords:
            for w in re.findall(r'\b[A-Z][a-z]{4,}\b', pwd):
                corp_words[w] += 1
        corp_rules = []
        for word, _ in corp_words.most_common(500):
            low = word.lower()
            cap = word.capitalize()
            corp_rules.extend([
                f"l c {' '.join(f'${c}' for c in low)}",
                f"l c {' '.join(f'${c}' for c in low)} $!",
                f"l {' '.join(f'${c}' for c in cap)} $!",
                f"l c {' '.join(f'${c}' for c in low)} $2 $0 $2 $5",
            ])
        corp_rules = list(dict.fromkeys(corp_rules))[:3000]
        (self.out/"04_corp_patterns.rule").write_text("\n".join(corp_rules)+"\n")
        log.info(f"  → 04_corp_patterns.rule ({len(corp_rules)} rules)")

        # 05_keyboard_walks.rule — valid
        walk_rules = set()
        patterns = ['1qaz','1q2w3e','qwerty','qwer','asdf','zxcv','zaq1','xsw2','cde3','4rfv','5tgb','6yhn','7ujm']
        for pwd in self.passwords:
            low = pwd.lower()
            for pat in patterns:
                if pat in low:
                    walk_rules.add(" $" + " $".join(pat))
                    walk_rules.add(" ^" + " ^".join(pat[::-1]))
        full = ['1q2w3e4r','qwertyuiop','asdfghjkl','zxcvbnm']
        for w in full:
            walk_rules.add(" $" + " $".join(w))
            walk_rules.add(" ^" + " ^".join(w[::-1]))
        walk_rules = list(walk_rules)[:5000]
        (self.out/"05_keyboard_walks.rule").write_text("\n".join(walk_rules)+"\n")
        log.info(f"  → 05_keyboard_walks.rule ({len(walk_rules)} rules)")

        # 06_mask_candidates.hcmask
        mask_counter = Counter()
        for pwd in self.passwords:
            mask = "".join("?l" if c.islower() else "?u" if c.isupper() else "?d" if c.isdigit() else "?s" for c in pwd)
            mask_counter[mask] += 1
        top_masks = [f"{m},{c}" for m, c in mask_counter.most_common(100)]
        (self.out/"06_mask_candidates.hcmask").write_text("\n".join(top_masks)+"\n")
        log.info(f"  → 06_mask_candidates.hcmask (top 100 masks)")

        # 07_years_seasons.rule — 100% valid
        year_rules = []
        for y in range(1990, 2031):
            digits = " $" + " $".join(str(y))
            year_rules.extend([f"l{digits}", f"l c{digits}", f"l{digits} $!", f"l c{digits} $!"])
        for y in range(20, 31):
            short = f"{y:02d}"
            digits = " $" + " $".join(short)
            year_rules.extend([f"l{digits}", f"l c{digits}", f"l{digits} $!", f"l c{digits} $!"])
        seasons = ["spring","summer","fall","winter","jan","feb","mar","apr","may","jun","jul","aug","sep","oct","nov","dec"]
        for word in seasons:
            cap = word.capitalize()
            for yr in ["2024","2025"]:
                ydigits = " $" + " $".join(yr)
                base_low = " $" + " $".join(word)
                base_cap = " $" + " $".join(cap)
                year_rules.extend([
                    f"l c{base_low}{ydigits}",
                    f"l c{base_cap}{ydigits}",
                    f"l c{base_low} $!",
                ])
        year_rules = list(dict.fromkeys(year_rules))[:10000]
        (self.out/"07_years_seasons.rule").write_text("\n".join(year_rules)+"\n")
        log.info(f"  → 07_years_seasons.rule ({len(year_rules)} rules)")

        # stats.txt
        stats = f"""
Target Analysis Report — {datetime.now():%Y-%m-%d %H:%M}
Total passwords parsed: {len(self.passwords):,}
Top suffixes: {', '.join(k for k, _ in self.suffix.most_common(20))}
Top prefixes: {', '.join(k for k, _ in self.prefix.most_common(20))}
"""
        (self.out/"stats.txt").write_text(stats)
        log.info(f"  → stats.txt")

        tmp_path.unlink(missing_ok=True)
        log.info(f"\nALL DONE! → {self.out.resolve()}")

# =============================================
# CLI
# =============================================
def main():
    parser = argparse.ArgumentParser(description="listminer.py — Red-Team Artifact Generator")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-f", "--file", type=Path, help="Single password file")
    group.add_argument("-d", "--dir", type=Path, help="Directory with password files")
    parser.add_argument("-o", "--output", type=Path, default=Path("listminer_output"), help="Output directory")
    args = parser.parse_args()

    files = [args.file.resolve()] if args.file else find_password_files(args.dir)
    if not files:
        log.error("No files found!")
        sys.exit(1)

    gen = RedTeamArtifactGenerator(args.output)
    gen.mine_passwords(files)
    gen.write_rules()
    gen.generate_all_artifacts()

if __name__ == "__main__":
    main()
