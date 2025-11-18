#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PASSWORD ARTIFACT GENERATOR
One command → 8 outputs perfectly tuned to your target
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
# PROGRESS BAR (bulletproof)
# =============================================
try:
    from tqdm import tqdm as _tqdm
    TQDM = True
except Exception:
    TQDM = False
def progress(it, **kw):
    return _tqdm(it, **kw) if TQDM and sys.stdout.isatty() else it

# =============================================
# Logging & graceful exit
# =============================================
logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(message)s", datefmt="%H:%M:%S")
log = logging.getLogger(__name__)

def sigint_handler(signum, frame):
    log.warning("\nInterrupted by user — exiting cleanly")
    sys.exit(0)
signal.signal(signal.SIGINT, sigint_handler)

# =============================================
# Password decoding ($HEX[] + \x3a)
# =============================================
HEX_BRACKET_RE = re.compile(r'\$HEX\[([0-9a-fA-F]+)\]')
HEX_ESCAPE_RE = re.compile(r'\\x([0-9a-fA-F]{2})')

def decode_plaintext(text: str) -> str:
    if not text:
        return ""
    if text.startswith("$HEX[") and text.endswith("]"):
        try:
            return bytes.fromhex(text[5:-1]).decode("latin-1")
        except ValueError:
            return ""
    return HEX_ESCAPE_RE.sub(lambda m: chr(int(m.group(1), 16)), text)

def extract_password(line: str) -> str:
    line = line.strip()
    if not line:
        return ""
    return decode_plaintext(line.rsplit(":", 1)[-1]) if ":" in line else decode_plaintext(line)

# =============================================
# Find any password-containing files
# =============================================
def find_password_files(directory: Path) -> List[Path]:
    exts = {".txt", ".pot", ".potfile", ".lst", ".list", ""}
    files = [p.resolve() for p in directory.rglob("*") if p.suffix.lower() in exts and p.is_file() and p.stat().st_size > 0]
    log.info(f"Found {len(files)} password file(s)")
    return sorted(files)

# =============================================
# MAIN RED-TEAM MINER CLASS
# =============================================
class RedTeamArtifactGenerator:
    def __init__(self, output_dir: Path):
        self.out = output_dir
        self.out.mkdir(parents=True, exist_ok=True)
        self.scored_rules: List[tuple] = []
        self.passwords: List[str] = []

    def add_rule(self, rule: str, score: int):
        if r := rule.strip():
            self.scored_rules.append((score, r))

    def mine_passwords(self, files: Iterable[Path]):
        log.info("Phase 1/3: Mining passwords and affixes...")
        prefix = Counter(); suffix = Counter(); total = 0

        for file in files:
            log.info(f"  → {file.name} ({file.stat().st_size//1048576} MB)")
            with file.open("r", encoding="utf-8", errors="ignore") as f:
                for line in progress(f, desc=file.stem[:30], leave=False):
                    pwd = extract_password(line)
                    if pwd and len(pwd) >= 6:
                        self.passwords.append(pwd)
                        total += 1
                        n = min(6, len(pwd))
                        for i in range(1, n+1):
                            prefix[pwd[:i]] += 1
                            suffix[pwd[-i:]] += 1

        log.info(f"Successfully parsed {total:,} passwords")

        # === Elite affix rules ===
        for affix, cnt in prefix.most_common(1200):
            bonus = min(len(affix), 6) ** 2.8
            self.add_rule("".join(f"^{c}" for c in affix), int(cnt * bonus * 15))
        for affix, cnt in suffix.most_common(1200):
            bonus = min(len(affix), 6) ** 2.8
            self.add_rule("".join(f"${c}" for c in affix), int(cnt * bonus * 15))

        # === Smart surround rules ===
        seen = set()
        for (p, pc) in prefix.most_common(300):
            for (s, sc) in suffix.most_common(300):
                if p != s and len(p) <= 4 and len(s) <= 4:
                    rule = "".join(f"^{c}" for c in p) + "".join(f"${c}" for c in s)
                    if rule not in seen:
                        seen.add(rule)
                        self.add_rule(rule, int((pc + sc) * 10))

        # === 2025 god-tier static rules ===
        killers = [
            ("l c $2 $0 $2 $4 $!", 999999),
            ("l c $2 $0 $2 $5",    999998),
            ("l c $2 $0 $2 $6",    999997),
            ("l c $1 $2 $3 $!",    999990),
            ("l c $!",             950000),
            ("l $!",               940000),
            ("c $!",               930000),
            ("l c $1 $2 $3",       920000),
        ]
        for r, s in killers:
            self.add_rule(r, s)

        for year in [2024,2025,2026,2027,2023,2022]:
            yf, ys = str(year), str(year)[-2:]
            for suf in [yf, ys]:
                self.add_rule(f"l ${suf}",      880000)
                self.add_rule(f"l c ${suf}",    870000)
                self.add_rule(f"l ${suf} $!",   860000)

    def write_rules(self):
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
        log.info("Phase 2/3: Generating 8 red-team artifacts...")

        # 00_real_bases.txt — fastest possible with OS tools
        with tempfile.NamedTemporaryFile(mode="w+", delete=False, encoding="utf-8") as tmp:
            for pwd in self.passwords:
                print(pwd, file=tmp)
            tmp_path = tmp.name

        cmd = f"""
        cat {shlex.quote(tmp_path)} |
        tr '[:upper:]' '[:lower:]' |
        sed -E 's/(202[0-9]|19[0-9][0-9]|[!@#$%^&*]+|[0-9]{{3,}}$)//gI' |
        grep -E '^[a-z]{{4,}}[a-z]*$' |
        sort | uniq -c | sort -nr | head -2000000 |
        awk '{{print $2}}' > "{self.out/'00_real_bases.txt'}"
        """
        subprocess.run(cmd, shell=True, check=True, executable="/bin/bash")
        count = int(subprocess.check_output(f"wc -l < \"{self.out/'00_real_bases.txt'}\"", shell=True).strip())
        log.info(f"  → 00_real_bases.txt ({count:,} bases)")

        # 04_corp_patterns.rule — company names, cities, WiFi, etc.
        corp_words = Counter()
        for pwd in self.passwords:
            words = re.findall(r'[A-Za-z]{5,}', pwd)
            for w in words:
                if any(c.isupper() for c in w) and len(w) >= 5:
                    corp_words[w] += 1
        corp_rules = [f"l c ${w.lower()} $!" for w, c in corp_words.most_common(500)]
        (self.out/"04_corp_patterns.rule").write_text("\n".join(corp_rules)+"\n")
        log.info(f"  → 04_corp_patterns.rule ({len(corp_rules)} rules)")

        # 05_keyboard_walks.rule
        walks = []
        patterns = [r'1qaz', r'qwer', r'asdf', r'zxcv', r'1q2w3e', r'qwerty', r'poiu', r'lkjh']
        for pwd in self.passwords:
            low = pwd.lower()
            for pat in patterns:
                if pat in low or pat[::-1] in low:
                    walks.append(f"l {low}")
        (self.out/"05_keyboard_walks.rule").write_text("\n".join(set(walks))+"\n")
        log.info(f"  → 05_keyboard_walks.rule ({len(set(walks))} walks)")

        # 06_mask_candidates.hcmask
        mask_counter = Counter()
        for pwd in self.passwords:
            mask = "".join("?l" if c.islower() else "?u" if c.isupper() else "?d" if c.isdigit() else "?s" for c in pwd)
            mask_counter[mask] += 1
        top_masks = [f"{mask},{count}" for mask, count in mask_counter.most_common(100)]
        (self.out/"06_mask_candidates.hcmask").write_text("\n".join(top_masks)+"\n")
        log.info(f"  → 06_mask_candidates.hcmask (top 100 masks)")

        # 07_years_seasons.rule
        extras = [f"l ${y}" for y in range(1990, 2031)] + \
                 [f"l c ${s}2025" for s in ["Spring","Summer","Fall","Winter","Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"]]
        (self.out/"07_years_seasons.rule").write_text("\n".join(extras)+"\n")
        log.info(f"  → 07_years_seasons.rule ({len(extras)} rules)")

        # stats.txt
        stats = f"""
Target Analysis Report — {datetime.now().strftime('%Y-%m-%d %H:%M')}
Total passwords parsed: {len(self.passwords):,}
Top suffixes: {', '.join([s for s,_ in suffix.most_common(20)])}
Top prefixes: {', '.join([p for p,_ in prefix.most_common(20)])}
        """
        (self.out/"stats.txt").write_text(stats)
        log.info(f"  → stats.txt")

        Path(tmp_path).unlink(missing_ok=True)
        log.info(f"\nALL DONE! → {self.out.resolve()}")

# =============================================
# CLI
# =============================================
def main():
    parser = argparse.ArgumentParser(description="2025 Ultimate Red-Team Artifact Generator")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-f", "--file", type=Path, help="Single password file")
    group.add_argument("-d", "--dir", type=Path, help="Directory with password files")
    parser.add_argument("-o", "--output", type=Path, default=Path("redteam_artifacts_2025"), help="Output directory")
    args = parser.parse_args()

    files = [args.file] if args.file else find_password_files(args.dir)
    if not files:
        log.error("No files found!")
        sys.exit(1)

    generator = RedTeamArtifactGenerator(args.output)
    generator.mine_passwords(files)
    generator.write_rules()
    generator.generate_all_artifacts()

if __name__ == "__main__":
    main()
