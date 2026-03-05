#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
potlist.py — Master Password List Generator

Reads all potfiles (single files, multiple files, or directories) and creates
a deduplicated master list of the actual passwords that were cracked.

Uses the same potfile reading logic as listminer.py.
"""

import argparse
import logging
import re
import sys
from pathlib import Path
from typing import List

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

# =============================================
# Password decoding (matches listminer.py)
# =============================================
HEX_BRACKET_RE = re.compile(r'\$HEX\[[0-9a-fA-F]+\]')
HEX_ESCAPE_RE = re.compile(r'\\x[0-9a-fA-F]{2}')


def decode_plaintext(text: str) -> str:
    r"""Decode $HEX[...] and \xHH sequences (matches listminer.py)."""
    if not text:
        return ""
    if text.startswith("$HEX[") and text.endswith("]"):
        try:
            return bytes.fromhex(text[5:-1]).decode("latin-1")
        except ValueError:
            return ""
    return HEX_ESCAPE_RE.sub(lambda m: chr(int(m.group(0)[2:], 16)), text)


def extract_password_from_pot(line: str) -> str:
    """Extract the plaintext password from a potfile line (hash:password format)."""
    line = line.strip()
    if not line or line.startswith("#"):
        return ""
    return decode_plaintext(line.rsplit(":", 1)[-1])


# =============================================
# File discovery (matches listminer.py)
# =============================================
def find_files(paths: List[str]) -> List[Path]:
    """Recursively find all non-empty files in the given paths."""
    out = []
    for p in paths:
        ppath = Path(p).expanduser()
        if ppath.is_dir():
            out.extend(ppath.rglob("*"))
        elif ppath.is_file():
            out.append(ppath)
    return sorted([f for f in out if f.is_file() and f.stat().st_size > 0])


# =============================================
# Potfile parsing
# =============================================
def parse_potfile(path: Path) -> List[str]:
    """Parse a single potfile and return the list of cracked passwords."""
    passwords = []
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                pwd = extract_password_from_pot(line)
                if pwd:
                    passwords.append(pwd)
    except OSError as e:
        log.warning(f"Could not read {path}: {e}")
    return passwords


def collect_passwords(pot_files: List[Path]) -> List[str]:
    """Read all potfiles and return a deduplicated, sorted list of passwords."""
    seen: set = set()
    total_lines = 0

    for pot_path in pot_files:
        log.info(f"Reading potfile: {pot_path}")
        passwords = parse_potfile(pot_path)
        total_lines += len(passwords)
        seen.update(passwords)

    unique_passwords = sorted(seen)
    log.info(
        f"Collected {total_lines:,} password entries; "
        f"{len(unique_passwords):,} unique passwords."
    )
    return unique_passwords


# =============================================
# Main
# =============================================
def main():
    parser = argparse.ArgumentParser(
        description=(
            "potlist — Master Password List Generator\n"
            "Reads potfiles and writes a deduplicated master list of cracked passwords."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-p", "--pot",
        nargs="+",
        required=True,
        metavar="POT",
        help="Potfile(s) or directory of potfiles (required)",
    )
    parser.add_argument(
        "-o", "--output",
        type=Path,
        default=Path("cracked_passwords.txt"),
        metavar="OUTPUT",
        help="Output file for the master password list (default: cracked_passwords.txt)",
    )
    args = parser.parse_args()

    pot_files = find_files(args.pot)
    if not pot_files:
        log.error("No potfiles found. Exiting.")
        sys.exit(1)

    log.info(f"Found {len(pot_files)} potfile(s).")
    passwords = collect_passwords(pot_files)

    if not passwords:
        log.warning("No passwords extracted from potfiles.")
        sys.exit(0)

    output_path: Path = args.output
    output_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with output_path.open("w", encoding="utf-8") as f:
            f.write("\n".join(passwords) + "\n")
        log.info(f"Master password list written to: {output_path} ({len(passwords):,} passwords)")
    except OSError as e:
        log.error(f"Failed to write output file: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
