#!/usr/bin/env python3
#Use this with the ListMiner output of 03_complete_phrase.rule
#python hc_rule_to_phrases.py 03_complete_phrase.rule --ignore-empty --sort --uniq -o phrases.txt

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Iterable, List, Optional, Tuple


def normalize_rule_line(line: str) -> str:
    return "".join(ch for ch in line if not ch.isspace())


def is_pure_prepend_append(rule: str) -> bool:
    """
    True if rule contains ONLY sequences of ^x and/or $x (no other operators).
    Examples:
      ^r^e^m^m^u^S      -> True
      $2$0$1$7          -> True
      ^S$2$0$2$6        -> True
      c^!^!             -> False  (has 'c')
      l$1$2             -> False  (has 'l')
      ss$so0$5...       -> False  (has 's','o',etc)
    """
    i = 0
    n = len(rule)
    while i < n:
        if rule[i] in ("^", "$"):
            if i + 1 >= n:
                return False  # dangling ^ or $
            i += 2
            continue
        return False
    return True


def extract_phrase(rule: str) -> str:
    """
    Extract the literal phrase implied by ^x/$x tokens.

    ^a^b^c => "cba"  (prepends stack)
    $1$2$3 => "123"
    """
    i = 0
    out_parts: List[str] = []

    while i < len(rule):
        c = rule[i]

        if c == "^":
            chars: List[str] = []
            while i < len(rule) and rule[i] == "^":
                chars.append(rule[i + 1])
                i += 2
            out_parts.append("".join(reversed(chars)))
            continue

        if c == "$":
            chars: List[str] = []
            while i < len(rule) and rule[i] == "$":
                chars.append(rule[i + 1])
                i += 2
            out_parts.append("".join(chars))
            continue

        # if caller used is_pure_prepend_append first, we shouldn't get here
        i += 1

    return "".join(out_parts)


def iter_noncomment_lines(path: Path) -> Iterable[Tuple[int, str]]:
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line_no, raw in enumerate(f, 1):
            line = raw.rstrip("\n")
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            yield line_no, line


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Extract literal phrases from hashcat rules.")
    ap.add_argument("rulefile", type=Path)
    ap.add_argument("--sort", action="store_true")
    ap.add_argument("--uniq", action="store_true")
    ap.add_argument("--ignore-empty", action="store_true")
    ap.add_argument(
        "--include-mixed",
        action="store_true",
        help="Also extract ^/$ literals from mixed rules (default is pure-only).",
    )
    ap.add_argument("-o", "--output", type=Path, default=None)
    args = ap.parse_args(argv)

    phrases: List[str] = []
    for _, raw_line in iter_noncomment_lines(args.rulefile):
        rule = normalize_rule_line(raw_line)

        if not args.include_mixed and not is_pure_prepend_append(rule):
            phrase = ""
        else:
            phrase = extract_phrase(rule)

        if phrase or not args.ignore_empty:
            phrases.append(phrase)

    if args.uniq:
        seen = set()
        deduped: List[str] = []
        for p in phrases:
            if p in seen:
                continue
            seen.add(p)
            deduped.append(p)
        phrases = deduped

    if args.sort:
        phrases.sort()

    rendered = "\n".join(phrases)
    if args.output:
        args.output.write_text(rendered + ("\n" if rendered and not rendered.endswith("\n") else ""), encoding="utf-8")
    else:
        print(rendered)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
