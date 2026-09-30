#!/usr/bin/env python3
"""Keep VAR rows named by the watchlist. FUNC rows stay so call context still resolves."""
import argparse
from pathlib import Path


def roots(path):
    names = set()
    if not path or not Path(path).is_file():
        return names
    for raw in Path(path).read_text(errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        names.add(line.split("+", 1)[0].strip())
        if ":" in line:
            alias = line.split(":")[-1].strip()
            if alias:
                names.add(alias)
    return names


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("meta")
    parser.add_argument("watch")
    parser.add_argument("-o", "--output", required=True)
    args = parser.parse_args()
    keep = roots(args.watch)
    out = []
    for raw in Path(args.meta).read_text(errors="ignore").splitlines():
        if not raw or raw.startswith("#") or raw.startswith("FUNC"):
            out.append(raw)
            continue
        parts = raw.split("\t")
        if parts[0] != "VAR" or len(parts) < 4:
            continue
        names = {parts[3]}
        if len(parts) > 4 and parts[4]:
            names.add(parts[4])
        if not keep or names & keep:
            out.append(raw)
    Path(args.output).write_text("\n".join(out) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
