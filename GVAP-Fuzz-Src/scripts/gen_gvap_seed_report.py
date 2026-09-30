#!/usr/bin/env python3
"""Turn QEMU GVAP log lines into a seed report."""
import argparse
import json
from pathlib import Path

MARKS = ("[gvap]", "[gvax]", "[gvay]")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--log", required=True)
    parser.add_argument("--exe", required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--output-md", required=True)
    parser.add_argument("--output-json", required=True)
    args = parser.parse_args()
    text = Path(args.log).read_text(errors="ignore") if Path(args.log).is_file() else ""
    rows = [line for line in text.splitlines() if any(mark in line for mark in MARKS)]
    body = "\n".join("- " + row for row in rows)
    Path(args.output_md).write_text(
        "# %s\n\nExecutable: `%s`\n\n%s\n" % (args.name, args.exe, body or "No GVAP lines."),
        encoding="utf-8")
    Path(args.output_json).write_text(json.dumps(
        {"name": args.name, "exe": args.exe, "gvaps": rows}, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
