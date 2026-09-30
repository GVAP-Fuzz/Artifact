#!/usr/bin/env python3
import argparse
import os
from pathlib import Path

TID_MAIN = -1
TID_INHERIT = -2


def parse_int(text):
    return int(text.strip(), 0)


def load_priorities(path):
    tasks, priorities = {}, {}
    if not path or not Path(path).is_file():
        return tasks, priorities
    for raw in Path(path).read_text(errors="ignore").splitlines():
        parts = raw.split()
        if len(parts) < 2 or parts[0].startswith("#"):
            continue
        tasks[parts[0]] = int(parts[1], 0)
        priorities[parts[0]] = int(parts[2], 0) if len(parts) >= 3 else 0
    return tasks, priorities


def parse_nm(exe, keep_vars):
    """nm text only. Sizes stay 1; that is not a full range recovery."""
    funcs, nm_vars = [], {}
    for line in os.popen("nm -n %s 2>/dev/null" % exe).read().splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        try:
            addr = int(parts[0], 16)
        except ValueError:
            continue
        kind, name = parts[1], parts[-1]
        if kind in "Tt":
            funcs.append((addr, 1, name))
        elif name in (keep_vars or ()) and kind in "BbDd":
            nm_vars[name] = (addr, 1)
    return funcs, nm_vars


def collect_var_entries(exe, keep_vars=None, wanted_roots=None):
    _, nm_vars = parse_nm(exe, keep_vars or set())
    for name in wanted_roots or []:
        if name in nm_vars:
            yield nm_vars[name][0], nm_vars[name][1], name


def emit_func_metadata(lines, funcs, tasks, priorities, include_inherit=True,
                       tid_main=TID_MAIN, tid_inherit=TID_INHERIT):
    for addr, size, name in funcs:
        tid = tasks.get(name, tid_inherit if include_inherit else tid_main)
        lines.append("FUNC\t0x%x\t0x%x\t%s\t%d\t%d" % (
            addr, size, name, tid, priorities.get(name, 0)))


def load_watch_specs(path):
    plain, fields = set(), []
    if path is None:
        return plain, fields
    for raw in Path(path).read_text(errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "+" in line and ":" in line:
            base, rest = line.split("+", 1)
            parts = [part.strip() for part in rest.split(":", 2)]
            try:
                offset, size = parse_int(parts[0]), parse_int(parts[1])
            except (ValueError, IndexError):
                plain.add(line)
                continue
            alias = parts[2] if len(parts) >= 3 and parts[2] else "%s+0x%x" % (base.strip(), offset)
            fields.append({"base": base.strip(), "offset": offset, "size": size, "name": alias})
        else:
            plain.add(line)
    return plain, fields


def emit_metadata(exe, out_path, watch_file, priority_file=None):
    exe = Path(exe)
    plain_watch, field_watch = load_watch_specs(watch_file)
    keep_vars = plain_watch | {spec["base"] for spec in field_watch}
    priority_path = Path(priority_file) if priority_file else exe.parent / "priority.txt"
    tasks, priorities = load_priorities(priority_path)
    funcs, nm_vars = parse_nm(exe, keep_vars)
    lines = ["# executable\t%s" % exe,
             "# VAR\tstart\tsize\tvar\tfield",
             "# FUNC\tstart\tsize\tname\ttid\tpriority"]
    seen = set()
    for addr, size, name in collect_var_entries(exe, keep_vars=keep_vars, wanted_roots=plain_watch):
        line = "VAR\t0x%x\t0x%x\t%s" % (addr, size, name)
        if line not in seen:
            seen.add(line)
            lines.append(line)
    for spec in field_watch:
        if spec["base"] not in nm_vars:
            continue
        base_addr, base_size = nm_vars[spec["base"]]
        if spec["offset"] < 0 or spec["size"] <= 0 or spec["offset"] + spec["size"] > base_size:
            continue
        line = "VAR\t0x%x\t0x%x\t%s\t%s" % (
            base_addr + spec["offset"], spec["size"], spec["base"], spec["name"])
        if line not in seen:
            seen.add(line)
            lines.append(line)
    emit_func_metadata(lines, funcs, tasks, priorities, include_inherit=True,
                       tid_main=TID_MAIN, tid_inherit=TID_INHERIT)
    out_path.write_text("\n".join(lines) + "\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("executable")
    parser.add_argument("-o", "--output", required=True)
    parser.add_argument("--watch-file")
    parser.add_argument("--priority-file")
    args = parser.parse_args()
    emit_metadata(args.executable, Path(args.output), args.watch_file, args.priority_file)


if __name__ == "__main__":
    main()
