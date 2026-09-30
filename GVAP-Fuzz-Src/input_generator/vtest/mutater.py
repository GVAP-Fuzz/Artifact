# GVAP-Fuzz input generator (VTest platform).
# Data mutation edits packet content. Order mutation inserts, deletes, reorders, and changes the delivery interval.
# A SUM or XOR checksum is recomputed after a content mutation.

import copy
import json
import os
import random

# ponytail: 16 mutants per content stage; raise the cap for a full walk.
CAP = 16
INTERVALS = ("0", "1", "-1", "100")


def _payload(path):
    body, kind = bytearray(), None
    for tok in open(path, encoding="utf-8", errors="replace").read().split():
        if tok in ("SUM", "XOR"):
            kind = tok
            break
        body.append(int(tok, 16) & 0xFF)
    return body, kind


def _checksum(body, kind):
    if kind == "XOR":
        value = 0
        for byte in body:
            value ^= byte
        return value
    return sum(body) & 0xFF


def _store(src, body, kind, tag, n):
    path = src[:-4] + "_mutated_%s_%d.txt" % (tag, n)
    parts = ["%02X" % byte for byte in body]
    if kind:
        parts.extend((kind, "%02X" % _checksum(body, kind)))
    open(path, "w", encoding="utf-8").write(" ".join(parts) + "\n")


def _each(path, tag, edit):
    body, kind = _payload(path)
    for n, trial in enumerate(edit(body)):
        if n >= CAP or not body:
            break
        _store(path, trial, kind, tag, n)


def mutate_bitflip(path):
    _each(path, "bitflip", lambda body: (body[:i] + bytes([(body[i] ^ 1)]) + body[i + 1:] for i in range(len(body))))


def mutate_arithmetic(path):
    _each(path, "arith", lambda body: (body[:i] + bytes([((body[i] + 1 + (i % 35)) & 0xFF)]) + body[i + 1:] for i in range(len(body))))


def mutate_interest(path):
    _each(path, "interest", lambda body: (body[:i] + bytes([value]) + body[i + 1:]
                                          for i in range(len(body)) for value in (0x00, 0x01, 0x7F, 0x80, 0xFF)))


def random_havoc(path):
    body, kind = _payload(path)
    if not body:
        return
    rng = random.Random(len(body) * 17 + body[0])
    width = len(body) if len(body) < 4 else 4
    for n in range(min(CAP, len(body))):
        nxt = bytearray(body)
        start = rng.randrange(len(nxt))
        for j in range(width):
            index = (start + j) % len(nxt)
            nxt[index] = ((nxt[index] ^ (1 << rng.randrange(8))) + rng.randrange(1, 36)) & 0xFF
        _store(path, nxt, kind, "havoc", n)


def _component(tc):
    for item in tc["TestCases"][0]["Items"]:
        name = item.get("ComponentName")
        if name:
            return name
    return ""


def change_cmd_id_and_CANType(tc):
    name = _component(tc)
    out = copy.deepcopy(tc)
    for item in out["TestCases"][0]["Items"]:
        if name and item.get("ComponentName") != name:
            continue
        if len(item.get("Arguments") or []) <= 3:
            continue
        item["Arguments"][1] = str(random.randrange(256))
        item["Arguments"][3] = "A" if random.randrange(3) == 1 else "B"
    return out, out["TestCases"][0]["Code"]


def _write(tc, filename, out_dir, tag):
    directory = os.path.join(out_dir, "queue3")
    os.makedirs(directory, exist_ok=True)
    stem = filename[:-5] if filename.lower().endswith(".json") else filename
    path = os.path.join(directory, "%s_mutated_%s.json" % (stem, tag))
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(tc, handle)
        handle.write("\n")
    return path


def _cmds(tc):
    name = _component(tc)
    items = tc["TestCases"][0]["Items"]
    if not name:
        return list(range(len(items)))
    return [i for i, item in enumerate(items) if item.get("ComponentName") == name]


def changetime(tc, filename, out_dir):
    paths = []
    for index in _cmds(tc):
        if not tc["TestCases"][0]["Items"][index].get("Arguments"):
            continue
        for gap in INTERVALS:
            out = copy.deepcopy(tc)
            out["TestCases"][0]["Items"][index]["Arguments"][0] = gap
            paths.append(_write(out, filename, out_dir, "interval_%d_%s" % (index, gap)))
            if len(paths) >= CAP:
                return paths
    return paths


def discordcommand(tc, filename, out_dir):
    paths = []
    for n, index in enumerate(_cmds(tc)):
        out = copy.deepcopy(tc)
        del out["TestCases"][0]["Items"][index]
        paths.append(_write(out, filename, out_dir, "delete_%d" % n))
        if len(paths) >= CAP:
            break
    return paths


def swapsequence(tc, filename, out_dir):
    out = copy.deepcopy(tc)
    idxs = _cmds(out)
    if len(idxs) < 2:
        return []
    items = out["TestCases"][0]["Items"]
    seq = [items[i] for i in idxs]
    seq = seq[1:] + seq[:1]
    for index, item in zip(idxs, seq):
        items[index] = item
    return [_write(out, filename, out_dir, "reorder")]


def insert_packet(tc, filename, out_dir):
    name = _component(tc)
    out = copy.deepcopy(tc)
    items = out["TestCases"][0]["Items"]
    idxs = _cmds(out)
    if not items or not idxs:
        return []
    at = idxs[len(idxs) // 2]
    sample = items[at]
    fresh = {"ComponentName": name or sample.get("ComponentName") or "",
             "Arguments": ["1"] + list(sample.get("Arguments") or [])[1:]}
    items.insert(at, fresh)
    return [_write(out, filename, out_dir, "insert")]


if __name__ == "__main__":
    import tempfile
    td = tempfile.mkdtemp()
    src = os.path.join(td, "a.txt")
    open(src, "w", encoding="utf-8").write("01 02 SUM 00\n")
    random_havoc(src)
    tc = {"TestCases": [{"Items": [
        {"ComponentName": "UART", "Arguments": ["0", "1", "2", "3", "4"]},
        {"ComponentName": "UART", "Arguments": ["1", "9", "8", "7", "6"]}],
        "Code": "c"}]}
    deleted = json.load(open(discordcommand(tc, "a.json", td)[0], encoding="utf-8"))
    assert len(deleted["TestCases"][0]["Items"]) == 1
    rotated = json.load(open(swapsequence(tc, "a.json", td)[0], encoding="utf-8"))
    assert rotated["TestCases"][0]["Items"][0]["Arguments"][1] == "9"
    inserted = json.load(open(insert_packet(tc, "a.json", td)[0], encoding="utf-8"))
    assert len(inserted["TestCases"][0]["Items"]) == 3
    assert inserted["TestCases"][0]["Items"][1]["ComponentName"] == "UART"
    print("mutater ok")
