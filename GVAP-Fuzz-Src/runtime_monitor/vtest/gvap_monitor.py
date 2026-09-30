# GVAP-Fuzz runtime monitor (VTest platform, MCS-51).
# GVA = <Var, Field, AccessLoc, AccessType, CallCtx>; CallCtx lists <CallLoc, FuncLoc>.
# GVAP = <GVAx -> GVAy, Dist>. Formula 5: Dist(GVAx, GVAy) <= tau.
# TAU = 120, derived from the empirical study with a 50% margin over the
# maximum observed distance of about 80 instructions. Unseen GVAP paints the bitmap.

import hashlib
import json
import os
from collections import namedtuple

TAU = 120
CallInfo = namedtuple("CallInfo", "call_loc func_loc")
GVA = namedtuple("GVA", "var field access_loc access_type call_ctx")


def _gva(ev):
    ctx = []
    for item in ev.get("call_ctx") or []:
        if isinstance(item, dict):
            ctx.append(CallInfo(item.get("call_loc"), item.get("func_loc")))
    return GVA(ev.get("var") or "", ev.get("field") or "", ev.get("access_loc"),
               ev.get("access_type"), tuple(ctx))


def _dict(gva):
    return {"var": gva.var, "field": gva.field, "access_loc": gva.access_loc,
            "access_type": gva.access_type,
            "call_ctx": [{"call_loc": c.call_loc, "func_loc": c.func_loc} for c in gva.call_ctx]}


class Monitor:
    def __init__(self):
        self.seen, self.table, self.patterns, self.new, self.open = set(), [], [], [], []
        self.enabled = self.seg_ctx = self.seg_irq = None
        self.once = set()

    def reset_execution(self):
        self.open, self.new, self.once = [], [], set()
        self.seg_ctx = self.seg_irq = None

    def on_access(self, ev):
        """Pair related accesses in one execution context. An interrupt boundary clears the segment."""
        if isinstance(ev.get("enabled_interrupts"), list):
            self.enabled = ev["enabled_interrupts"]
        gva = _gva(ev)
        ctx, irq = ev.get("exec_ctx") or "normal", ev.get("irq") or ""
        if ev.get("irq_boundary") or ctx != self.seg_ctx or irq != self.seg_irq:
            self.open, self.seg_ctx, self.seg_irq = [], ctx, irq
        icount = int(ev.get("icount") or 0)
        # ponytail: whole open segment, O(n^2); window it if traces get long.
        for prev, picount in self.open:
            dist = icount - picount
            if prev.var != gva.var or not prev.var or dist <= 0 or dist > TAU:
                continue
            xd, yd = _dict(prev), _dict(gva)
            digest = int(hashlib.sha1(json.dumps([xd, yd, dist], sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:8], 16)
            token = ((xd["var"], xd["field"], yd["var"], yd["field"]),
                     "%s:%s>%s:%s" % (xd["access_loc"], xd["access_type"], yd["access_loc"], yd["access_type"]), ctx)
            if token not in self.once:
                self.once.add(token)
                key = list(token[0])
                for row in self.patterns:
                    if row["key"] == key and row["order"] == token[1] and row["ctx"] == ctx and row.get("irq", "") == irq:
                        row["count"] += 1
                        break
                else:
                    self.patterns.append({"key": key, "order": token[1], "ctx": ctx, "irq": irq, "count": 1})
            if digest not in self.seen and all(item["hash"] != digest for item in self.new):
                self.new.append({"hash": digest, "x": xd, "y": yd, "dist": dist,
                                 "exec_ctx": {"exec_ctx": ctx, "irq": irq, "priority": int(ev.get("priority") or 0)}})
        self.open.append((gva, icount))

    def has_unseen(self):
        return bool(self.new)

    def paint(self, bitmap):
        """Paint each unseen GVAP into the shared-memory bitmap."""
        size = len(bitmap)
        for item in self.new:
            if size:
                bitmap[item["hash"] % size] = 1

    def shortest_new(self):
        return min((item["dist"] for item in self.new), default=10 ** 9)

    def commit_interesting(self, path, subname):
        for item in self.new:
            self.seen.add(item["hash"])
            self.table.append({"input": path, "subname": subname,
                               "gvap": {"x": item["x"], "y": item["y"], "dist": item["dist"]},
                               "exec_ctx": item["exec_ctx"]})
        self.new = []

    def save(self, output_dir):
        if not output_dir:
            return
        os.makedirs(output_dir, exist_ok=True)
        for name, obj in (("gvap_table.json", self.table), ("gvap_patterns.json", self.patterns)):
            with open(os.path.join(output_dir, name), "w", encoding="utf-8") as handle:
                json.dump(obj, handle)
                handle.write("\n")
        if self.enabled is not None:
            with open(os.path.join(output_dir, "enabled_interrupts.json"), "w", encoding="utf-8") as handle:
                json.dump(self.enabled, handle)
                handle.write("\n")

    @staticmethod
    def pick_index(entries, cursor):
        """Unfuzzed seeds first, then the shorter dynamic instruction distance."""
        pending = [i for i, (done, _) in enumerate(entries) if not done]
        pool = pending or list(range(len(entries)))
        best = min(entries[i][1] for i in pool)
        cands = [i for i in pool if entries[i][1] == best]
        return cands[cursor % len(cands)]


MONITOR = Monitor()
