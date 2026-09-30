# GVAP-Fuzz interrupt controller (VTest platform, MCS-51).
# Feasible interrupt set: enabled and serviceable; nested interrupts only if priority is higher.
# Precise injection after GVAx. Candidate atomicity violation must recur inside Dist+delta.

import json
import os

DELTA = 8


def load_json(path, default):
    if not path or not os.path.isfile(path):
        return default
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def load_enabled(path):
    return load_json(path, [])


def feasible_interrupt_set(ctx, enabled):
    ctx = ctx or {}
    chosen = []
    for irq in enabled or []:
        name = irq.get("name")
        if not name or not irq.get("enabled", True) or not irq.get("can_service", True):
            continue
        if ctx.get("exec_ctx") == "handler" and (
            name == ctx.get("irq") or int(irq.get("priority") or 0) <= int(ctx.get("priority") or 0)):
            continue
        chosen.append(name)
    return chosen


def same_gva(access, gva):
    gva = gva or {}
    return access.get("var") == gva.get("var") and (access.get("field") or "") == (gva.get("field") or "") and \
        access.get("access_loc") == gva.get("access_loc") and access.get("access_type") == gva.get("access_type")


def same_context(access, ctx):
    ctx = ctx or {}
    if (access.get("exec_ctx") or "normal") != (ctx.get("exec_ctx") or "normal"):
        return False
    return access.get("irq") == ctx.get("irq") if ctx.get("exec_ctx") == "handler" and ctx.get("irq") else True


def _stable(patterns, gvap, ctx):
    x, y = gvap.get("x") or {}, gvap.get("y") or {}
    key = [x.get("var"), x.get("field") or "", y.get("var"), y.get("field") or ""]
    order = "%s:%s>%s:%s" % (x.get("access_loc"), x.get("access_type"), y.get("access_loc"), y.get("access_type"))
    ctx = ctx or {}
    for row in patterns or []:
        if row.get("key") != key or row.get("order") != order or row.get("count", 0) < 2:
            continue
        if same_context({"exec_ctx": row.get("ctx") or "normal", "irq": row.get("irq")}, ctx):
            return True
    return False


def _fields_cooccur(patterns, gvap, ctx):
    """Multi-variable: different fields of one structure recur together."""
    x, y = gvap.get("x") or {}, gvap.get("y") or {}
    if (x.get("field") or "") == (y.get("field") or ""):
        return True
    return bool(x.get("var")) and x.get("var") == y.get("var") and _stable(patterns, gvap, ctx)


def inject_all(table, enabled, patterns, output_dir, replay_until, trigger, collect_handler_accesses, resume_and_watch):
    """Algorithm 1. replay_until is true only after GVAx under the same execution context."""
    reports = []
    for row in table or []:
        ctx, gvap = row.get("exec_ctx") or {}, row.get("gvap") or {}
        dist = int(gvap.get("dist") or 0)
        for irq in feasible_interrupt_set(ctx, enabled):
            if not replay_until(row):
                continue
            trigger(irq)

            def _hit(acc, gva):
                gva = gva or {}
                return (acc.get("var") and acc.get("var") == gva.get("var")) or (
                    bool(gva.get("field")) and acc.get("field") == gva.get("field"))

            hit = next((acc for acc in collect_handler_accesses()
                        if _hit(acc, gvap.get("x")) or _hit(acc, gvap.get("y"))), None)
            gy = next((acc for acc in resume_and_watch(dist + DELTA) if same_gva(acc, gvap.get("y"))), None)
            if hit is None or gy is None or not _stable(patterns, gvap, ctx) or not _fields_cooccur(patterns, gvap, ctx):
                continue
            xf, yf = (gvap.get("x") or {}).get("field") or "", (gvap.get("y") or {}).get("field") or ""
            reports.append({"input": row.get("input"), "subname": row.get("subname"), "gvap": gvap,
                            "exec_ctx": ctx, "interrupt": irq, "handler_access": hit,
                            "kind": "multi-variable" if xf != yf else "single-variable"})
    if output_dir is not None:
        os.makedirs(output_dir, exist_ok=True)
        with open(os.path.join(output_dir, "atomicity_violations.json"), "w", encoding="utf-8") as handle:
            json.dump(reports, handle)
            handle.write("\n")
    return reports


def _selfcheck():
    enabled = [{"name": "INT0", "priority": 0, "enabled": True, "can_service": True},
               {"name": "INT1", "priority": 1, "enabled": True, "can_service": True}]
    assert feasible_interrupt_set({"exec_ctx": "normal"}, enabled) == ["INT0", "INT1"]
    assert feasible_interrupt_set({"exec_ctx": "handler", "irq": "INT0", "priority": 0}, enabled) == ["INT1"]
    cur = {}

    def replay_until(row):
        cur.clear()
        cur.update(row)
        return bool(row.get("input"))

    def trigger(irq):
        cur["fired"] = irq

    def collect_handler_accesses():
        return list(cur.get("handler_accesses") or [])

    def resume_and_watch(limit):
        return [acc for acc in (cur.get("watch") or []) if int(acc.get("icount") or 0) <= limit]

    table = [{"input": "seed.json",
              "gvap": {"dist": 4,
                       "x": {"var": "dev", "field": "a", "access_loc": "f:1", "access_type": "W"},
                       "y": {"var": "dev", "field": "b", "access_loc": "f:2", "access_type": "R"}},
              "exec_ctx": {"exec_ctx": "normal"},
              "handler_accesses": [{"var": "dev", "field": "a"}],
              "watch": [{"var": "dev", "field": "b", "access_loc": "f:2", "access_type": "R", "icount": 4}]}]
    patterns = [{"key": ["dev", "a", "dev", "b"], "order": "f:1:W>f:2:R", "ctx": "normal", "count": 2}]
    found = inject_all(table, enabled, patterns, None, replay_until, trigger, collect_handler_accesses, resume_and_watch)
    assert len(found) == 2 and all(item["kind"] == "multi-variable" for item in found)
    patterns[0]["count"] = 1
    assert inject_all(table, enabled, patterns, None, replay_until, trigger, collect_handler_accesses, resume_and_watch) == []


def main(argv=None):
    import argparse
    import sys
    _selfcheck()
    parser = argparse.ArgumentParser(description="Algorithm 1 GVAP-aware interrupt injection")
    parser.add_argument("--table", default="gvap_table.json")
    parser.add_argument("--enabled", default="enabled_interrupts.json")
    parser.add_argument("--patterns", default="gvap_patterns.json")
    parser.add_argument("-o", "--output", default=".")
    parser.add_argument("--inject", action="store_true", help="same phase-2 entry as the VTest driver")
    args = parser.parse_args(argv)
    argv = sys.argv if argv is None else argv
    if args.inject and any(flag in argv for flag in ("-i", "--input", "-D", "--DTP")):
        from gvap_vtest_plugin import inject_main
        inject_main()
        return 0
    table = load_json(args.table, [])
    if not table:
        print("gvap_injection ok")
        return 0
    cur = {}

    def replay_until(row):
        cur.clear()
        cur.update(row)
        return bool(row.get("input"))

    def trigger(irq):
        cur["fired"] = irq

    def collect_handler_accesses():
        return list(cur.get("handler_accesses") or [])

    def resume_and_watch(limit):
        return [acc for acc in (cur.get("watch") or []) if int(acc.get("icount") or 0) <= limit]

    inject_all(table, load_enabled(args.enabled), load_json(args.patterns, []), args.output,
               replay_until, trigger, collect_handler_accesses, resume_and_watch)
    print("gvap_injection ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
