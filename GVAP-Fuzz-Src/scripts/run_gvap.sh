#!/usr/bin/env bash
# Unified GVAP miner (two-phase: collect seeds, then validate).
#
# Usage:
#   Phase 1 — collect GVAP seeds:
#     bash run_gvap.sh collect --benchmark <name>
#
#   Phase 2 — validate seed via targeted ISR injection:
#     bash run_gvap.sh validate --benchmark <name> [--site <site>] [--irq <irq>]
#
#   List available benchmarks:
#     bash run_gvap.sh list
#
# Config: ../config/benchmarks.json

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$SCRIPT_DIR/.."
# GVAP_ROOT: root of the benchmark environment that provides config/,
# artifacts/, src/ (watchlists, priorities), and the per-benchmark build
# scripts. Defaults to this repository root; override via the environment.
GVAP_ROOT="${GVAP_ROOT:-$ROOT}"
CONFIG="$GVAP_ROOT/config/benchmarks.json"
PLUGIN_SO="${GVAP_PLUGIN_SO:-$SCRIPT_DIR/../runtime_monitor/qemu/atomicity_plugin_stack.so}"
ARTIFACT_DIR="$GVAP_ROOT/artifacts"
LOG_DIR="$GVAP_ROOT/logs"
RESULT_DIR="$GVAP_ROOT/results"
LD_COMPAT="${LD_COMPAT:-}"
QEMU_BIN="${QEMU_BIN:-qemu-x86_64}"
TIMEOUT="${TIMEOUT:-30}"

# --- helpers ---

cfg_field() {
    local key="$1" field="$2"
    python3 -c "
import json, sys
d = json.load(open('$CONFIG'))
key = sys.argv[1]
field = sys.argv[2]
v = d.get(key, {}).get(field)
if v is not None:
    if isinstance(v, str):
        print(v)
    elif isinstance(v, (list, dict)):
        print(json.dumps(v))
" "$key" "$field"
}

cfg_env() {
    local key="$1" field="$2"
    python3 -c "
import json, sys
d = json.load(open('$CONFIG'))
key = sys.argv[1]
field = sys.argv[2]
env = d.get(key, {}).get(field)
if env:
    for k, v in env.items():
        print(f'{k}={v}')
" "$key" "$field"
}

cfg_exists() {
    local key="$1"
    python3 -c "
import json, sys
d = json.load(open('$CONFIG'))
print('yes' if sys.argv[1] in d else 'no')
" "$key"
}

cfg_list() {
    python3 -c "
import json
d = json.load(open('$CONFIG'))
keys = sorted(k for k in d if not k.startswith('_'))
for k in keys:
    name = d[k].get('name', k)
    print(f'{k:30s}  {name}')
"
}

die() { echo "error: $*" >&2; exit 1; }

# --- commands ---

cmd_list() {
    echo "Available benchmarks (key  display-name)"
    echo "-------------------------------------------"
    cfg_list
    exit 0
}

cmd_collect() {
    local bench="$1"
    local exists; exists=$(cfg_exists "$bench")
    [[ "$exists" != "yes" ]] && die "unknown benchmark '$bench'"

    local name; name=$(cfg_field "$bench" name)
    local exe_name; exe_name=$(cfg_field "$bench" exe)
    local build_script; build_script=$(cfg_field "$bench" build_script)
    local watchlist; watchlist=$(cfg_field "$bench" watchlist)
    local priority; priority=$(cfg_field "$bench" priority)

    local EXE="$ARTIFACT_DIR/$exe_name"
    local META="$ARTIFACT_DIR/$exe_name.meta"
    local RAW_LOG="$LOG_DIR/qemu_collect_gvap_${bench}.log"
    local OUT_MD="$RESULT_DIR/gvap_seed_report_${bench}.md"
    local OUT_JSON="$RESULT_DIR/gvap_seed_report_${bench}.json"

    mkdir -p "$LOG_DIR" "$RESULT_DIR"

    echo "[collect] building $bench..."
    bash "$GVAP_ROOT/scripts/$build_script" >/dev/null

    echo "[collect] copying priority -> priority.txt"
    cp "$GVAP_ROOT/src/$priority" "$ARTIFACT_DIR/priority.txt"

    echo "[collect] generating metadata..."
    python3 "$SCRIPT_DIR/gen_metadata_with_watchlist.py" \
      "$EXE" -o "$META" --watch-file "$GVAP_ROOT/src/$watchlist"

    # Collect extra env vars
    local extra_env=()
    while IFS='=' read -r k v; do
        [[ -n "$k" ]] && extra_env+=("$k=$v")
    done < <(cfg_env "$bench" collect_env)

    echo "[collect] running QEMU (mode=collect_gvap)..."
    env LD_LIBRARY_PATH="$LD_COMPAT${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
        GVAP_COVERAGE_FILE="$RESULT_DIR/gvap_table_${bench}.txt" \
        "${extra_env[@]}" \
      timeout "$TIMEOUT" "$QEMU_BIN" \
        -plugin "$PLUGIN_SO,meta=$META,mode=collect_gvap,report_limit=-1" \
        "$EXE" >"$RAW_LOG" 2>&1

    echo "[collect] generating seed report..."
    python3 "$GVAP_ROOT/scripts/gen_gvap_seed_report.py" \
      --log "$RAW_LOG" \
      --exe "$EXE" \
      --name "$name" \
      --output-md "$OUT_MD" \
      --output-json "$OUT_JSON" >/dev/null

    echo ""
    cat "$OUT_MD"
    echo "[collect] done — report: $OUT_MD"
}

cmd_validate() {
    local bench="$1"
    local site="${SITE:-${2:-}}"
    local irq="${IRQ_NAME:-${3:-}}"
    local exists; exists=$(cfg_exists "$bench")
    [[ "$exists" != "yes" ]] && die "unknown benchmark '$bench'"

    local name; name=$(cfg_field "$bench" name)
    local exe_name; exe_name=$(cfg_field "$bench" exe)
    local build_script; build_script=$(cfg_field "$bench" build_script)
    local watchlist; watchlist=$(cfg_field "$bench" watchlist)
    local priority; priority=$(cfg_field "$bench" priority)

    # If --site/--irq not given, fall back to config defaults
    if [[ -z "$site" ]]; then
        site=$(python3 -c "
import json, sys
d = json.load(open('$CONFIG'))
sites = d.get('$bench', {}).get('phase2', {}).get('sites', [])
print(sites[0] if sites else '')
")
    fi
    if [[ -z "$irq" ]]; then
        irq=$(python3 -c "
import json, sys
d = json.load(open('$CONFIG'))
irqs = d.get('$bench', {}).get('phase2', {}).get('irqs', [])
print(irqs[0] if irqs else '')
")
    fi

    [[ -z "$site" ]] && die "no injection site specified (use --site or set SITE=)"
    [[ -z "$irq" ]] && die "no IRQ name specified (use --irq or set IRQ_NAME=)"

    local EXE="$ARTIFACT_DIR/$exe_name"
    local META="$ARTIFACT_DIR/$exe_name.meta"
    local FILTERED_META="$ARTIFACT_DIR/$exe_name.filtered.meta"
    local RAW_LOG="$LOG_DIR/qemu_validate_gvap_${bench}.log"
    local DEDUP_LOG="$LOG_DIR/qemu_validate_gvap_${bench}.dedup.log"

    mkdir -p "$LOG_DIR" "$RESULT_DIR"

    echo "[validate] building $bench..."
    bash "$GVAP_ROOT/scripts/$build_script" >/dev/null

    echo "[validate] copying priority -> priority.txt"
    cp "$GVAP_ROOT/src/$priority" "$ARTIFACT_DIR/priority.txt"

    echo "[validate] generating metadata..."
    python3 "$SCRIPT_DIR/gen_metadata_with_watchlist.py" \
      "$EXE" -o "$META" --watch-file "$GVAP_ROOT/src/$watchlist"
    python3 "$GVAP_ROOT/scripts/filter_metadata.py" "$META" "$GVAP_ROOT/src/$watchlist" -o "$FILTERED_META"

    # Collect extra env vars
    local extra_env=()
    while IFS='=' read -r k v; do
        [[ -n "$k" ]] && extra_env+=("$k=$v")
    done < <(cfg_env "$bench" phase2_env)

    echo "[validate] site=$site irq=$irq"
    echo "[validate] running QEMU (mode=validate)..."

    env GVAP_INJECT_SITE="$site" \
        GVAP_INJECT_IRQ="$irq" \
        GVAP_COVERAGE_FILE="$RESULT_DIR/gvap_table_${bench}.txt" \
        LD_LIBRARY_PATH="$LD_COMPAT${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
        "${extra_env[@]}" \
      timeout "$TIMEOUT" "$QEMU_BIN" \
        -plugin "$PLUGIN_SO,meta=$FILTERED_META,mode=validate" \
        "$EXE" >"$RAW_LOG" 2>&1

    echo "[validate] deduping..."
    AUTO_REFRESH_REPORTS=0 bash "$GVAP_ROOT/scripts/dedupe_qemu_log.sh" "$RAW_LOG" "$DEDUP_LOG" >/dev/null

    echo ""
    cat "$DEDUP_LOG"
    echo "[validate] done — dedup log: $DEDUP_LOG"
}

# --- main ---

action="${1:-help}"
shift 2>/dev/null || true

case "$action" in
    collect)
        bench=""
        while [[ $# -gt 0 ]]; do
            case "$1" in
                --benchmark) bench="$2"; shift 2 ;;
                *) die "unknown option: $1" ;;
            esac
        done
        [[ -z "$bench" ]] && die "usage: run_gvap.sh collect --benchmark <name>"
        cmd_collect "$bench"
        ;;
    validate)
        bench=""; site=""; irq=""
        while [[ $# -gt 0 ]]; do
            case "$1" in
                --benchmark) bench="$2"; shift 2 ;;
                --site) site="$2"; shift 2 ;;
                --irq) irq="$2"; shift 2 ;;
                *) die "unknown option: $1" ;;
            esac
        done
        [[ -z "$bench" ]] && die "usage: run_gvap.sh validate --benchmark <name> [--site <site>] [--irq <irq>]"
        cmd_validate "$bench" "$site" "$irq"
        ;;
    list)
        cmd_list
        ;;
    help|--help|-h)
        echo "Usage:"
        echo "  run_gvap.sh collect   --benchmark <name>    Phase 1: collect GVAP seeds"
        echo "  run_gvap.sh validate  --benchmark <name>    Phase 2: validate via ISR injection"
        echo "                       [--site <site>] [--irq <irq>]"
        echo "  run_gvap.sh list                             List available benchmarks"
        echo ""
        echo "Or set env vars: GVAP_ROOT= GVAP_PLUGIN_SO= SITE= IRQ_NAME= TIMEOUT= LD_COMPAT= QEMU_BIN="
        ;;
    *)
        die "unknown action '$action'. Use: collect | validate | list"
        ;;
esac
