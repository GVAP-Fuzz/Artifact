/* GVAP-Fuzz runtime monitor (QEMU TCG plugin).
 * Formula 5: Dist(GVAx, GVAy) <= tau. GVAP_DIST_THRESHOLD = 120, derived from
 * the empirical study with a 50% margin over the maximum observed distance
 * of about 80 instructions. Calling context is the function stack.
 * A GVAP is two accesses of one variable, or of different fields of one
 * structure, in the same execution context. Interrupt entry and return break
 * that pairing. mode=validate watches GVAy for Dist+delta instructions. */
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

#define MAX_VARS 4096
#define MAX_FUNCS 4096
#define MAX_NAME 128
#define MAX_VCPUS 64
#define MAX_STACK 64
#define TID_MAIN (-1)
#define TID_INHERIT (-2)
#define GVAP_DELTA 8

typedef struct {
    int tid, op;
    uint64_t icount, pc;
    int anchor;
    uint32_t epoch;
} access_record_t;

typedef struct {
    uint64_t start, end;
    char name[MAX_NAME];
    char base[MAX_NAME];
    char field[MAX_NAME];
    access_record_t hist[3];
    int hist_len;
    access_record_t last_main;
    bool has_last_main;
} watched_var_t;

typedef struct {
    uint64_t start, end;
    int tid, priority;
    char name[MAX_NAME];
} func_range_t;

typedef struct {
    int func_index, tid;
    uint64_t start, end;
} frame_t;

typedef struct {
    int tid, anchor, stack_len, in_irq;
    uint64_t last_main_pc, interrupt_pc;
    uint32_t epoch;
    frame_t stack[MAX_STACK];
} vcpu_state_t;

static watched_var_t vars[MAX_VARS];
static func_range_t funcs[MAX_FUNCS];
static vcpu_state_t vcpu_states[MAX_VCPUS];
static size_t n_vars, n_funcs;
static uint64_t insn_count, gvap_pair_count, report_count;
#define GVAP_DIST_THRESHOLD 120
static uint64_t gvap_dist_threshold = GVAP_DIST_THRESHOLD;
static bool mode_collect_gvap, mode_validate, watching;
static uint64_t watch_from, inject_dist;
static char inject_site[MAX_NAME];

typedef struct {
    uint64_t pc;
    int func_index;
} insn_info_t;

static void split_name(const char *name, const char *field_tok, char *base, char *field)
{
    const char *arrow, *dot;
    size_t n;
    if (field_tok && *field_tok) {
        snprintf(base, MAX_NAME, "%s", name ? name : "");
        snprintf(field, MAX_NAME, "%s", field_tok);
        return;
    }
    arrow = name ? strstr(name, "->") : NULL;
    dot = name ? strrchr(name, '.') : NULL;
    if (arrow && (!dot || arrow > dot)) {
        n = (size_t)(arrow - name);
        if (n >= MAX_NAME)
            n = MAX_NAME - 1;
        memcpy(base, name, n);
        base[n] = 0;
        snprintf(field, MAX_NAME, "%s", arrow + 2);
        return;
    }
    if (dot && dot != name) {
        n = (size_t)(dot - name);
        if (n >= MAX_NAME)
            n = MAX_NAME - 1;
        memcpy(base, name, n);
        base[n] = 0;
        snprintf(field, MAX_NAME, "%s", dot + 1);
        return;
    }
    snprintf(base, MAX_NAME, "%s", name ? name : "");
    field[0] = 0;
}

static void fmt_ctx(vcpu_state_t *st, char *out, size_t n)
{
    size_t used = 0;
    int i;
    out[0] = 0;
    for (i = 0; i < st->stack_len && used + 1 < n; i++) {
        int fi = st->stack[i].func_index;
        uint64_t func_loc = (fi >= 0 && (size_t)fi < n_funcs) ? funcs[fi].start : st->stack[i].start;
        uint64_t call_loc = i ? st->stack[i - 1].start : (st->in_irq ? st->interrupt_pc : st->last_main_pc);
        int w = snprintf(out + used, n - used, "%s0x%" PRIx64 ":0x%" PRIx64, used ? "," : "", call_loc, func_loc);
        if (w < 0 || (size_t)w >= n - used)
            break;
        used += (size_t)w;
    }
}

static int find_func(uint64_t pc)
{
    for (size_t i = 0; i < n_funcs; i++)
        if (pc == funcs[i].start)
            return (int)i;
    return -1;
}

static watched_var_t *find_var(uint64_t addr, size_t size)
{
    for (size_t i = 0; i < n_vars; i++)
        if (addr >= vars[i].start && addr + size <= vars[i].end)
            return &vars[i];
    return NULL;
}

static void note_gvap(watched_var_t *var, access_record_t *rec, vcpu_state_t *st)
{
    watched_var_t *prev = NULL;
    int fi = st->anchor;
    const char *fname = (fi >= 0 && (size_t)fi < n_funcs) ? funcs[fi].name : "";
    int pri = (fi >= 0 && (size_t)fi < n_funcs) ? funcs[fi].priority : 0;
    char ctx[256];
    size_t i;

    fmt_ctx(st, ctx, sizeof ctx);
    /* ponytail: linear scan over watched vars; index by base if a program has thousands. */
    for (i = 0; i < n_vars; i++) {
        if (!vars[i].has_last_main || strcmp(vars[i].base, var->base))
            continue;
        if (vars[i].last_main.epoch != st->epoch || vars[i].last_main.tid != rec->tid)
            continue;
        if (!prev || vars[i].last_main.icount > prev->last_main.icount)
            prev = &vars[i];
    }
    if (!prev && mode_validate)
        fprintf(stderr, "[gvax] %s.%s pc=0x%" PRIx64 " site=%s ctx=%s\n",
                var->base, var->field, rec->pc, inject_site[0] ? inject_site : "-", ctx);
    if (prev && rec->icount > prev->last_main.icount) {
        uint64_t dist = rec->icount - prev->last_main.icount;
        if (dist <= gvap_dist_threshold) {
            gvap_pair_count++;
            fprintf(stderr, "[gvap] %s.%s -> %s.%s dist=%" PRIu64
                    " exec=%s func=%s pri=%d irq_pc=0x%" PRIx64 " main_pc=0x%" PRIx64 " ctx=%s\n",
                    prev->base, prev->field, var->base, var->field, dist,
                    rec->tid == TID_MAIN ? "normal" : "handler", fname, pri,
                    st->interrupt_pc, st->last_main_pc, ctx);
        }
    }
    var->last_main = *rec;
    var->has_last_main = true;
}

static void push_access(watched_var_t *var, vcpu_state_t *st, int op, uint64_t pc)
{
    access_record_t rec = {.tid = st->tid, .op = op, .icount = insn_count, .pc = pc,
                           .anchor = st->anchor, .epoch = st->epoch};
    access_record_t *last = var->hist_len ? &var->hist[var->hist_len - 1] : NULL;

    if (mode_validate && watching && st->tid == TID_MAIN) {
        uint64_t span = insn_count - watch_from;
        uint64_t limit = inject_dist + GVAP_DELTA;
        if (span <= limit)
            fprintf(stderr, "[gvay] %s.%s dist=%" PRIu64 " window=%" PRIu64 " irq_pc=0x%" PRIx64 "\n",
                    var->base, var->field, span, limit, st->interrupt_pc);
        else
            watching = false;
    }
    if (mode_collect_gvap || mode_validate)
        note_gvap(var, &rec, st);
    if (last && last->tid == rec.tid) {
        last->icount = rec.icount;
        last->pc = pc;
        if (op == 2)
            last->op = 2;
    } else if (var->hist_len < 3) {
        var->hist[var->hist_len++] = rec;
    } else {
        var->hist[0] = var->hist[1];
        var->hist[1] = var->hist[2];
        var->hist[2] = rec;
    }
    if (var->hist_len == 3) {
        access_record_t a = var->hist[0], b = var->hist[1], c = var->hist[2];
        int kind = (a.op == 1 && b.op == 2 && c.op == 1) ? 1 :
                   (a.op == 1 && b.op == 2 && c.op == 2) ? 2 :
                   (a.op == 2 && b.op == 2 && c.op == 1) ? 3 :
                   (a.op == 2 && b.op == 1 && c.op == 2) ? 4 : 0;
        if (kind && a.tid == c.tid && a.tid != b.tid && c.icount - a.icount <= gvap_dist_threshold) {
            report_count++;
            fprintf(stderr, "[atomicity] %s type=%d dist=%" PRIu64 "\n",
                    var->name, kind, c.icount - a.icount);
        }
    }
}

static void on_insn_exec(unsigned int vcpu_index, void *userdata)
{
    insn_info_t *insn = userdata;
    vcpu_state_t *st = &vcpu_states[vcpu_index];
    int now_irq;

    insn_count++;
    if (insn->func_index >= 0 && st->stack_len < MAX_STACK) {
        func_range_t *fn = &funcs[insn->func_index];
        int tid = fn->tid == TID_INHERIT ? st->tid : fn->tid;
        if (st->stack_len == 0 || st->stack[st->stack_len - 1].func_index != insn->func_index) {
            if (tid != TID_MAIN && st->tid == TID_MAIN)
                st->interrupt_pc = st->last_main_pc;
            st->stack[st->stack_len++] = (frame_t){insn->func_index, tid, fn->start, fn->end};
            st->tid = tid;
            st->anchor = insn->func_index;
        }
    }
    while (st->stack_len > 0) {
        frame_t *fr = &st->stack[st->stack_len - 1];
        if (insn->pc >= fr->start && insn->pc < fr->end)
            break;
        st->stack_len--;
    }
    st->tid = st->stack_len ? st->stack[st->stack_len - 1].tid : TID_MAIN;
    now_irq = st->tid != TID_MAIN;
    if (now_irq != st->in_irq) {
        if (now_irq)
            st->interrupt_pc = st->last_main_pc;
        st->epoch++;
        if (mode_validate && st->in_irq && !now_irq) {
            watching = true;
            watch_from = insn_count;
        }
        st->in_irq = now_irq;
    }
    if (st->tid == TID_MAIN)
        st->last_main_pc = insn->pc;
}

static void on_mem_access(unsigned int vcpu_index, qemu_plugin_meminfo_t info,
                          uint64_t vaddr, void *userdata)
{
    insn_info_t *insn = userdata;
    watched_var_t *var = find_var(vaddr, (size_t)1 << qemu_plugin_mem_size_shift(info));

    if (!var || vcpu_index >= MAX_VCPUS)
        return;
    push_access(var, &vcpu_states[vcpu_index], qemu_plugin_mem_is_store(info) ? 2 : 1,
                insn ? insn->pc : 0);
}

static void on_tb_translate(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    size_t n = qemu_plugin_tb_n_insns(tb);
    (void)id;
    for (size_t i = 0; i < n; i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        insn_info_t *info = calloc(1, sizeof(*info));
        info->pc = qemu_plugin_insn_vaddr(insn);
        info->func_index = find_func(info->pc);
        qemu_plugin_register_vcpu_insn_exec_cb(insn, on_insn_exec, QEMU_PLUGIN_CB_NO_REGS, info);
        qemu_plugin_register_vcpu_mem_cb(insn, on_mem_access, QEMU_PLUGIN_CB_NO_REGS,
                                         QEMU_PLUGIN_MEM_RW, info);
    }
}

static void load_metadata(const char *path)
{
    FILE *fp = fopen(path, "r");
    char line[1024];

    if (!fp)
        return;
    while (fgets(line, sizeof line, fp)) {
        char *kind = strtok(line, "\t\r\n");
        char *t1 = strtok(NULL, "\t\r\n");
        char *t2 = strtok(NULL, "\t\r\n");
        char *t3 = strtok(NULL, "\t\r\n");
        char *t4 = strtok(NULL, "\t\r\n");
        char *t5 = strtok(NULL, "\t\r\n");
        uint64_t start, size;
        if (!kind || kind[0] == '#' || !t1 || !t2 || !t3)
            continue;
        start = strtoull(t1, NULL, 0);
        size = strtoull(t2, NULL, 0);
        if (!strcmp(kind, "VAR") && n_vars < MAX_VARS && size) {
            vars[n_vars].start = start;
            vars[n_vars].end = start + size;
            snprintf(vars[n_vars].name, MAX_NAME, "%s", t3);
            split_name(t3, t4, vars[n_vars].base, vars[n_vars].field);
            n_vars++;
        } else if (!strcmp(kind, "FUNC") && t4 && n_funcs < MAX_FUNCS && size) {
            funcs[n_funcs].start = start;
            funcs[n_funcs].end = start + size;
            funcs[n_funcs].tid = (int)strtol(t4, NULL, 0);
            funcs[n_funcs].priority = t5 ? (int)strtol(t5, NULL, 0) : 0;
            snprintf(funcs[n_funcs].name, MAX_NAME, "%s", t3);
            n_funcs++;
        }
    }
    fclose(fp);
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
                                           int argc, char **argv)
{
    const char *metadata = NULL;
    const char *dist_env, *site_env;
    (void)info;
    for (int i = 0; i < argc; i++) {
        if (!strncmp(argv[i], "meta=", 5))
            metadata = argv[i] + 5;
        else if (!strncmp(argv[i], "window=", 7) || !strncmp(argv[i], "dist_t=", 7))
            gvap_dist_threshold = strtoull(argv[i] + 7, NULL, 0);
        else if (!strcmp(argv[i], "mode=collect_gvap"))
            mode_collect_gvap = true;
        else if (!strcmp(argv[i], "mode=validate"))
            mode_validate = true;
    }
    dist_env = getenv("GVAP_INJECT_DIST");
    inject_dist = dist_env && *dist_env ? strtoull(dist_env, NULL, 0) : gvap_dist_threshold;
    site_env = getenv("GVAP_INJECT_SITE");
    snprintf(inject_site, sizeof inject_site, "%s", site_env ? site_env : "");
    if (metadata)
        load_metadata(metadata);
    for (size_t i = 0; i < MAX_VCPUS; i++) {
        vcpu_states[i].tid = TID_MAIN;
        vcpu_states[i].epoch = 1;
    }
    qemu_plugin_register_vcpu_tb_trans_cb(id, on_tb_translate);
    return 0;
}
