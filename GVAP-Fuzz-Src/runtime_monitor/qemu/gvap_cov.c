/* GVAP table: interesting input, GVAP, execution context (interrupt name and priority).
 * Formula 5: Dist <= tau. tau = 120. Interrupt entry/return clears open pairs.
 * Coverage file is rewritten with fopen mode "w" (the only writer). */
#include "gvap_cov.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TAU 120
#define MAX_OPEN 64
#define MAX_ROWS 256
#define NAME 64

typedef struct {
    char var[NAME], field[NAME], loc[NAME], typ[4], ctx[160];
    uint64_t icount;
    int in_irq, priority;
    char irq[NAME];
} acc_t;

typedef struct {
    char input[128], gvap[768], exec[16], irq[NAME];
    uint64_t dist;
    int priority;
} row_t;

static acc_t open_acc[MAX_OPEN];
static row_t rows[MAX_ROWS];
static int n_open, n_rows, in_irq, cur_pri, path_cached;
static char cur_irq[NAME];
static const char *out_path;

void gvap_cov_init(void)
{
    const char *path;
    if (path_cached)
        return;
    path_cached = 1;
    path = getenv("GVAP_COVERAGE_FILE");
    out_path = (path && *path) ? path : NULL;
}

int gvap_cov_in_irq(void)
{
    return in_irq;
}

void gvap_cov_set_irq(const char *irq_name, int priority, int active)
{
    int next = active ? 1 : 0;
    if (next == in_irq && (!irq_name || !strcmp(irq_name, cur_irq)))
        return;
    n_open = 0;
    in_irq = next;
    cur_pri = next ? priority : 0;
    if (next && irq_name)
        snprintf(cur_irq, sizeof cur_irq, "%s", irq_name);
    else
        cur_irq[0] = 0;
}

void gvap_cov_access(const char *var, const char *field, const char *loc,
                     const char *access_type, const char *call_ctx, uint64_t icount)
{
    acc_t rec;
    int i;
    if (!var || !loc)
        return;
    gvap_cov_init();
    memset(&rec, 0, sizeof rec);
    snprintf(rec.var, NAME, "%s", var);
    snprintf(rec.field, NAME, "%s", field ? field : "");
    snprintf(rec.loc, NAME, "%s", loc);
    snprintf(rec.typ, sizeof rec.typ, "%s", access_type && *access_type ? access_type : "R");
    snprintf(rec.ctx, sizeof rec.ctx, "%s", call_ctx ? call_ctx : "");
    rec.icount = icount;
    rec.in_irq = in_irq;
    rec.priority = cur_pri;
    snprintf(rec.irq, NAME, "%s", cur_irq);
    /* ponytail: open segment is capped at MAX_OPEN; drop the oldest if a trace is longer. */
    for (i = 0; i < n_open; i++) {
        acc_t *prev = &open_acc[i];
        uint64_t dist;
        const char *input;
        if (strcmp(prev->var, rec.var) || prev->in_irq != rec.in_irq)
            continue;
        if (rec.in_irq && strcmp(prev->irq, rec.irq))
            continue;
        if (rec.icount <= prev->icount)
            continue;
        dist = rec.icount - prev->icount;
        if (dist > TAU || n_rows >= MAX_ROWS)
            continue;
        input = getenv("GVAP_INPUT");
        if (!input || !*input)
            input = getenv("GVAP_CASEFILE_PATH");
        if (!input)
            input = "";
        snprintf(rows[n_rows].input, sizeof rows[n_rows].input, "%s", input);
        snprintf(rows[n_rows].gvap, sizeof rows[n_rows].gvap,
                 "%s.%s %s %s %s -> %s.%s %s %s %s",
                 prev->var, prev->field, prev->loc, prev->typ, prev->ctx,
                 rec.var, rec.field, rec.loc, rec.typ, rec.ctx);
        rows[n_rows].dist = dist;
        snprintf(rows[n_rows].exec, sizeof rows[n_rows].exec, "%s", rec.in_irq ? "handler" : "normal");
        snprintf(rows[n_rows].irq, sizeof rows[n_rows].irq, "%s", rec.irq);
        rows[n_rows].priority = rec.priority;
        n_rows++;
    }
    if (n_open == MAX_OPEN)
        memmove(&open_acc[0], &open_acc[1], sizeof(acc_t) * (MAX_OPEN - 1));
    else
        n_open++;
    open_acc[n_open - 1] = rec;
}

void gvap_cov_finish(void)
{
    const char *path = out_path ? out_path : getenv("GVAP_COVERAGE_FILE");
    FILE *fp;
    int i;
    if (!path || !*path)
        return;
    fp = fopen(path, "w");
    if (!fp)
        return;
    fprintf(fp, "# input\tgvap\tdist\texec_ctx\tirq\tpriority\n");
    for (i = 0; i < n_rows; i++)
        fprintf(fp, "%s\t%s\t%llu\t%s\t%s\t%d\n",
                rows[i].input, rows[i].gvap, (unsigned long long)rows[i].dist,
                rows[i].exec, rows[i].irq, rows[i].priority);
    fclose(fp);
}

__attribute__((constructor)) static void gvap_cov_boot(void)
{
    gvap_cov_init();
    atexit(gvap_cov_finish);
}
