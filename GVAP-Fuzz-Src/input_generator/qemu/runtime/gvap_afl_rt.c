/* GVAP-Fuzz input generator: shared-memory bridge. Magic 0x47564150.
 * Dist is the dynamic instruction count between two accesses (gvap_afl_step),
 * the same definition as the TCG plugin insn_count. tau = 120.
 * CallCtx is the stack of <CallLoc, FuncLoc> (formulas 3 and 4). */
#include "gvap_afl_rt.h"
#include "gvap_cov.h"

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

int irq_is_in(void) __attribute__((weak));
int irq_is_in(void) { return 0; }
void gvap_broker_hit(const char *site) __attribute__((weak));
void gvap_broker_init_from_env(void);

#define GVAP_AFL_MAGIC 0x47564150u
#define GVAP_AFL_MAX_PAIRS 4096u
#define GVAP_AFL_MAX_SLOTS 256u
#define GVAP_STACK 16
#define GVAP_DIST_THRESHOLD 120

typedef struct {
    uint32_t magic, count;
    uint64_t hashes[GVAP_AFL_MAX_PAIRS];
    uint32_t dists[GVAP_AFL_MAX_PAIRS];
} gvap_afl_shm_t;

typedef struct {
    uint64_t key, last_loc, last_icount;
    int has_last, last_irq;
} gvap_afl_slot_t;

typedef struct { uint64_t call_loc, func_loc; } gvap_frame_t;

static gvap_afl_shm_t *g_shm;
static gvap_afl_slot_t g_slots[GVAP_AFL_MAX_SLOTS];
static gvap_frame_t g_stack[GVAP_STACK];
static int g_ready, g_started, g_sp;
static uint64_t g_icount, g_dist_t = GVAP_DIST_THRESHOLD;

static uint64_t hash_bytes(const char *s)
{
    uint64_t h = 1469598103934665603ULL;
    while (s && *s)
        h = (h ^ (unsigned char)*s++) * 1099511628211ULL;
    return h;
}

static uint64_t ctx_hash(void)
{
    uint64_t h = 1469598103934665603ULL;
    int i;
    if (!g_sp)
        return (uint64_t)(uintptr_t)__builtin_return_address(0);
    for (i = 0; i < g_sp; i++) {
        h ^= g_stack[i].call_loc;
        h *= 1099511628211ULL;
        h ^= g_stack[i].func_loc;
        h *= 1099511628211ULL;
    }
    return h;
}

void gvap_afl_step(uint64_t n) { g_icount += n; }
uint64_t gvap_afl_icount(void) { return g_icount; }

void gvap_afl_call(uint64_t call_loc, uint64_t func_loc)
{
    if (g_sp < GVAP_STACK)
        g_stack[g_sp++] = (gvap_frame_t){call_loc, func_loc};
}

void gvap_afl_ret(void)
{
    if (g_sp)
        g_sp--;
}

void gvap_afl_fmt_ctx(char *out, size_t n)
{
    size_t used = 0;
    int i;
    if (!out || !n)
        return;
    out[0] = 0;
    if (!g_sp) {
        snprintf(out, n, "0x%llx:0x0",
                 (unsigned long long)(uintptr_t)__builtin_return_address(0));
        return;
    }
    for (i = 0; i < g_sp && used + 1 < n; i++) {
        int w = snprintf(out + used, n - used, "%s0x%llx:0x%llx", used ? "," : "",
                         (unsigned long long)g_stack[i].call_loc,
                         (unsigned long long)g_stack[i].func_loc);
        if (w < 0 || (size_t)w >= n - used)
            break;
        used += (size_t)w;
    }
}

void gvap_afl_boundary(void)
{
    size_t i;
    for (i = 0; i < GVAP_AFL_MAX_SLOTS; i++)
        g_slots[i].has_last = 0;
}

static void split_var(const char *name, char *var, char *field, size_t n)
{
    const char *dot = name ? strrchr(name, '.') : NULL;
    size_t vn;
    if (!dot || dot == name) {
        snprintf(var, n, "%s", name ? name : "");
        field[0] = 0;
        return;
    }
    vn = (size_t)(dot - name);
    if (vn >= n)
        vn = n - 1;
    memcpy(var, name, vn);
    var[vn] = 0;
    snprintf(field, n, "%s", dot + 1);
}

static void note_loc(uint64_t key, uint64_t loc)
{
    gvap_afl_slot_t *slot = &g_slots[key % GVAP_AFL_MAX_SLOTS];
    int irq = irq_is_in() ? 1 : 0;
    uint64_t dist;

    if (slot->has_last && slot->key != key)
        return;
    slot->key = key;
    loc ^= ctx_hash();
    if (slot->has_last && slot->last_irq != irq)
        slot->has_last = 0;
    if (slot->has_last && g_shm && g_icount > slot->last_icount &&
        (dist = g_icount - slot->last_icount) <= g_dist_t) {
        uint64_t pair = key ^ (slot->last_loc * 0x9e3779b97f4a7c15ULL) ^ loc;
        uint32_t i;
        for (i = 0; i < g_shm->count; i++)
            if (g_shm->hashes[i] == pair)
                goto done;
        if (g_shm->count < GVAP_AFL_MAX_PAIRS) {
            g_shm->dists[g_shm->count] = (uint32_t)dist;
            g_shm->hashes[g_shm->count++] = pair;
        }
    }
done:
    slot->last_loc = loc;
    slot->last_icount = g_icount;
    slot->last_irq = irq;
    slot->has_last = 1;
}

void gvap_afl_init(void)
{
    const char *name;
    int fd;
    if (g_started)
        return;
    g_started = 1;
    gvap_broker_init_from_env();
    name = getenv("GVAP_AFL_SHM");
    if (!name || !*name)
        return;
    fd = shm_open(name, O_RDWR, 0600);
    if (fd < 0)
        return;
    g_shm = mmap(NULL, sizeof(*g_shm), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (g_shm == MAP_FAILED || g_shm->magic != GVAP_AFL_MAGIC) {
        g_shm = NULL;
        return;
    }
    g_ready = 1;
    g_shm->count = 0;
}

void gvap_afl_note(const void *addr, int is_write)
{
    if (!g_ready || !addr)
        return;
    note_loc((uint64_t)(uintptr_t)addr,
             ((uint64_t)(is_write ? 2 : 1) << 56));
}

void gvap_afl_note_named(const char *var_name, const char *site_name, int is_write)
{
    char var[96], field[96], ctx[192];
    if (!var_name || !site_name)
        return;
    split_var(var_name, var, field, sizeof var);
    gvap_afl_fmt_ctx(ctx, sizeof ctx);
    gvap_cov_access(var, field, site_name, is_write ? "W" : "R", ctx, g_icount);
    if (gvap_broker_hit)
        gvap_broker_hit(site_name);
    if (!g_ready)
        return;
    note_loc(hash_bytes(var_name),
             hash_bytes(site_name) ^ ((uint64_t)(is_write ? 2 : 1) << 56));
}
