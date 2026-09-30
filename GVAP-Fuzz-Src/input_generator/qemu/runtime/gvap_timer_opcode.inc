/* Timer opcode interpreter. byte = op(4) || dev(4). Include after platform hooks. */
#ifndef TIMER_DEV_NUMOF
#define TIMER_DEV_NUMOF 3U
#endif
#include <stdio.h>
#include <stdlib.h>
#include "gvap_afl_rt.h"

static size_t gvap_timer_load_schedule(uint8_t *out, size_t cap)
{
    const char *path = getenv("GVAP_CASEFILE_PATH");
    FILE *fp = path && *path ? fopen(path, "rb") : NULL;
    size_t n = fp ? fread(out, 1, cap, fp) : 0;
    if (fp)
        fclose(fp);
    return n;
}

static size_t gvap_timer_synthesize_schedule(uint8_t *out, size_t cap,
                                             unsigned profile, unsigned scenario, unsigned variant)
{
    size_t n = 3U + (profile % 4U);
    if (n > cap)
        n = cap;
    for (size_t i = 0; i < n; i++)
        out[i] = (uint8_t)((profile + scenario + variant + (unsigned)i) & 0x0fU);
    return n;
}

static void gvap_run_timer_opcode(uint8_t byte)
{
    unsigned dev = TIMER_DEV_NUMOF ? ((byte >> 4) % TIMER_DEV_NUMOF) : 0;
    gvap_afl_step(1);
    unsigned op = byte & 0x0fU;
    static const char *site[] = {"init_a", "init_b", "set0", "set1", "fire0", "fire1", "clear", "init_a_set"};
    char name[40];
    snprintf(name, sizeof name, "timer_dev_%u", dev);
    gvap_afl_note_named(name, op < 8 ? site[op] : "fire0", 1);
    if (op <= 1 || op == 7)
        gvap_plat_timer_init(dev, op == 1);
    if (op == 2 || op == 3 || op == 7)
        gvap_plat_timer_set(dev, op == 3);
    if (op == 4 || op == 5 || op >= 8)
        gvap_plat_timer_fire(dev, op == 5);
    if (op == 6)
        gvap_plat_timer_clear(dev);
}
