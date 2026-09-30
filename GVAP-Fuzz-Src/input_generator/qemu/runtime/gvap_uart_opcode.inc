/* UART opcode interpreter. byte = op(4) || dev(4). Include after platform hooks and UART_NUMOF. */
#include <stdio.h>
#include <stdlib.h>
#include "gvap_afl_rt.h"

static size_t gvap_load_schedule(uint8_t *out, size_t cap)
{
    const char *path = getenv("GVAP_CASEFILE_PATH");
    FILE *fp = path && *path ? fopen(path, "rb") : NULL;
    size_t n = fp ? fread(out, 1, cap, fp) : 0;
    if (fp)
        fclose(fp);
    return n;
}

static size_t gvap_synthesize_schedule(uint8_t *out, size_t cap,
                                       unsigned profile, unsigned scenario, unsigned variant)
{
    size_t n = 4U + (profile % 8U);
    unsigned devs = UART_NUMOF ? UART_NUMOF : 1U;
    if (n > cap)
        n = cap;
    for (size_t i = 0; i < n; i++)
        out[i] = (uint8_t)(((profile + scenario + variant + (unsigned)i) & 0x0fU) |
                           (((unsigned)i + variant) % devs << 4));
    return n;
}

static void gvap_run_opcode(uint8_t opcode, unsigned profile, unsigned scenario,
                            unsigned variant, unsigned slot)
{
    unsigned dev = UART_NUMOF ? ((opcode >> 4) % UART_NUMOF) : 0;
    unsigned op = opcode & 0x0fU;
    uint8_t first = (uint8_t)(0x41U + (slot & 0x1fU));
    char name[40];
    gvap_afl_step(1);
    (void)profile;
    (void)scenario;
    (void)variant;
    snprintf(name, sizeof name, "uart_dev_%u", dev);
    gvap_afl_note_named(name, "op", 1);
    if (op == 0)
        gvap_plat_init_cb(dev);
    else if (op == 1)
        gvap_plat_init_plain(dev);
    else if (op == 6)
        gvap_plat_fire_rx(dev, (uint8_t)(0x20U + slot));
    else if (op == 8 || op == 9)
        gvap_plat_power(dev, op == 8);
    else if (op == 5 || op == 10 || op == 13 || op == 14)
        gvap_plat_write(dev, first, (op == 10 || op == 14) ? 16U : 1U, op != 5);
    else if (op != 7)
        gvap_plat_mode(dev, (int)op);
    if (op == 7 || op == 14)
        gvap_plat_fire_tx(dev);
}
