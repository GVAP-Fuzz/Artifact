/* GPIO opcode interpreter. byte = op(4) || dev(4). Include after platform hooks. */
#ifndef GPIO_DEV_NUMOF
#define GPIO_DEV_NUMOF 8U
#endif
#include <stdio.h>
#include <stdlib.h>
#include "gvap_afl_rt.h"

static size_t gvap_gpio_load_schedule(uint8_t *out, size_t cap)
{
    const char *path = getenv("GVAP_CASEFILE_PATH");
    FILE *fp = path && *path ? fopen(path, "rb") : NULL;
    size_t n = fp ? fread(out, 1, cap, fp) : 0;
    if (fp)
        fclose(fp);
    return n;
}

static size_t gvap_gpio_synthesize_schedule(uint8_t *out, size_t cap,
                                            unsigned profile, unsigned scenario, unsigned variant)
{
    size_t n = 3U + (profile % 4U);
    if (n > cap)
        n = cap;
    for (size_t i = 0; i < n; i++)
        out[i] = (uint8_t)((profile + scenario + variant + (unsigned)i) & 0x0fU);
    return n;
}

static void gvap_run_gpio_opcode(uint8_t byte)
{
    unsigned dev = GPIO_DEV_NUMOF ? ((byte >> 4) % GPIO_DEV_NUMOF) : 0;
    gvap_afl_step(1);
    unsigned op = byte & 0x0fU;
    static const char *site[] = {
        "init_a", "init_b", "enable", "disable", "fire", "fire_all",
        "init_a_fire", "init_b_fire", "reinit", "init_enable"};
    char name[40];
    snprintf(name, sizeof name, "gpio_slot_%u", dev);
    gvap_afl_note_named(name, op < 10 ? site[op] : "fire", 1);
    if (op <= 1 || op == 6 || op == 7 || op == 8 || op == 9)
        gvap_plat_gpio_init(dev, op == 1 || op == 7);
    if (op == 8)
        gvap_plat_gpio_init(dev, 1);
    if (op == 2 || op == 9)
        gvap_plat_gpio_enable(dev);
    if (op == 3)
        gvap_plat_gpio_disable(dev);
    if (op == 4 || op == 6 || op == 7 || op >= 10)
        gvap_plat_gpio_fire(dev);
    if (op == 5)
        gvap_plat_gpio_fire_all();
}
