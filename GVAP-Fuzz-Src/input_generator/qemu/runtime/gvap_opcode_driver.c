/* Opcode schedule runner. Weak gvap_plat_* hooks; a harness may override them.
 * Each included interpreter is called from gvap_run_schedule. */
#include "gvap_afl_rt.h"
#include "gvap_irq_broker.h"

#include <stdint.h>
#include <string.h>

#ifndef UART_NUMOF
#define UART_NUMOF 2U
#endif

#define WEAK_HOOK(decl, body) decl __attribute__((weak)); decl body

WEAK_HOOK(void gvap_plat_gpio_init(unsigned dev, int alt), { (void)dev; (void)alt; })
WEAK_HOOK(void gvap_plat_gpio_enable(unsigned dev), { (void)dev; })
WEAK_HOOK(void gvap_plat_gpio_disable(unsigned dev), { (void)dev; })
WEAK_HOOK(void gvap_plat_gpio_fire(unsigned dev), { (void)dev; })
WEAK_HOOK(void gvap_plat_gpio_fire_all(void), {})
WEAK_HOOK(void gvap_plat_timer_init(unsigned dev, int alt), { (void)dev; (void)alt; })
WEAK_HOOK(void gvap_plat_timer_set(unsigned dev, int high), { (void)dev; (void)high; })
WEAK_HOOK(void gvap_plat_timer_fire(unsigned dev, int which), { (void)dev; (void)which; })
WEAK_HOOK(void gvap_plat_timer_clear(unsigned dev), { (void)dev; })
WEAK_HOOK(void gvap_plat_init_cb(unsigned dev), { (void)dev; })
WEAK_HOOK(void gvap_plat_init_plain(unsigned dev), { (void)dev; })
WEAK_HOOK(void gvap_plat_fire_rx(unsigned dev, uint8_t byte), { (void)dev; (void)byte; })
WEAK_HOOK(void gvap_plat_power(unsigned dev, int on), { (void)dev; (void)on; })
WEAK_HOOK(void gvap_plat_write(unsigned dev, uint8_t byte, unsigned n, int flag),
          { (void)dev; (void)byte; (void)n; (void)flag; })
WEAK_HOOK(void gvap_plat_mode(unsigned dev, int mode), { (void)dev; (void)mode; })
WEAK_HOOK(void gvap_plat_fire_tx(unsigned dev), { (void)dev; })

#include "gvap_gpio_opcode.inc"
#include "gvap_timer_opcode.inc"
#include "gvap_uart_opcode.inc"

void gvap_run_schedule(const uint8_t *buf, size_t n)
{
    size_t i;
    if (!buf || !n) {
        uint8_t scratch[8];
        (void)gvap_gpio_synthesize_schedule(scratch, sizeof scratch, 0, 0, 0);
        (void)gvap_timer_synthesize_schedule(scratch, sizeof scratch, 0, 0, 0);
        (void)gvap_synthesize_schedule(scratch, sizeof scratch, 0, 0, 0);
        return;
    }
    for (i = 0; i < n; i++) {
        gvap_afl_call((uint64_t)(uintptr_t)gvap_run_schedule,
                      (uint64_t)(uintptr_t)gvap_run_gpio_opcode);
        gvap_run_gpio_opcode(buf[i]);
        gvap_afl_ret();
        gvap_afl_call((uint64_t)(uintptr_t)gvap_run_schedule,
                      (uint64_t)(uintptr_t)gvap_run_timer_opcode);
        gvap_run_timer_opcode(buf[i]);
        gvap_afl_ret();
        gvap_afl_call((uint64_t)(uintptr_t)gvap_run_schedule,
                      (uint64_t)(uintptr_t)gvap_run_opcode);
        gvap_run_opcode(buf[i], 0, 0, 0, (unsigned)i);
        gvap_afl_ret();
    }
}

__attribute__((constructor)) static void gvap_opcode_boot(void)
{
    uint8_t buf[64];
    size_t n;
    gvap_broker_init_from_env();
    n = gvap_load_schedule(buf, sizeof buf);
    if (!n)
        n = gvap_gpio_load_schedule(buf, sizeof buf);
    if (!n)
        n = gvap_timer_load_schedule(buf, sizeof buf);
    gvap_run_schedule(n ? buf : NULL, n);
}
