/* GVAP-Fuzz interrupt controller (QEMU). Fire the chosen IRQ after GVAx. */
#include "gvap_irq_broker.h"
#include "gvap_afl_rt.h"
#include "gvap_cov.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_IRQS 8

typedef struct { const char *name; gvap_irq_fn_t fn; } irq_t;

static irq_t irqs[MAX_IRQS];
static size_t n_irqs;
static const char *target_site, *target_irq;
static int active, fires, broker_busy, registered, inject_pri;

void gvap_plat_irq(void) __attribute__((weak));
void gvap_plat_irq(void) {}

int irq_is_in(void)
{
    return gvap_cov_in_irq();
}

void gvap_broker_init_from_env(void)
{
    const char *pri;
    if (broker_busy)
        return;
    broker_busy = 1;
    gvap_afl_init();
    broker_busy = 0;
    target_site = getenv("GVAP_INJECT_SITE");
    target_irq = getenv("GVAP_INJECT_IRQ");
    pri = getenv("GVAP_INJECT_PRI");
    inject_pri = pri && *pri ? atoi(pri) : 0;
    active = target_site && *target_site && target_irq && *target_irq;
    if (!registered && active) {
        gvap_broker_register_irq(target_irq, gvap_plat_irq);
        registered = 1;
    }
}

void gvap_broker_register_irq(const char *name, gvap_irq_fn_t fn)
{
    if (n_irqs < MAX_IRQS && name && fn)
        irqs[n_irqs++] = (irq_t){name, fn};
}

bool gvap_broker_active(void)
{
    return active;
}

void gvap_broker_hit(const char *site)
{
    size_t i;
    if (!active || !site || strcmp(target_site, site) || fires)
        return;
    for (i = 0; i < n_irqs; i++) {
        if (strcmp(irqs[i].name, target_irq))
            continue;
        fires++;
        gvap_afl_boundary();
        gvap_cov_set_irq(target_irq, inject_pri, 1);
        irqs[i].fn();
        gvap_cov_set_irq(NULL, 0, 0);
        gvap_afl_boundary();
        return;
    }
}

void gvap_cov_main(const char *var_name, const char *site_name)
{
    if (!var_name || !site_name)
        return;
    gvap_afl_note_named(var_name, site_name, 1);
}

void gvap_cov_irq(const char *var_name, const char *site_name)
{
    const char *irq, *pri;
    if (!var_name || !site_name)
        return;
    if (!gvap_cov_in_irq()) {
        irq = getenv("GVAP_INJECT_IRQ");
        pri = getenv("GVAP_INJECT_PRI");
        gvap_cov_set_irq(irq && *irq ? irq : site_name, pri && *pri ? atoi(pri) : 0, 1);
    }
    gvap_afl_note_named(var_name, site_name, 1);
}

__attribute__((constructor)) static void gvap_broker_boot(void)
{
    gvap_broker_init_from_env();
}
