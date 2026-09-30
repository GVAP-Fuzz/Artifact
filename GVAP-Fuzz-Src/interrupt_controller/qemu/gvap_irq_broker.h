#pragma once

#include <stdbool.h>

typedef void (*gvap_irq_fn_t)(void);

void gvap_broker_init_from_env(void);
void gvap_broker_register_irq(const char *name, gvap_irq_fn_t fn);
bool gvap_broker_active(void);
void gvap_broker_hit(const char *site);
void gvap_cov_main(const char *var_name, const char *site_name);
void gvap_cov_irq(const char *var_name, const char *site_name);
