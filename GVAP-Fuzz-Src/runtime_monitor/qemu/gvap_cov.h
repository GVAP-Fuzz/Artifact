#pragma once

#include <stddef.h>
#include <stdint.h>

void gvap_cov_init(void);
void gvap_cov_set_irq(const char *irq_name, int priority, int active);
int gvap_cov_in_irq(void);
/* GVA = <Var, Field, AccessLoc, AccessType, CallCtx>. Dist is a dynamic instruction count. */
void gvap_cov_access(const char *var, const char *field, const char *loc,
                     const char *access_type, const char *call_ctx, uint64_t icount);
/* Defined by the interrupt broker (one strong definition). */
void gvap_cov_main(const char *var_name, const char *site_name);
void gvap_cov_irq(const char *var_name, const char *site_name);
void gvap_cov_finish(void);
