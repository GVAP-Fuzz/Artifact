#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void gvap_afl_init(void);
void gvap_afl_note(const void *addr, int is_write);
void gvap_afl_note_named(const char *var_name, const char *site_name, int is_write);
/* Dynamic instruction count. One gvap_afl_step(1) per executed instruction. */
void gvap_afl_step(uint64_t n);
uint64_t gvap_afl_icount(void);
/* CallCtx frame: CallInfo = <CallLoc, FuncLoc>. */
void gvap_afl_call(uint64_t call_loc, uint64_t func_loc);
void gvap_afl_ret(void);
void gvap_afl_fmt_ctx(char *out, size_t n);
/* Drop open pairs at an interrupt boundary. */
void gvap_afl_boundary(void);

#ifdef __cplusplus
}
#endif
