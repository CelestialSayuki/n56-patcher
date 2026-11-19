/* N56 offline host ABI. ARM payload bytes are never executable on this host. */
#ifndef N56_KPF_OFFLINE_H
#define N56_KPF_OFFLINE_H
#include <pongo.h>
extern uint32_t *n56_select_shellcode(uint32_t count);
extern void n56_audit_match(xnu_pf_patch_t *patch, void *stream);
extern void n56_audit_result(xnu_pf_patch_t *patch);
extern void n56_audit_policy(bool ssv, bool livefs, bool optional_arv);
extern void n56_audit_finish(void);
#endif
