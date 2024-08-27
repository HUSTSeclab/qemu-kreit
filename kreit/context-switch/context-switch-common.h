#ifndef __CONTEXT_SWITCH_COMMON_H__
#define __CONTEXT_SWITCH_COMMON_H__

#include <stdbool.h>
#include "qemu/osdep.h"
#include "hw/core/cpu.h"
#include "kreit/instrument/instrument.h"

void kreit_fill_switch_pair(CPUState *cpu, KreitSwitchPair *spair, bool tcg_api);

void kreit_log_context_switch(const KreitSwitchPair *spair);

extern bool *_skip_next_tcg_instr;

typedef struct KreitContextSwitchConf {
    vaddr addr_context_switch;
    size_t pid_offset;
    size_t pname_offset;
} KreitContextSwitchConf;

extern KreitContextSwitchConf switch_conf;

#endif // __CONTEXT_SWITCH_COMMON_H__
