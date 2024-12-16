#include "qemu/osdep.h"
#include "cpu.h"
#include "exec/exec-all.h"
#include "exec/helper-proto-common.h"
#include "kreit/sanitizer/asan/asan-common.h"
// #include "exec/log.h"
// #include "tcg/tcg.h"

#include "kreit/instrument/instrument.h"
#include "kreit/kreit.h"

#include "kreit/context-switch/context-switch-common.h"

#define HELPER_H  "kreit/kreit_helper.h"
#include "exec/helper-info.c.inc"
#undef  HELPER_H

// void HELPER(kreit_trace_goto_tb)(CPUArchState *env, uint32_t arg)
// {
//     kreit_trace_goto_tb_event(env, arg);
// }
//

void HELPER(kreit_trace_tb_start)(CPUArchState *env, uint64_t pc)
{
    kreit_trace_tb_start_addr(env, pc);
}

void HELPER(kreit_trace_context_switch)(CPUArchState *env)
{
    KreitSwitchPair spair;
    CPUState *cpu = env_cpu(env);
    kreit_fill_switch_pair(cpu, &spair, true);
    if (_skip_next_tcg_instr && _skip_next_tcg_instr[cpu->cpu_index]) {
        _skip_next_tcg_instr[cpu->cpu_index] = false;
        return;
    }
    kreit_trace_context_switch(&spair);
}

void HELPER(kreit_trace_die)(CPUArchState *env)
{
    kreit_trace_die(env);
}

void HELPER(kreit_trace_asan_hook)(CPUArchState *env, uint32_t hook_index)
{
    kreit_trace_asan_hook(env, hook_index);
}

void HELPER(qasan_load1)(CPUArchState *env, target_ulong addr)
{
    if (!asan_check_range(addr))
        return;

    if (asan_giovese_load1(addr)) {
        asan_giovese_report_and_crash(ACCESS_TYPE_LOAD, addr, 1, env);
    }
}

void HELPER(qasan_load2)(CPUArchState *env, target_ulong addr)
{
    if (!asan_check_range(addr))
        return;

    if (asan_giovese_load2(addr)) {
        asan_giovese_report_and_crash(ACCESS_TYPE_LOAD, addr, 2, env);
    }
}

void HELPER(qasan_load4)(CPUArchState *env, target_ulong addr)
{
    if (!asan_check_range(addr))
        return;

    if (asan_giovese_load4(addr)) {
        asan_giovese_report_and_crash(ACCESS_TYPE_LOAD, addr, 4, env);
    }
}

void HELPER(qasan_load8)(CPUArchState *env, target_ulong addr)
{
    if (!asan_check_range(addr))
        return;

    if (asan_giovese_load8(addr)) {
        asan_giovese_report_and_crash(ACCESS_TYPE_LOAD, addr, 8, env);
    }
}

void HELPER(qasan_load16)(CPUArchState *env, target_ulong addr)
{
    if (!asan_check_range(addr))
        return;

    if (asan_giovese_load16(addr)) {
        asan_giovese_report_and_crash(ACCESS_TYPE_LOAD, addr, 16, env);
    }
}

void HELPER(qasan_store1)(CPUArchState *env, target_ulong addr)
{
    if (!asan_check_range(addr))
        return;

    if (asan_giovese_store1(addr)) {
        asan_giovese_report_and_crash(ACCESS_TYPE_STORE, addr, 1, env);
    }
}

void HELPER(qasan_store2)(CPUArchState *env, target_ulong addr)
{
    if (!asan_check_range(addr))
        return;

    if (asan_giovese_store2(addr)) {
        asan_giovese_report_and_crash(ACCESS_TYPE_STORE, addr, 2, env);
    }
}

void HELPER(qasan_store4)(CPUArchState *env, target_ulong addr)
{
    if (!asan_check_range(addr))
        return;

    if (asan_giovese_store4(addr)) {
        asan_giovese_report_and_crash(ACCESS_TYPE_STORE, addr, 4, env);
    }
}

void HELPER(qasan_store8)(CPUArchState *env, target_ulong addr)
{
    if (!asan_check_range(addr))
        return;

    if (asan_giovese_store8(addr)) {
        asan_giovese_report_and_crash(ACCESS_TYPE_STORE, addr, 8, env);
    }
}

void HELPER(qasan_store16)(CPUArchState *env, target_ulong addr)
{
    if (!asan_check_range(addr))
        return;

    if (asan_giovese_store16(addr)) {
        asan_giovese_report_and_crash(ACCESS_TYPE_STORE, addr, 16, env);
    }
}
