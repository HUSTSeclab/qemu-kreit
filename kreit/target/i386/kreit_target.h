#ifndef __KREIT_TARGET_H__
#define __KREIT_TARGET_H__

#include <stdint.h>
#include <elf.h>

#include "qemu/osdep.h"
#include "cpu.h"
#include "kreit/kreit.h"

#define KREIT_LEN_REGVAL (CPU_NB_REGS * sizeof(target_ulong))

static inline int get_cpu_privilege(CPUArchState *env)
{
    return (env->hflags & HF_CPL_MASK);
}

static inline bool is_cpu_kernel_mode(int priv)
{
    switch (kcont.target) {
    case TRACE_TARGET_QNX:
        return (priv == 0) || (priv == 1);
    case TRACE_TARGET_LINUX:
        return priv == 0;
    }
    return false;
}

#define KREIT_E_MACHINE EM_X86_64

typedef struct KreitRegisters {
    uint64_t regs[CPU_NB_REGS];
    uint64_t segs[6];
    uint64_t eip;
    uint64_t cr[5];
} KreitRegisters;

static inline void kreit_copy_cpu_regs(CPUArchState *env, KreitRegisters *dst)
{
    memcpy(dst->regs, env->regs, CPU_NB_REGS * sizeof(target_ulong));
    memcpy(dst->segs, env->segs, 6 * sizeof(target_ulong));
    dst->eip = env->eip;
    memcpy(dst->cr, env->cr, 5 * sizeof(target_ulong));
}

static inline target_ulong kreit_get_pc(CPUArchState *env)
{
    return env->eip;
}

static const int abi_param_order[] = {
    R_EDI,
    R_ESI,
    R_EDX,
    R_ECX,
    R_R8,
    R_R9
};
#define MAX_ABI_REG_PARAM (sizeof(abi_param_order) / sizeof(int))

static inline uint64_t kreit_get_return_value(CPUArchState *env)
{
    return env->regs[R_EAX];
}

static inline void kreit_set_return_value(CPUArchState *env, uint64_t val)
{
    env->regs[R_EAX] = val;
}

static inline uint64_t kreit_get_stack_ptr(CPUArchState *env)
{
    return env->regs[R_ESP];
}

static inline void kreit_set_stack_ptr(CPUArchState *env, uint64_t val)
{
    env->regs[R_ESP] = val;
}

static inline uint64_t kreit_get_abi_param(CPUArchState *env, int param_order)
{
    vaddr rsp;

    if (param_order <= MAX_ABI_REG_PARAM)
        return env->regs[abi_param_order[param_order - 1]];

    rsp = kreit_get_stack_ptr(env);
    return kreit_cpu_ldq(env_cpu(env), rsp + 8 * (param_order - MAX_ABI_REG_PARAM));
}

static inline void kreit_set_abi_reg_param(CPUArchState *env, int param_order, uint64_t val)
{
    vaddr rsp;

    if (param_order <= MAX_ABI_REG_PARAM)
        env->regs[abi_param_order[param_order - 1]] = val;

    rsp = kreit_get_stack_ptr(env);
    kreit_cpu_stq(env_cpu(env), rsp + 8 * (param_order - MAX_ABI_REG_PARAM), val);
}

static inline void *kreit_get_regular_register_buf(CPUArchState *env)
{
    void *buf = g_malloc(sizeof(env->regs));
    memcpy(buf, env->regs, sizeof(env->regs));
    return buf;
}

static inline void kreit_set_regular_register_buf(CPUArchState *env, void *buf)
{
    memcpy(env->regs, buf, sizeof(env->regs));
}

#define KREIT_E_MACHINE EM_X86_64

#endif // __KREIT_TARGET_H__
