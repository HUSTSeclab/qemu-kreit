#ifndef __KREIT_INSTRUMENT_H__
#define __KREIT_INSTRUMENT_H__

#include <stdbool.h>
#include <stdint.h>
#include "kreit/kreit.h"
#include "qom/object.h"

#define TYPE_KREITINSTR "kreitinstr"

typedef enum KreitInstrType {
    KREIT_INSTR_GOTO_TB_EVENT,
    KREIT_INSTR_TB_ENTRY,
    KREIT_INSTR_TB_TRANSLATE,
    KREIT_INSTR_TB_STOP,
    KREIT_INSTR_INTTERUPT,
    KREIT_INSTR_TB_START_ADDR,
    KREIT_INSTR_GEN_TB_START,
    KREIT_INSTR_TRACE_CONTEXT_SWITCH,
    KREIT_INSTR_TRACE_DIE,
    KREIT_INSTR_BREAKPOINT,
    KREIT_INSTR_ASAN_HOOK,
    KREIT_INSTR_INSN_TRANS_PRE,
    KREIT_INSTR_INSN_TRANS_POST,
    KREIT_INSTR_INSN_LOAD,
    KREIT_INSTR_END
} KreitInstrType;

typedef void (KreitInstrumentCallback)(void *instr_data, void *userdata);

typedef struct KreitInstrState {
    /*< private >*/
    Object parent_obj;

    /*< public >*/
    KreitInstrType type;
    KreitInstrumentCallback *callback;
    void *userdata;
    bool __valid_bit;
} KreitInstrState;

typedef struct KreitInstrClass {
    /*< private >*/
    ObjectClass parent_class;

    /*< public >*/
    const char *name;
    void (*init_instr)(KreitInstrState *kis, KreitInstrType type, KreitInstrumentCallback callback, void *data);
    void (*invoke_callback)(KreitInstrState *kis, void *instr_data);
} KreitInstrClass;

#define KREITINSTR_CLASS(klass) \
    OBJECT_CLASS_CHECK(KreitInstrClass, (klass), TYPE_KREITINSTR)

#define KREITINSTR_GET_CLASS(obj) \
    OBJECT_GET_CLASS(KreitInstrClass, (obj), TYPE_KREITINSTR)

DECLARE_INSTANCE_CHECKER(KreitInstrState, KREITINSTR_STATE,
                         TYPE_KREITINSTR)

KreitInstrState *kreitinstr_register(KreitInstrType type, KreitInstrumentCallback callback, void *data);
void kreitinstr_unregister(KreitInstrState *kis);

void __kreit_instrument(KreitInstrType type, void *instr_data);

#define kreit_trace_goto_tb_event(tb_index) \
    __kreit_instrument(KREIT_INSTR_GOTO_TB_EVENT, (void *)tb_index)

#define kreit_trace_tb_entry(pc) \
    __kreit_instrument(KREIT_INSTR_TB_ENTRY, (void *)pc)

typedef struct KreitTBTranslateData {
    void *env;
    uint64_t pc;
    size_t size;
} KreitTBTranslateData;

#define kreit_trace_tb_translate(env_, pc_, size_) \
    do { \
        KreitTBTranslateData tmp = { .env = env_, .pc = pc_, .size = size_ }; \
        __kreit_instrument(KREIT_INSTR_TB_TRANSLATE, &tmp); \
    } while(0)

typedef struct KreitInterruptInfo {
    void *env;
    int intno;
    int error_code;
} KreitInterruptInfo;

#define kreit_trace_interrupt(env_, intno_, error_code_) \
    do { \
        KreitInterruptInfo tmp = { .env = env_, .intno = intno_, .error_code = error_code_ }; \
        __kreit_instrument(KREIT_INSTR_INTTERUPT, &tmp); \
    } while(0)

typedef struct KreitEnvPC {
    void *env;
    uint64_t pc;
} KreitEnvPC;

#define kreit_trace_tb_start_addr(env_, pc_) \
    do { \
        KreitEnvPC tmp = { .env = env_, .pc = pc_ }; \
        __kreit_instrument(KREIT_INSTR_TB_START_ADDR, &tmp); \
    } while(0)

#define kreit_trace_gen_tb_start(addr) \
    __kreit_instrument(KREIT_INSTR_GEN_TB_START, (void *)addr)

#define kreit_trace_breakpoint(cpu) \
    __kreit_instrument(KREIT_INSTR_BREAKPOINT, (void *)cpu)

typedef struct KreitSwitchPair {
    int prev;
    int next;
    char prev_name[PROCESS_NAME_LENGTH];
    char next_name[PROCESS_NAME_LENGTH];
    uint64_t switch_index;
    void *cpu;
} KreitSwitchPair;

#define kreit_trace_context_switch(spair) \
    __kreit_instrument(KREIT_INSTR_TRACE_CONTEXT_SWITCH, (void *)spair)

#define kreit_trace_die(env_) \
    __kreit_instrument(KREIT_INSTR_TRACE_DIE, (void *)env_)

#define kreit_trace_asan_hook(hook) \
    do { \
        __kreit_instrument(KREIT_INSTR_ASAN_HOOK, hook); \
    } while(0)

typedef struct KreitDisasContext {
    void *db;   /* DisasContextBase */
    void *cpu;  /* CPUState */
} KreitDisasContext;

#define kreit_trace_insn_trans__(instr_, db_, cpu_) \
    do { \
        KreitDisasContext tmp = {.db = db_, .cpu = cpu_}; \
        __kreit_instrument(instr_, &tmp); \
    } while(0)

#define kreit_trace_insn_trans_pre(cpu, db) \
    kreit_trace_insn_trans__(KREIT_INSTR_INSN_TRANS_PRE, cpu, db)

#define kreit_trace_insn_trans_post(cpu, db) \
    kreit_trace_insn_trans__(KREIT_INSTR_INSN_TRANS_POST, cpu, db)

typedef struct KreitInsnLoadContext {
    uint64_t pc;
    size_t ld_size;
    void *value;
    bool *patched;
} KreitInsnLoadContext;

#define kreit_trace_insn_load(pc_, ld_size_, value_, patched_) \
    do { \
        KreitInsnLoadContext tmp = { \
            .pc = pc_, \
            .ld_size = ld_size_, \
            .value = value_, \
            .patched = patched_ \
        }; \
        __kreit_instrument(KREIT_INSTR_INSN_LOAD, &tmp); \
    } while(0)

#endif // __KREIT_INSTRUMENT_H__
