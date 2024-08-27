/*
 * Kreit tracing data struct version 0.7
 */
#ifndef __KREIT_TRACE_H__
#define __KREIT_TRACE_H__

#include <stdint.h>

#include "cpu.h"
#include "hw/core/cpu.h"
#include "exec/exec-all.h"

typedef enum KTraceType {
    KRETI_TRACE_INST_GOTO_TB = 0x11,
    KRETI_TRACE_INST_TB_ENTRY = 0x21,
    KREIT_TRACE_INST_INT = 0x31,
    KREIT_TRACE_ATTR_CONTEXT_SWITCH = 0x12,
    KREIT_TRACE_ATTR_TIMESTAMP = 0x22,
    KREIT_TRACE_ATTR_REG_VAL = 0x32
} KTraceType;

#define kreit_flag_is_trace_inst(flag) ((flag) & 0x1)
#define kreit_flag_is_trace_event(flag) ((flag) & 0x2)

#define kreit_obj_is_trace_inst(obj) (kreit_flag_is_trace_inst((obj)->flag))
#define kreit_obj_is_trace_event(obj) (kreit_flag_is_trace_event((obj)->flag))

typedef struct switch_pair {
    int prev;
    int next;
    uint64_t index;
} switch_pair;

typedef uint64_t timestamp_t;

typedef struct register_vals {
    size_t size;
    char *valbuf;
} register_vals;

typedef struct KreitTraceObj {
    KTraceType flag;
    int cpl;
    union {
        uint16_t goto_index;
        target_ulong next_pc;
        target_ulong int_pc;
        void *attr_data;
    };
} KreitTraceObj;

#define ATTR_CONTEXT_SWITCH(obj_ptr) ((switch_pair *)(obj_ptr->attr_data))
#define ATTR_TIMESTAMP(obj_ptr) ((timestamp_t *)(obj_ptr->attr_data))
#define ATTR_REG_VAL(obj_ptr) ((register_vals *)(obj_ptr->attr_data))

#define KREIT_DATA_HEADER_INST ((uint8_t)0x55)
#define KREIT_DATA_HEADER_ATTR ((uint8_t)0x65)

#endif
