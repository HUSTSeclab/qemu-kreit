/**
 * Header only library for running ring0 function
 */
#ifndef BOKASAN_TEST_RING0_H
#define BOKASAN_TEST_RING0_H

#include <stdio.h>
#include <sys/neutrino.h>
#include <unistd.h>

#define __WEAK __attribute__((weak))

typedef enum {
    S_IDLE,
    S_PREPARED,
    S_RUNNING,
    S_FINISHED,
} running_state_t;

typedef void ring0_func_t(void);

__WEAK volatile running_state_t g_state = 0;

__WEAK ring0_func_t *g_func = 0;

__WEAK int g_interrupt_id = 0;

__WEAK void idle_interrupt_handler(unsigned int cpu, struct syspage_entry *spp,
                                   struct _idle_hook *ihp) {
    if (!__sync_bool_compare_and_swap(&g_state, S_PREPARED, S_RUNNING)) return;
    InterruptDisable();
    if (g_func != NULL) {
        g_func();
    }
    g_state = S_FINISHED;
    InterruptEnable();
}

__WEAK int ensure_regist_handler() {
    static int is_registed = 0;
    if (is_registed) return 1;
    is_registed = 1;

    g_interrupt_id = InterruptHookIdle2(idle_interrupt_handler, 0);
    if (g_interrupt_id < 0) {
        perror("Enter ring0 (InterruptHook) failed");
        return 0;
    }
    return 1;
}

/**
 * @brief In this call back, we enter Ring0 and execute func
 * @note This function is not reentrant.
 *
 * To print something in Ring0, you can use KERNEL_PRINT macro after
 * init() is called.
 *
 * @param func The function to be executed in Ring0, i.e. kernel mode.
 * @note func should not call function like printf.
 *
 * @return int 0 if success, -1 if failed. -2 if reenter.
 */
__WEAK int ring0(ring0_func_t *func) {
    if (!ensure_regist_handler()) return -1;  // failed: -1
    if (g_state != S_IDLE) {
        return -2;  // reenter, return busy: -2
    }
    g_func = func;
    g_state = S_PREPARED;
    printf("KASAN TEST [DEBUG] Ring0 prepared, g_state: %d\n", g_state);
    // Wait for ISR to wake us up
    int try_count = 3;
    while (g_state != S_FINISHED) {
        sleep(1);
        printf(
            "KASAN TEST [DEBUG] Wait for ring0 function success, g_state: %d\n",
            g_state);
        try_count--;
        if (try_count <= 0) {
            g_state = S_IDLE;
            printf(
                "KASAN TEST [DEBUG] Ring0 function failed, set g_state to "
                "S_IDLE\n");
            return -1;
        }
    }
    g_state = S_IDLE;
    return 0;
}

#endif  // BOKASAN_TEST_RING0_H
