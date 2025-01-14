DEF_HELPER_FLAGS_1(kreit_trace_die, TCG_CALL_NO_RWG, void, env)
DEF_HELPER_FLAGS_2(kreit_trace_tb_start, TCG_CALL_NO_RWG, void, env, i64)
DEF_HELPER_FLAGS_1(kreit_trace_context_switch, TCG_CALL_NO_RWG, void, env)
DEF_HELPER_FLAGS_2(kreit_trace_asan_hook, TCG_CALL_NO_RWG, void, env, i32)

DEF_HELPER_FLAGS_2(qasan_load1, TCG_CALL_NO_RWG, void, env, i64)
DEF_HELPER_FLAGS_2(qasan_load2, TCG_CALL_NO_RWG, void, env, i64)
DEF_HELPER_FLAGS_2(qasan_load4, TCG_CALL_NO_RWG, void, env, i64)
DEF_HELPER_FLAGS_2(qasan_load8, TCG_CALL_NO_RWG, void, env, i64)
DEF_HELPER_FLAGS_2(qasan_load16, TCG_CALL_NO_RWG, void, env, i64)
DEF_HELPER_FLAGS_2(qasan_store1, TCG_CALL_NO_RWG, void, env, i64)
DEF_HELPER_FLAGS_2(qasan_store2, TCG_CALL_NO_RWG, void, env, i64)
DEF_HELPER_FLAGS_2(qasan_store4, TCG_CALL_NO_RWG, void, env, i64)
DEF_HELPER_FLAGS_2(qasan_store8, TCG_CALL_NO_RWG, void, env, i64)
DEF_HELPER_FLAGS_2(qasan_store16, TCG_CALL_NO_RWG, void, env, i64)