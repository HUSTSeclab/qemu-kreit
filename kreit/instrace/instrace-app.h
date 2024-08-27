typedef struct KreitInstraceData {
    // for instructions tracing
    bool log_reg_val;
    //KreitRecorder *krec;
    size_t nr_cpus;
    uint64_t trace_id;
    char output_path[FILENAME_MAX - TRACE_FILE_NAME_LENGTH];
} KreitInstraceData;
