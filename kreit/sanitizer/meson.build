kreit_sanitizer_ss = ss.source_set()

kreit_sanitizer_ss.add(files('common.c'))

subdir('asan')
# subdir('ubsan')

kreit_ss.add_all(kreit_sanitizer_ss)
