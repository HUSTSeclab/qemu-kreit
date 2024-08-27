# QEMU-KREIT README

This is a modified qemu based on v8.1.3, which is aimed to provided various instrumentation for binary-only kernel fuzzing, crash analysis and so on.

## Basic Function

- Binary-only coverage collection
- Binary-only address sanitizer for full-system mode
- Full-system mode instruction trace
- Full-system mode crash dump for crash analysis

## Design Principle

- Easy to migrate to other qemu version
- Minimal configuration for various binary-only kernel programs
- Flexible tracing configuration (e.g., instruction trace for a specified thread)

## State

Now the project is still in demo state, for reproducing please refer to xxx.
