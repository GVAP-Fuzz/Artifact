# GVAP-Fuzz

Source code of **GVAP-Fuzz**, the fuzzing tool presented in the paper for detecting atomicity violations in interrupt-driven embedded software. Figure 6 of the paper shows three components, an input generator, a runtime
monitor, and an interrupt controller. Each component has a QEMU version and a
VTest version. This document only covers how to build and run the code.

## Repository layout

| Path                                     | Contents                                                                                                                                                  |
| ---------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `runtime_monitor/qemu/`                | QEMU runtime monitor: TCG plugin`atomicity_plugin_stack.c`, GVAP table writer `gvap_cov.c`.                                                           |
| `runtime_monitor/vtest/`               | VTest runtime monitor and the simulation driver.                                                                                                          |
| `interrupt_controller/qemu/`           | QEMU interrupt controller (`gvap_irq_broker.c`). Reads `GVAP_INJECT_SITE` and `GVAP_INJECT_IRQ`.                                                    |
| `interrupt_controller/vtest/`          | VTest interrupt controller. Algorithm 1 lives in`gvap_injection.py`.                                                                                    |
| `input_generator/qemu/custom_mutator/` | AFL++ custom mutators.`gvap_feedback.c` is GVAP-coverage feedback. `gvap_feedback_only.c` is traditional code-coverage feedback.                      |
| `input_generator/qemu/runtime/`        | Shared-memory bridge, packet opcode interpreters, and`gvap_opcode_driver.c`.                                                                            |
| `input_generator/vtest/`               | VTest input generator (`mutater.py`).                                                                                                                   |
| `scripts/`                             | `run_gvap.sh`, `build_harnesses.sh`, `gen_metadata_with_watchlist.py`, `gen_gvap_seed_report.py`, `filter_metadata.py`, `dedupe_qemu_log.sh`. |
| `config/benchmarks.json`               | Benchmark list used by`scripts/run_gvap.sh`. Keys that start with `_` are ignored by `list`.                                                        |

## Dependencies

- **AFL++ 4.35c** (`afl-fuzz`, `afl-clang-fast`), built from source.
- **QEMU 6.2 source tree** — `include/qemu/qemu-plugin.h` is needed to build the plugin.
- A host C toolchain (`gcc`) and `python3`.

## Building

Run the commands below from this directory. Set `QEMU_SRC` to the QEMU 6.2 tree and `AFL_INCLUDE` to the AFL++ `include` directory.

### Runtime monitor (QEMU plugin)

```sh
gcc -shared -fPIC -I"$QEMU_SRC/include/qemu" \
  runtime_monitor/qemu/atomicity_plugin_stack.c \
  -o runtime_monitor/qemu/atomicity_plugin_stack.so
```

### VTest components

```sh
make -C interrupt_controller/vtest check
make -C interrupt_controller/vtest inject
```

## Running

`scripts/run_gvap.sh` drives the two phases in the paper. `GVAP_ROOT` selects
the benchmark environment and defaults to this directory.

```sh
# Phase 1: collect GVAPs
GVAP_ROOT=/path/to/bench-env bash scripts/run_gvap.sh collect --benchmark stm32_uart

# Phase 2: replay, inject the IRQ after GVAx, watch GVAy inside Dist+delta
GVAP_ROOT=/path/to/bench-env bash scripts/run_gvap.sh validate \
    --benchmark stm32_uart --site wr_tail --irq usart1
```

Useful environment variables: `GVAP_ROOT`, `GVAP_PLUGIN_SO`, `QEMU_BIN`,
`TIMEOUT`, `LD_COMPAT`, `SITE`, `IRQ_NAME`, `GVAP_INJECT_SITE`,
`GVAP_INJECT_IRQ`, `GVAP_COVERAGE_FILE`.
