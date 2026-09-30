# BugDataset

This directory contains the bug dataset: 12 open-source ARM-based MCU drivers from the RIOT embedded operating system (version 2026.04) and the records of the 30 real atomicity violations found in them. All of the 30 atomicity violations have been confirmed by the corresponding RIOT developers.

## Directory layout

```
BugDataset/
├── Programs/               # the 12 RIOT driver programs under test,
│                           # one folder per program: the driver source file
│                           # plus the RIOT headers it directly includes
│   ├── cc26xx_gpio/
│   ├── dose/
│   ├── gd32v_uart/
│   ├── nrf5x_gpio/
│   ├── rp2350_uart/
│   ├── rpx0xx_gpio/
│   ├── rpx0xx_uart/
│   ├── samd5x_gpio/
│   ├── samd5x_uart/
│   ├── slipdev/
│   ├── stm32_qdec/
│   └── stm32_uart/
└── Bugs.csv             # the 30 confirmed bug records
```

Driver program sources are from **RIOT 2026.04** (tag `2026.04`, commit `835e7a8b85f37dd8657db6ac1880f375fc097403`). Each program folder contains the driver program source file and its included headers, keeping their original RIOT-relative paths.

`Bugs.csv` has one row per atomicity violation, with the following columns: program name, atomicity violation type, global variable(s), execution context and locations of global variable accesses (X, INT and Y).
