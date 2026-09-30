# GVAP-Fuzz Artifact

This repository contains the artifact for the GVAP-Fuzz paper: the bug dataset, the empirical study data, and the source code of GVAP-Fuzz.

## Repository Structure

```
Artifact/
├── BugDataset/        # Bug dataset used in the evaluation
├── EmpiricalStudy/    # Empirical study data
├── GVAP-Fuzz-Src/     # Source code of GVAP-Fuzz
└── README.md
```

## Contents

### BugDataset

12 open-source ARM-based MCU drivers from the RIOT embedded operating system (version 2026.04), together with the records of the 30 real atomicity violations found in them, all of which have been confirmed by the corresponding RIOT developers. See `BugDataset/README.md` for details.

### EmpiricalStudy

The empirical study data of the paper: 15 confirmed and fixed atomicity violations collected from real-world open-source embedded software projects, together with the measured instruction distances used to derive the distance threshold τ. See `EmpiricalStudy/README.md` for details.

### GVAP-Fuzz-Src

Source code of GVAP-Fuzz, implemented on the QEMU and VTest simulation platforms: 
the input generator collects data packets from virtual peripherals and organizes them into a packet sequence as the input to the tested program. the runtime monitor collects the runtime information required for GVAP construction and atomicity violation detection. the runtime monitor collects the runtime information required for GVAP construction and atomicity violation detection, and the runner scripts. See `GVAP-Fuzz-Src/README.md` for details.
