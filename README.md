# GVAP-Fuzz Artifact

This repository contains the artifact for the GVAP-Fuzz paper: the bug dataset, the empirical study data and the source code of GVAP-Fuzz.

## Repository Structure

```
Artifact/
├── BugDataset/        # Bug dataset used in the evaluation
├── EmpiricalStudy/    # Empirical study data
├── GVAP-Fuzz-Src/     # Source code of GVAP-Fuzz
└── README.md
```

## Content

### BugDataset

30 real atomicity violations found by GVAP-Fuzz in 12 open-source RIOT MCU drivers. See `BugDataset/README.md` for details.

### EmpiricalStudy

The empirical study data of the paper: 15 previously confirmed and fixed atomicity violations collected from real-world open-source embedded software projects. See `EmpiricalStudy/README.md` for details.

### GVAP-Fuzz-Src

Source code of GVAP-Fuzz, implemented on the QEMU and VTest simulation platforms. See `GVAP-Fuzz-Src/README.md` for details.
