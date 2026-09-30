# Empirical Study

This directory contains the empirical study data of the paper, which is used to determine the distance threshold $\tau$ for GVAP collection (Section 3.1 of the paper).

```
EmpiricalStudy/
├── EmpiricalStudyData.csv   # the empirical study table
└── README.md
```

We perform a search-based survey of issues submitted since 2015 and manually verify the reported issues and corresponding fixes, identifying 15 real atomicity violations. `EmpiricalStudyData.csv` lists the 15 previously confirmed and fixed atomicity violations collected from real-world open-source embedded software projects.

`EmpiricalStudyData.csv` has one row per atomicity violation, with the following columns: project name, issue link, execution context, atomicity violation type, global variable(s), locations of global variable accesses (X, INT and Y) and the ARM instruction distance between accesses X and Y.

## Distance measurement

For each case, we extract the code region containing the atomicity violation, compile it for ARM, and inspect the generated assembly instructions to measure the instruction distance between the two accesses whose atomicity is broken. We use ARM as the reference architecture because it is widely adopted in MCU-based systems and supported by all studied projects. The maximum observed distance is about 80 instructions. We therefore set $\tau$ to 120, introducing a 50% margin to accommodate variations in compilation and runtime contexts while still filtering excessively distant access pairs.
