# GVAP-Fuzz interrupt controller (VTest, MCS-51). Feasible interrupt set, then the inject command.
PYTHON ?= python3
HERE := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
.PHONY: check inject
check:
	$(PYTHON) -m py_compile $(HERE)gvap_injection.py \
		$(HERE)../../runtime_monitor/vtest/gvap_monitor.py \
		$(HERE)../../runtime_monitor/vtest/gvap_vtest_plugin.py \
		$(HERE)../../input_generator/vtest/mutater.py
inject: check
	$(PYTHON) $(HERE)gvap_injection.py
