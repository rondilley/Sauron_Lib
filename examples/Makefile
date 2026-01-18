# Sauron Library Examples Makefile
# Copyright (c) 2024-2026, Ron Dilley

CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -O2 -I../include
LDFLAGS = -L../src/.libs -lsauron -Wl,-rpath,$(abspath ../src/.libs)

# C examples
C_EXAMPLES = example_basic example_concurrent stress_test

# Python examples
PY_EXAMPLES = example_specter.py example_concurrent.py

.PHONY: all clean run run-c run-python run-concurrent help

all: $(C_EXAMPLES)

example_basic: example_basic.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

example_concurrent: example_concurrent.c
	$(CC) $(CFLAGS) -pthread -o $@ $< $(LDFLAGS)

stress_test: stress_test.c
	$(CC) $(CFLAGS) -pthread -o $@ $< $(LDFLAGS)

# Run all examples
run: run-c run-python

# Run C examples
run-c: $(C_EXAMPLES)
	@echo "=============================="
	@echo "Running C Example"
	@echo "=============================="
	@echo ""
	./example_basic
	@echo ""

# Run Python examples
run-python:
	@echo "=============================="
	@echo "Running Python Example"
	@echo "=============================="
	@echo ""
	@LD_LIBRARY_PATH=../src/.libs python3 example_specter.py
	@echo ""

# Run stress tests with different presets
stress-small: stress_test
	./stress_test small

stress-medium: stress_test
	./stress_test medium

stress-large: stress_test
	./stress_test large

# Run concurrent stress tests (C and Python)
run-concurrent: example_concurrent
	@echo "=============================="
	@echo "Running C Concurrent Stress Test"
	@echo "=============================="
	@echo ""
	./example_concurrent 10 4 2
	@echo ""
	@echo "=============================="
	@echo "Running Python Concurrent Stress Test"
	@echo "=============================="
	@echo ""
	@LD_LIBRARY_PATH=../src/.libs python3 example_concurrent.py 10 4 2
	@echo ""

clean:
	rm -f $(C_EXAMPLES)
	rm -f /tmp/sauron_*.dat /tmp/sauron_*.csv

help:
	@echo "Sauron Library Examples and Stress Tests"
	@echo ""
	@echo "Targets:"
	@echo "  all            - Build all C examples"
	@echo "  run            - Run all examples (C and Python)"
	@echo "  run-c          - Run C examples only"
	@echo "  run-python     - Run Python examples only"
	@echo "  run-concurrent - Run concurrent stress tests (C and Python)"
	@echo "  stress-small   - Stress test: 1M entries, 10 seconds"
	@echo "  stress-medium  - Stress test: 10M entries, 30 seconds"
	@echo "  stress-large   - Stress test: 100M entries, 60 seconds"
	@echo "  clean          - Remove built binaries"
	@echo ""
	@echo "Examples:"
	@echo "  example_basic        - C: Demonstrates all core library features"
	@echo "  example_concurrent   - C: Concurrent stress test"
	@echo "  stress_test          - C: Comprehensive stress test with metrics"
	@echo "  example_specter.py   - Python: Simulated threat detection workflow"
	@echo "  example_concurrent.py - Python: Concurrent stress test"
	@echo ""
	@echo "Stress test usage:"
	@echo "  ./stress_test small|medium|large"
	@echo "  ./stress_test custom <entries> <duration_sec> <readers> <writers>"
	@echo "  Example: ./stress_test custom 50000000 45 8 4"
