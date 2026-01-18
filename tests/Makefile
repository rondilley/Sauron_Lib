# Sauron Complete Test Suite Makefile
# Copyright (c) 2024-2026, Ron Dilley

CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -O2 -I../include
LDFLAGS = -L../src/.libs -lsauron -lpthread -lm -Wl,-rpath,$(abspath ../src/.libs)

# All test binaries
TESTS = test_basic test_threading test_performance test_edge_cases test_stress

# Benchmark binaries
BENCHMARKS = bench_bulk_verify

.PHONY: all clean test quick full valgrind

all: $(TESTS)

test_basic: test_basic.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

test_threading: test_threading.c
	$(CC) $(CFLAGS) -pthread -o $@ $< $(LDFLAGS)

test_performance: test_performance.c
	$(CC) $(CFLAGS) -pthread -o $@ $< $(LDFLAGS)

test_edge_cases: test_edge_cases.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

test_stress: test_stress.c
	$(CC) $(CFLAGS) -pthread -o $@ $< $(LDFLAGS)

bench_bulk_verify: bench_bulk_verify.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# Quick test - basic functionality only
quick: test_basic test_edge_cases
	@echo "=============================="
	@echo "Running Quick Tests"
	@echo "=============================="
	./test_basic
	@echo ""
	./test_edge_cases
	@echo ""
	@echo "Quick tests completed!"

# Full test suite
test: all
	@echo "=============================="
	@echo "Running Complete Test Suite"
	@echo "=============================="
	@echo ""
	@echo "[1/6] Basic Functionality Tests"
	@echo "------------------------------"
	./test_basic
	@echo ""
	@echo "[2/6] Edge Case Tests"
	@echo "------------------------------"
	./test_edge_cases
	@echo ""
	@echo "[3/6] Threading Tests"
	@echo "------------------------------"
	./test_threading
	@echo ""
	@echo "[4/6] Performance Tests"
	@echo "------------------------------"
	./test_performance
	@echo ""
	@echo "[5/6] Stress Tests"
	@echo "------------------------------"
	./test_stress
	@echo ""
	@echo "[6/6] Python Binding Tests"
	@echo "------------------------------"
	@LD_LIBRARY_PATH=../src/.libs python3 test_python.py
	@echo ""
	@echo "=============================="
	@echo "All tests completed!"
	@echo "=============================="

# Bulk load verification benchmark
benchmark: $(BENCHMARKS)
	@echo "=============================="
	@echo "Bulk Load Verification Benchmark"
	@echo "=============================="
	./bench_bulk_verify 1000000

# Full test with Python benchmark
full: test
	@echo ""
	@echo "[Bonus] Python Performance Benchmark"
	@echo "------------------------------"
	@LD_LIBRARY_PATH=../src/.libs python3 test_python.py --benchmark

# Memory leak check with Valgrind
valgrind: test_basic test_edge_cases
	@echo "=============================="
	@echo "Running Valgrind Memory Check"
	@echo "=============================="
	@echo ""
	@echo "Checking test_basic..."
	LD_LIBRARY_PATH=../src/.libs valgrind --leak-check=full --error-exitcode=1 ./test_basic 2>&1 | tail -20
	@echo ""
	@echo "Checking test_edge_cases..."
	LD_LIBRARY_PATH=../src/.libs valgrind --leak-check=full --error-exitcode=1 ./test_edge_cases 2>&1 | tail -20

# ThreadSanitizer check
tsan: CFLAGS += -fsanitize=thread -g
tsan: LDFLAGS += -fsanitize=thread
tsan: clean test_threading
	@echo "=============================="
	@echo "Running ThreadSanitizer Check"
	@echo "=============================="
	./test_threading

clean:
	rm -f $(TESTS) $(BENCHMARKS)
	rm -f /tmp/sauron_*.dat /tmp/bulk_bench_verify.csv

help:
	@echo "Sauron Test Suite"
	@echo ""
	@echo "Targets:"
	@echo "  all       - Build all tests"
	@echo "  test      - Run complete test suite"
	@echo "  quick     - Run quick tests (basic + edge cases)"
	@echo "  full      - Run complete tests + Python benchmark"
	@echo "  benchmark - Run bulk load verification benchmark (1M entries)"
	@echo "  valgrind  - Run memory leak check"
	@echo "  tsan      - Build and run with ThreadSanitizer"
	@echo "  clean     - Remove test binaries"
	@echo ""
	@echo "Individual tests:"
	@echo "  ./test_basic       - Core functionality"
	@echo "  ./test_edge_cases  - Boundary conditions, error paths"
	@echo "  ./test_threading   - Concurrent access"
	@echo "  ./test_performance - Performance benchmarks"
	@echo "  ./test_stress      - Long-running stability"
	@echo ""
	@echo "Benchmarks:"
	@echo "  ./bench_bulk_verify [N] - Verify bulk load with N entries (default 100K)"
