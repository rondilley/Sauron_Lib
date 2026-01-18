# Sauron - IPv4 Scoring Engine
# Build shared library and CLI utility

# Shared library
lib_LTLIBRARIES = libsauron.la

libsauron_la_SOURCES = \
    sauron.c \
    mem.c mem.h \
    util.c util.h \
    ../include/sauron.h \
    ../include/common.h \
    ../include/sysdep.h \
    ../include/config.h

libsauron_la_LDFLAGS = -version-info 0:1:0 -shared
libsauron_la_LIBADD = -lpthread -lm

# CLI utility
bin_PROGRAMS = sauron-cli

sauron_cli_SOURCES = \
    sauron_cli.c \
    ../include/sauron.h \
    ../include/common.h \
    ../include/config.h

sauron_cli_LDADD = libsauron.la -lpthread -lm

# Install public header
include_HEADERS = ../include/sauron.h

# Compiler flags
AM_CFLAGS = -Wall -Wextra -Wstrict-prototypes -std=c11
AM_CFLAGS += -O2

# Static Analysis Targets
ANALYZE_FILES = sauron.c mem.c util.c sauron_cli.c

.PHONY: static-analysis cppcheck

static-analysis:
	@echo "Running static analysis..."
	@$(MAKE) cppcheck
	@echo "Static analysis complete."

cppcheck:
	@if command -v cppcheck >/dev/null 2>&1; then \
		echo "Running cppcheck..."; \
		cppcheck --enable=all --std=c11 -I../include $(ANALYZE_FILES) || true; \
	else \
		echo "cppcheck not available"; \
	fi

clean-local:
	@rm -f *.o *.lo

# Test target placeholder
.PHONY: test
test:
	@echo "Running tests..."
	@echo "TODO: Implement test suite"
