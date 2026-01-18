# Sauron - High-Speed IPv4 Scoring Engine

Sauron is a C library for ultra-fast IP threat/risk scoring, designed for high-throughput security analytics pipelines.

## Overview

Sauron maintains in-memory risk scores for IPv4 addresses with:

- Lock-free reads at hundreds of millions of operations per second
- Efficient memory usage through hierarchical /24 CIDR blocks
- 2MB bitmap filter for fast negative lookups (80-90% of lookups return immediately)
- Automatic score decay toward neutral over time
- Bulk loading from CSV files or buffers
- Persistent state with atomic archive/restore
- Full thread safety for concurrent access
- Python bindings via ctypes

## Performance (Measured)

**Single-threaded:**
- **GET**: 165M ops/sec (lock-free)
- **SET**: 70-97M ops/sec
- **INCR**: 102M ops/sec

**Multi-threaded (8 cores):**
- **GET**: 687M ops/sec
- **SET**: 140M ops/sec
- **Decay**: 738M scores/sec

**Concurrent stress test (4 readers, 2 writers, bulk loader, decay):**
- **Reads**: 85M ops/sec
- **Writes**: 9M ops/sec

**Memory:**
- ~2.6MB base (bitmap + context)
- ~540 bytes per active /24 network

## Quick Start

### Build

```bash
./bootstrap
./configure
make
make check  # Run tests
sudo make install
```

### C Usage

```c
#include <sauron.h>

// Create context
sauron_ctx_t *ctx = sauron_create();

// Update scores
sauron_incr(ctx, "192.168.1.100", 10);  // Increase risk
sauron_decr(ctx, "10.0.0.1", 5);        // Decrease risk (more trusted)

// Query scores
int16_t score = sauron_get(ctx, "192.168.1.100");

// Use faster u32 versions for high-throughput
uint32_t ip = sauron_ip_to_u32("192.168.1.100");
score = sauron_get_u32(ctx, ip);
sauron_incr_u32(ctx, ip, 10);

// Periodic decay (e.g., hourly)
sauron_decay(ctx, 0.99, 5);  // 1% decay, deadzone=5

// Save/restore
sauron_save(ctx, "/var/lib/sauron/scores.dat");
sauron_load(ctx, "/var/lib/sauron/scores.dat");

// Cleanup
sauron_destroy(ctx);
```

### Python Usage

```python
from sauron import Sauron

with Sauron() as s:
    s.incr("192.168.1.100", 10)
    score = s.get("192.168.1.100")
    s.decay(0.99, 5)
    s.save("/var/lib/sauron/scores.dat")

# Faster u32 operations
with Sauron() as s:
    ip = Sauron.ip_to_u32("192.168.1.100")
    s.incr_u32(ip, 10)
    score = s.get_u32(ip)
```

### CLI Usage

```bash
# Get score
$ sauron-cli get 192.168.1.100
192.168.1.100: 0

# Set score
$ sauron-cli set 192.168.1.100 50
192.168.1.100: 0 -> 50

# Increment
$ sauron-cli incr 192.168.1.100 10
192.168.1.100: 60

# Use persistent archive
$ sauron-cli -f /var/lib/sauron/scores.dat set 10.0.0.1 100
10.0.0.1: 0 -> 100

# Show stats
$ sauron-cli stats
Sauron IPv4 Scoring Engine v0.1.0
Active scores:    1
Allocated blocks: 1
Memory usage:     2625072 bytes

# Run benchmark
$ sauron-cli benchmark 1000000
```

## Score Semantics

- **Positive scores (1 to 32767)**: Higher risk/threat (suspicious, malicious)
- **Negative scores (-32767 to -1)**: More trusted (known good)
- **Zero (0)**: Neutral / no data

Scores use saturating arithmetic - incrementing past 32767 clamps at 32767.

---

## Complete C API Reference

### Lifecycle Functions

```c
sauron_ctx_t *sauron_create(void);
```
Create a new scoring engine context. Returns pointer to context, or NULL on failure.

```c
void sauron_destroy(sauron_ctx_t *ctx);
```
Destroy a context and free all resources. Safe to pass NULL.

### Score Operations (String IP)

These functions accept IPv4 addresses as dotted-decimal strings (e.g., "192.168.1.1").

```c
int16_t sauron_get(sauron_ctx_t *ctx, const char *ip);
```
Get the score for an IP. Returns 0 if not found or invalid.

```c
int16_t sauron_set(sauron_ctx_t *ctx, const char *ip, int16_t score);
```
Set the score for an IP. Returns the previous score value.

```c
int16_t sauron_incr(sauron_ctx_t *ctx, const char *ip, int16_t delta);
```
Increment the score (saturating at -32767/+32767). Returns the new score.

```c
int16_t sauron_decr(sauron_ctx_t *ctx, const char *ip, int16_t delta);
```
Decrement the score. Equivalent to `sauron_incr(ctx, ip, -delta)`.

```c
int sauron_delete(sauron_ctx_t *ctx, const char *ip);
```
Delete the score for an IP (set to 0). Returns `SAURON_OK` on success.

### Score Operations (uint32 IP - Fast Path)

These functions accept IPv4 addresses as uint32_t in host byte order. **Recommended for high-throughput applications** as they skip string parsing overhead.

```c
int16_t sauron_get_u32(sauron_ctx_t *ctx, uint32_t ip);
int16_t sauron_set_u32(sauron_ctx_t *ctx, uint32_t ip, int16_t score);
int16_t sauron_incr_u32(sauron_ctx_t *ctx, uint32_t ip, int16_t delta);
int16_t sauron_decr_u32(sauron_ctx_t *ctx, uint32_t ip, int16_t delta);
int sauron_delete_u32(sauron_ctx_t *ctx, uint32_t ip);
```

### Extended Operations

```c
int sauron_get_ex(sauron_ctx_t *ctx, uint32_t ip, int16_t *score_out);
```
Get score with explicit error reporting. Unlike `sauron_get_u32()`, this distinguishes between "score is 0" and "not found". Returns `SAURON_OK` if found, `SAURON_ERR_INVALID` if not found.

```c
int sauron_clear(sauron_ctx_t *ctx);
```
Clear all scores without destroying the context. More efficient than destroy/create cycle.

### Batch Operations

```c
int sauron_incr_batch(sauron_ctx_t *ctx, const uint32_t *ips,
                      const int16_t *deltas, size_t count);
```
Increment scores for multiple IPs in a single call. Returns the number of successful increments.

### Bulk Loading

Load scores from CSV files or memory buffers. Supports both absolute sets and relative updates.

```c
typedef struct sauron_bulk_result {
    uint64_t lines_processed;   // Total lines read
    uint64_t lines_skipped;     // Lines skipped (invalid, parse errors)
    uint64_t sets;              // Absolute sets performed
    uint64_t updates;           // Relative updates performed
    uint64_t parse_errors;      // Lines with parse errors
    double elapsed_seconds;     // Total time
    double lines_per_second;    // Processing rate
} sauron_bulk_result_t;

int sauron_bulk_load(sauron_ctx_t *ctx, const char *filename,
                     sauron_bulk_result_t *result);

int sauron_bulk_load_buffer(sauron_ctx_t *ctx, const char *data, size_t len,
                            sauron_bulk_result_t *result);
```

**CSV Format:**
```
IP,CHANGE
```

Where CHANGE is:
- Absolute value: `100` (sets score to 100)
- Negative absolute: `-25` (sets score to -25)
- Relative increment: `+10` (adds 10 to current score)
- Relative decrement: `+-5` (subtracts 5 from current score)

**Example file:**
```csv
# Comments start with #
192.168.1.1,100       # Set to 100
192.168.1.2,+50       # Add 50 to current score
10.0.0.1,-25          # Set to -25 (negative score)
10.0.0.2,+-10         # Subtract 10 from current score
```

### Decay

```c
uint64_t sauron_decay(sauron_ctx_t *ctx, float decay_factor, int16_t deadzone);
```
Apply decay to all scores. Multiplies each score by `decay_factor` (0.0-1.0). Scores with absolute value ≤ `deadzone` after decay are deleted. Returns the number of scores modified/deleted.

**Example:**
```c
// Reduce all scores by 1%, delete scores within ±5 of zero
uint64_t modified = sauron_decay(ctx, 0.99f, 5);
printf("Modified %lu scores\n", modified);
```

### Iteration

```c
typedef int (*sauron_foreach_cb)(uint32_t ip, int16_t score, void *user_data);

uint64_t sauron_foreach(sauron_ctx_t *ctx, sauron_foreach_cb callback, void *user_data);
```
Iterate over all scored IPs. The callback receives each IP and score; return 0 to continue, non-zero to stop early. Returns the number of IPs iterated.

**Warning:** Do not call other sauron functions from within the callback to avoid deadlocks.

**Example:**
```c
int print_score(uint32_t ip, int16_t score, void *user_data) {
    char buf[16];
    sauron_u32_to_ip_s(ip, buf, sizeof(buf));
    printf("%s: %d\n", buf, score);
    return 0;  // Continue iteration
}

sauron_foreach(ctx, print_score, NULL);
```

### Statistics

```c
uint64_t sauron_count(sauron_ctx_t *ctx);      // Active scores
uint64_t sauron_block_count(sauron_ctx_t *ctx); // Allocated /24 blocks
size_t sauron_memory_usage(sauron_ctx_t *ctx);  // Memory in bytes
```

### Persistence

```c
int sauron_save(sauron_ctx_t *ctx, const char *filename);
int sauron_load(sauron_ctx_t *ctx, const char *filename);
```
Save/load scores to/from binary archive files. Uses atomic writes (temp file + fsync + rename) to prevent corruption.

### Utility Functions

```c
uint32_t sauron_ip_to_u32(const char *ip);
```
Parse an IPv4 string to uint32. Returns 0 on invalid input.

```c
void sauron_u32_to_ip(uint32_t ip, char *buf);  // Deprecated
int sauron_u32_to_ip_s(uint32_t ip, char *buf, size_t buf_size);  // Safe version
```
Format a uint32 IP as a dotted-decimal string. Buffer must be at least 16 bytes.

```c
const char *sauron_version(void);
```
Get the library version string (e.g., "0.1.0").

### Error Codes

| Code | Value | Meaning |
|------|-------|---------|
| `SAURON_OK` | 0 | Success |
| `SAURON_ERR_NULL` | -1 | NULL pointer argument |
| `SAURON_ERR_INVALID` | -2 | Invalid argument |
| `SAURON_ERR_NOMEM` | -3 | Memory allocation failed |
| `SAURON_ERR_IO` | -4 | File I/O error |

---

## Complete Python API Reference

### Class: Sauron

```python
from sauron import Sauron
```

#### Constructor

```python
Sauron(library_path: Optional[str] = None)
```
Initialize the scoring engine. If `library_path` is not provided, the library is searched in standard locations.

#### Context Manager

```python
with Sauron() as s:
    s.set("192.168.1.1", 100)
    # Context automatically closed on exit
```

#### Score Operations (String IP)

```python
s.get(ip: str) -> int
```
Get the score for an IP. Returns 0 if not found.

```python
s.set(ip: str, score: int) -> int
```
Set the score for an IP. Returns the previous score.

```python
s.incr(ip: str, delta: int) -> int
```
Increment the score (saturating). Returns the new score.

```python
s.decr(ip: str, delta: int) -> int
```
Decrement the score. Returns the new score.

```python
s.delete(ip: str) -> bool
```
Delete the score for an IP. Returns True if successful.

#### Score Operations (uint32 IP - Fast Path)

```python
s.get_u32(ip: int) -> int
s.set_u32(ip: int, score: int) -> int
s.incr_u32(ip: int, delta: int) -> int
s.decr_u32(ip: int, delta: int) -> int
s.delete_u32(ip: int) -> bool
```
Same as string versions but accept uint32 IPs. **Faster** - no string parsing.

#### Extended Operations

```python
s.get_ex(ip: int) -> Optional[int]
```
Get score with explicit not-found handling. Returns `None` if not found, otherwise returns the score (including 0).

```python
s.clear() -> None
```
Clear all scores without destroying the context.

#### Bulk Loading

```python
s.bulk_load(filename: str) -> BulkLoadResult
```
Bulk load from a CSV file. Returns a `BulkLoadResult` namedtuple with statistics.

```python
s.bulk_load_string(data: str) -> BulkLoadResult
```
Bulk load from a string buffer.

**BulkLoadResult fields:**
- `lines_processed`: Total lines read
- `lines_skipped`: Lines skipped (invalid, parse errors)
- `sets`: Absolute sets performed
- `updates`: Relative updates performed
- `parse_errors`: Lines with parse errors
- `elapsed_seconds`: Total time
- `lines_per_second`: Processing rate

#### Decay

```python
s.decay(factor: float, deadzone: int = 10) -> int
```
Apply decay to all scores. Returns the number modified/deleted.

#### Statistics

```python
s.count() -> int        # Active scores
s.block_count() -> int  # Allocated blocks
s.memory_usage() -> int # Memory in bytes
s.stats() -> dict       # Combined stats
```

#### Persistence

```python
s.save(filename: str) -> None
s.load(filename: str) -> None
```
Save/load scores to/from archive files.

#### Utility Functions

```python
Sauron.ip_to_u32(ip: str) -> int  # Static method
Sauron.u32_to_ip(ip: int) -> str  # Static method
```
Convert between IP string and uint32 formats.

```python
s.version -> str  # Property
```
Get the library version string.

#### Lifecycle

```python
s.close() -> None
```
Destroy the engine and free resources. Safe to call multiple times.

### Exceptions

- `SauronError`: Base exception for all Sauron errors
- `SauronIOError`: I/O error during save/load operations
- `SauronMemoryError`: Memory allocation error

### Constants

```python
SAURON_SCORE_MIN = -32767
SAURON_SCORE_MAX = 32767
```

---

## Usage Examples

### Threat Detection Pipeline (Python)

```python
from sauron import Sauron

# Initialize at startup
scoring = Sauron()
scoring.load("/var/lib/sauron/scores.dat")

# Process events
for event in event_stream:
    for ip in event.source_ips:
        score = scoring.get(ip)

        if event.is_threat_indicator:
            scoring.incr(ip, event.severity * 10)
        elif event.is_legitimate:
            scoring.decr(ip, 5)  # Build trust

        # Check threshold
        if score > 1000:
            alert(f"High-risk IP detected: {ip} (score={score})")

# Hourly decay (via cron or scheduler)
scoring.decay(0.99, 5)  # 1% decay, deadzone=5
scoring.save("/var/lib/sauron/scores.dat")
```

### Bulk Loading (C)

```c
#include <sauron.h>

sauron_ctx_t *ctx = sauron_create();

sauron_bulk_result_t result;
int ret = sauron_bulk_load(ctx, "/data/threat_intel.csv", &result);

if (ret == SAURON_OK) {
    printf("Loaded %lu entries in %.2f seconds (%.1f/sec)\n",
           result.lines_processed - result.lines_skipped,
           result.elapsed_seconds,
           result.lines_per_second);
    printf("  Sets: %lu, Updates: %lu, Errors: %lu\n",
           result.sets, result.updates, result.parse_errors);
}

sauron_destroy(ctx);
```

### Bulk Loading (Python)

```python
from sauron import Sauron

with Sauron() as s:
    result = s.bulk_load("/data/threat_intel.csv")
    print(f"Loaded {result.lines_processed} lines in {result.elapsed_seconds:.2f}s")
    print(f"  Sets: {result.sets}, Updates: {result.updates}")

    # Or from string
    csv_data = """
    192.168.1.1,+100
    192.168.1.2,-50
    10.0.0.1,200
    """
    result = s.bulk_load_string(csv_data)
```

### Concurrent Access (C)

The library is fully thread-safe. Multiple threads can safely read and write concurrently.

```c
#include <pthread.h>
#include <sauron.h>

sauron_ctx_t *g_ctx;

void *reader_thread(void *arg) {
    while (running) {
        int16_t score = sauron_get_u32(g_ctx, random_ip());
        // Process score...
    }
    return NULL;
}

void *writer_thread(void *arg) {
    while (running) {
        sauron_incr_u32(g_ctx, random_ip(), 10);
    }
    return NULL;
}

int main() {
    g_ctx = sauron_create();

    // Start 4 reader threads, 2 writer threads
    pthread_t readers[4], writers[2];
    for (int i = 0; i < 4; i++)
        pthread_create(&readers[i], NULL, reader_thread, NULL);
    for (int i = 0; i < 2; i++)
        pthread_create(&writers[i], NULL, writer_thread, NULL);

    // ... wait for threads ...

    sauron_destroy(g_ctx);
    return 0;
}
```

### Concurrent Access (Python)

```python
import threading
from sauron import Sauron

s = Sauron()

def reader():
    while running:
        score = s.get_u32(random_ip())

def writer():
    while running:
        s.incr_u32(random_ip(), 10)

# Start threads
threads = [
    threading.Thread(target=reader) for _ in range(4)
] + [
    threading.Thread(target=writer) for _ in range(2)
]
for t in threads:
    t.start()
```

---

## Key Features

### Two-Level Lookup Structure

Sauron uses a 2MB bitmap to track which /24 networks have any scores. 80-90% of lookups for "clean" traffic return immediately without touching score data.

### Lock-Free Reads

Read operations require no locks - just atomic loads. Write operations use per-CIDR spinlocks, allowing parallel updates to different networks.

### Automatic Decay

Scores decay toward zero over time. Call `sauron_decay()` periodically (e.g., hourly):
- `decay_factor`: Multiplier (0.9 = 10% reduction, 0.99 = 1% reduction)
- `deadzone`: Scores with absolute value ≤ this become zero

### Persistence

State is saved to binary archive files:
- Atomic writes (temp file + fsync + rename) prevent corruption
- Load on startup to restore state

## IP Address Handling

All IPv4 addresses can be scored, including:
- Private ranges (RFC1918): 10/8, 172.16/12, 192.168/16
- CGNAT: 100.64/10
- Loopback: 127.0.0.0/8
- Link-local: 169.254.0.0/16
- Multicast: 224.0.0.0/4

Applications should implement their own filtering before calling Sauron if certain ranges should be excluded.

---

## Testing

```bash
# Build and run tests
cd tests
make test

# Run individual tests
./test_basic          # Basic functionality
./test_threading      # Thread safety
./test_performance    # Performance benchmarks
./test_edge_cases     # Edge cases and error handling

# Python tests
python3 test_python.py
python3 test_python.py --benchmark
```

### Examples and Stress Tests

```bash
cd examples

# Build examples
make

# Run basic example
./example_basic

# Run concurrent stress test
./example_concurrent 10 4 2  # 10 seconds, 4 readers, 2 writers

# Run comprehensive stress test
./stress_test small    # 1M entries, 10 seconds
./stress_test medium   # 10M entries, 30 seconds
./stress_test large    # 100M entries, 60 seconds
./stress_test custom 50000000 45 8 4  # Custom: 50M entries, 45s, 8 readers, 4 writers

# Python examples
python3 example_specter.py
python3 example_concurrent.py 10 4 2
```

## Architecture

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for detailed design documentation including:

- Data structure design and rationale
- Memory layout diagrams
- Threading model
- Lookup algorithms
- Persistence format

## License

GNU General Public License v3.0. See COPYING for details.

## Author

Ron Dilley <ron.dilley@uberadmin.com>
