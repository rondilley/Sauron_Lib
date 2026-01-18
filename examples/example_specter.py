#!/usr/bin/env python3
"""
Sauron Library - Python Integration Example

Demonstrates practical usage patterns for integrating Sauron into
a threat detection system like Specter_AI. Shows:

- Context manager usage
- Score operations (get/set/incr/decr)
- Bulk loading from CSV
- Decay operations for score aging
- Persistence (save/load)
- Performance benchmarking
- Error handling

Run:
    LD_LIBRARY_PATH=../src/.libs python3 example_specter.py

Copyright (c) 2024-2026, Ron Dilley
"""

import os
import sys
import time
import tempfile
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "python"))

from sauron import Sauron, SauronError, SauronIOError, BulkLoadResult


def print_section(title: str) -> None:
    """Print a section header."""
    print(f"\n{'=' * 50}")
    print(f" {title}")
    print('=' * 50)


def print_stats(s: Sauron, label: str = "Current State") -> None:
    """Print scoring engine statistics."""
    stats = s.stats()
    print(f"\n--- {label} ---")
    print(f"  Active scores: {stats['count']:,}")
    print(f"  Blocks allocated: {stats['blocks']:,}")
    print(f"  Memory usage: {stats['memory'] / 1024:.2f} KB")


def demo_basic_operations(s: Sauron) -> None:
    """Demonstrate basic score operations."""
    print_section("Basic Score Operations")

    # Set some initial scores
    test_data = [
        ("192.168.1.100", 100, "Internal scanner activity"),
        ("10.0.0.50", -50, "Trusted internal server"),
        ("45.33.50.1", 200, "Known bad actor"),
        ("8.8.8.8", 10, "Low-risk public DNS"),
    ]

    print("\nSetting initial scores:")
    for ip, score, reason in test_data:
        old = s.set(ip, score)
        print(f"  {ip:20s} -> {score:6d}  ({reason})")

    # Read back scores
    print("\nReading scores:")
    for ip, expected, _ in test_data:
        actual = s.get(ip)
        status = "[OK]" if actual == expected else "[FAIL]"
        print(f"  {ip:20s} = {actual:6d}  {status}")

    # Increment on detection event
    print("\nSimulating detection events (incrementing scores):")
    events = [
        ("192.168.1.100", 25, "Port scan detected"),
        ("192.168.1.100", 50, "Brute force attempt"),
        ("45.33.50.1", 100, "Malware callback"),
    ]
    for ip, delta, event in events:
        new_score = s.incr(ip, delta)
        print(f"  {ip}: +{delta} ({event}) -> {new_score}")

    # Decrement for positive behavior
    print("\nSimulating positive behavior (decrementing scores):")
    s.decr("10.0.0.50", 20)
    print(f"  10.0.0.50: -20 (successful auth) -> {s.get('10.0.0.50')}")


def demo_uint32_api(s: Sauron) -> None:
    """Demonstrate faster uint32 API."""
    print_section("uint32 API (High-Performance Path)")

    # Convert IP to uint32 for faster operations
    ip_str = "45.33.60.1"
    ip_u32 = Sauron.ip_to_u32(ip_str)
    print(f"\nIP {ip_str} as uint32: {ip_u32} (0x{ip_u32:08x})")
    print(f"Convert back: {Sauron.u32_to_ip(ip_u32)}")

    # Use uint32 API
    s.set_u32(ip_u32, 500)
    print(f"\nset_u32({ip_u32}, 500) -> get_u32() = {s.get_u32(ip_u32)}")

    s.incr_u32(ip_u32, 100)
    print(f"incr_u32({ip_u32}, 100) -> get_u32() = {s.get_u32(ip_u32)}")

    # Benchmark: string vs uint32
    print("\nBenchmark: String API vs uint32 API (100K ops each):")

    iterations = 100000

    # String API
    start = time.perf_counter()
    for i in range(iterations):
        s.set("45.33.60.1", i % 32767)
    string_time = time.perf_counter() - start

    # uint32 API
    start = time.perf_counter()
    for i in range(iterations):
        s.set_u32(ip_u32, i % 32767)
    u32_time = time.perf_counter() - start

    print(f"  String API: {string_time:.3f}s ({iterations/string_time:,.0f} ops/sec)")
    print(f"  uint32 API: {u32_time:.3f}s ({iterations/u32_time:,.0f} ops/sec)")
    print(f"  Speedup: {string_time/u32_time:.1f}x")


def demo_bulk_loading(s: Sauron) -> None:
    """Demonstrate bulk loading from CSV."""
    print_section("Bulk Loading from CSV")

    # Create a sample CSV file
    csv_content = """# Threat intelligence feed
# Format: IP,SCORE (absolute) or IP,+DELTA (relative)
# Lines starting with # are comments

# Known malicious IPs
45.33.60.10,500
45.33.60.11,450
45.33.60.12,400

# Spam sources
45.33.50.50,200
45.33.50.51,+50

# Trusted networks (negative scores)
10.10.10.1,-100
10.10.10.2,-100

# Update existing (relative)
45.33.60.10,+100

# Relative decrement
45.33.50.50,+-25
"""

    with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
        f.write(csv_content)
        csv_file = f.name

    try:
        s.clear()
        print(f"\nLoading from: {csv_file}")
        print(f"File size: {os.path.getsize(csv_file)} bytes")

        result = s.bulk_load(csv_file)

        print(f"\nBulk load results:")
        print(f"  Lines processed: {result.lines_processed}")
        print(f"  Sets (absolute): {result.sets}")
        print(f"  Updates (relative): {result.updates}")
        print(f"  Skipped: {result.lines_skipped}")
        print(f"  Parse errors: {result.parse_errors}")
        print(f"  Elapsed: {result.elapsed_seconds:.6f} seconds")
        print(f"  Rate: {result.lines_per_second:,.0f} lines/sec")

        print(f"\nVerifying loaded scores:")
        verify = [
            ("45.33.60.10", 600),   # 500 + 100
            ("45.33.60.11", 450),
            ("45.33.50.50", 175),    # 200 - 25
            ("10.10.10.1", -100),
        ]
        for ip, expected in verify:
            actual = s.get(ip)
            status = "[OK]" if actual == expected else f"[FAIL: expected {expected}]"
            print(f"  {ip}: {actual} {status}")

    finally:
        os.unlink(csv_file)


def demo_bulk_load_string(s: Sauron) -> None:
    """Demonstrate bulk loading from string buffer."""
    print_section("Bulk Loading from String")

    s.clear()

    data = """45.33.70.1,100
45.33.70.2,200
45.33.70.3,+50
"""

    result = s.bulk_load_string(data)
    print(f"\nLoaded from string ({len(data)} bytes):")
    print(f"  Lines: {result.lines_processed}, Sets: {result.sets}, Updates: {result.updates}")
    print(f"  Scores: {s.count()}")


def demo_decay(s: Sauron) -> None:
    """Demonstrate decay operation."""
    print_section("Decay Operation (Score Aging)")

    s.clear()

    # Set up test scores
    test_ips = [
        ("45.33.70.1", 1000),
        ("45.33.70.2", 500),
        ("45.33.70.3", 100),
        ("45.33.70.4", 20),
        ("45.33.70.5", 5),
        ("45.33.70.6", -500),
    ]

    print("\nInitial scores:")
    for ip, score in test_ips:
        s.set(ip, score)
        print(f"  {ip}: {score}")

    print(f"\nApplying decay(factor=0.5, deadzone=15)...")
    modified = s.decay(0.5, 15)
    print(f"Modified: {modified} scores")

    print("\nAfter decay:")
    for ip, original in test_ips:
        current = s.get(ip)
        expected = int(original * 0.5) if abs(int(original * 0.5)) > 15 else 0
        status = "[deleted]" if current == 0 and expected == 0 else ""
        print(f"  {ip}: {original} -> {current} {status}")

    print("\nApplying 3 more decay cycles...")
    for i in range(3):
        modified = s.decay(0.5, 15)
        print(f"  Cycle {i+2}: {modified} modified, {s.count()} remaining")


def demo_persistence(s: Sauron) -> None:
    """Demonstrate save/load operations."""
    print_section("Persistence (Save/Load)")

    s.clear()

    # Set up test data
    test_data = {
        "192.168.1.1": 111,
        "192.168.1.2": 222,
        "192.168.1.3": -333,
    }

    for ip, score in test_data.items():
        s.set(ip, score)

    print(f"\nBefore save: {s.count()} scores")

    # Save to temp file
    with tempfile.NamedTemporaryFile(suffix='.dat', delete=False) as f:
        archive_file = f.name

    try:
        s.save(archive_file)
        file_size = os.path.getsize(archive_file)
        print(f"[OK] Saved to {archive_file} ({file_size} bytes)")

        # Clear and verify empty
        s.clear()
        print(f"After clear: {s.count()} scores")

        # Load and verify
        s.load(archive_file)
        print(f"After load: {s.count()} scores")

        print("\nVerifying loaded data:")
        all_ok = True
        for ip, expected in test_data.items():
            actual = s.get(ip)
            ok = actual == expected
            all_ok = all_ok and ok
            print(f"  {ip}: {actual} {'[OK]' if ok else f'[FAIL: expected {expected}]'}")

        if all_ok:
            print("\n[OK] All data verified correctly")

    finally:
        os.unlink(archive_file)


def demo_error_handling(s: Sauron) -> None:
    """Demonstrate error handling."""
    print_section("Error Handling")

    # Invalid score range
    print("\nTesting score validation:")
    try:
        s.set("192.168.1.1", 50000)  # Out of range
        print("  [FAIL] Should have raised ValueError")
    except ValueError as e:
        print(f"  [OK] ValueError: {e}")

    try:
        s.set("192.168.1.1", "not a number")  # Wrong type
        print("  [FAIL] Should have raised TypeError")
    except TypeError as e:
        print(f"  [OK] TypeError: {e}")

    # File operations
    print("\nTesting file error handling:")
    try:
        s.load("/nonexistent/path/file.dat")
        print("  [FAIL] Should have raised SauronIOError")
    except SauronIOError as e:
        print(f"  [OK] SauronIOError: {e}")


def demo_performance(s: Sauron) -> None:
    """Performance benchmark."""
    print_section("Performance Benchmark")

    s.clear()
    iterations = 1_000_000

    print(f"\nBenchmarking {iterations:,} operations...")

    # SET operations
    start = time.perf_counter()
    for i in range(iterations):
        ip = 0x01000001 + i  # 1.0.0.1 + i
        first_octet = (ip >> 24) & 0xFF
        # Skip loopback (127.x.x.x) and multicast/reserved (224+)
        if first_octet != 127 and first_octet < 224:
            s.set_u32(ip, i % 32767)
    set_time = time.perf_counter() - start

    print(f"\n  SET: {set_time:.3f}s ({iterations/set_time/1e6:.2f}M ops/sec)")
    print_stats(s, "After SET")

    # GET operations
    start = time.perf_counter()
    checksum = 0
    for i in range(iterations):
        ip = 0x01000001 + i
        checksum += s.get_u32(ip)
    get_time = time.perf_counter() - start

    print(f"\n  GET: {get_time:.3f}s ({iterations/get_time/1e6:.2f}M ops/sec)")
    print(f"  Checksum: {checksum} (prevents optimization)")

    # INCR operations (more realistic workload)
    s.clear()
    start = time.perf_counter()
    for i in range(iterations):
        ip = 0x08080808 + (i % 10000)  # Concentrated in 10K IPs
        s.incr_u32(ip, 1)
    incr_time = time.perf_counter() - start

    print(f"\n  INCR (10K IPs, repeated): {incr_time:.3f}s ({iterations/incr_time/1e6:.2f}M ops/sec)")


def demo_simulated_workflow() -> None:
    """Simulate a real threat detection workflow."""
    print_section("Simulated Threat Detection Workflow")

    print("\nScenario: Processing a batch of security events")

    with Sauron() as s:
        # 1. Load existing threat intelligence
        print("\n1. Loading threat intelligence feed...")
        intel_data = "\n".join([
            f"45.33.60.{i},{500 - i*10}"  # Known bad range
            for i in range(50)
        ])
        result = s.bulk_load_string(intel_data)
        print(f"   Loaded {result.sets} known threats")

        # 2. Process incoming events
        print("\n2. Processing security events...")
        events = [
            ("45.33.60.10", 50, "Malware callback"),
            ("45.33.70.100", 100, "Port scan"),
            ("45.33.70.100", 75, "Brute force attempt"),
            ("45.33.70.100", 200, "Exploitation attempt"),
            ("10.10.10.5", -50, "Successful auth from known good"),
        ]

        for ip, delta, event_type in events:
            if delta > 0:
                new_score = s.incr(ip, delta)
                print(f"   [THREAT] {ip}: +{delta} ({event_type}) -> score={new_score}")
            else:
                new_score = s.incr(ip, delta)
                print(f"   [TRUST]  {ip}: {delta} ({event_type}) -> score={new_score}")

        # 3. Check thresholds
        print("\n3. Checking threat thresholds...")
        threshold = 300
        high_risk = []
        for i in range(50):
            ip = f"45.33.60.{i}"
            score = s.get(ip)
            if score >= threshold:
                high_risk.append((ip, score))

        # Also check our detected scanner
        scanner_score = s.get("45.33.70.100")
        if scanner_score >= threshold:
            high_risk.append(("45.33.70.100", scanner_score))

        print(f"   IPs exceeding threshold ({threshold}):")
        for ip, score in high_risk[:5]:  # Show first 5
            print(f"     {ip}: {score}")
        if len(high_risk) > 5:
            print(f"     ... and {len(high_risk) - 5} more")

        # 4. Apply hourly decay
        print("\n4. Applying hourly decay (factor=0.95, deadzone=5)...")
        before = s.count()
        modified = s.decay(0.95, 5)
        after = s.count()
        print(f"   Modified: {modified}, Deleted: {before - after}")

        # 5. Save state
        print("\n5. Saving state for next cycle...")
        archive = "/tmp/sauron_workflow_state.dat"
        s.save(archive)
        print(f"   Saved to {archive} ({os.path.getsize(archive)} bytes)")
        os.unlink(archive)

        print(f"\n[OK] Workflow complete. Final state: {s.count()} active scores")


def main():
    print("Sauron Library - Python Integration Example")
    print("=" * 50)

    # Create a single context for most demos
    with Sauron() as s:
        print(f"\n[OK] Created scoring engine (version {s.version})")

        demo_basic_operations(s)
        demo_uint32_api(s)
        demo_bulk_loading(s)
        demo_bulk_load_string(s)
        demo_decay(s)
        demo_persistence(s)
        demo_error_handling(s)
        demo_performance(s)

    # Separate context for workflow demo
    demo_simulated_workflow()

    print("\n" + "=" * 50)
    print(" All examples completed successfully")
    print("=" * 50)


if __name__ == "__main__":
    main()
