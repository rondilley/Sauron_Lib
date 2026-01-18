#!/usr/bin/env python3
"""
Sauron Python Bindings Test Suite

Tests the Python ctypes wrapper for libsauron.
"""

import sys
import os
import time
import tempfile

# Add parent directory to path for development testing
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from python import Sauron, SauronError, SauronIOError


def test_basic_operations():
    """Test basic set/get/incr/decr operations."""
    print("Testing basic operations...", end=" ")

    with Sauron() as s:
        # Test set/get
        old = s.set("192.168.1.100", 50)
        assert old == 0, f"Expected 0, got {old}"

        score = s.get("192.168.1.100")
        assert score == 50, f"Expected 50, got {score}"

        # Test incr
        score = s.incr("192.168.1.100", 10)
        assert score == 60, f"Expected 60, got {score}"

        # Test decr
        score = s.decr("192.168.1.100", 20)
        assert score == 40, f"Expected 40, got {score}"

        # Test delete
        result = s.delete("192.168.1.100")
        assert result is True, "Delete should return True"

        score = s.get("192.168.1.100")
        assert score == 0, f"Expected 0 after delete, got {score}"

    print("PASS")


def test_saturation():
    """Test score saturation at boundaries."""
    print("Testing saturation...", end=" ")

    with Sauron() as s:
        # Positive saturation
        s.set("10.0.0.1", 32760)
        score = s.incr("10.0.0.1", 100)
        assert score == 32767, f"Expected 32767, got {score}"

        # Negative saturation
        s.set("10.0.0.2", -32760)
        score = s.incr("10.0.0.2", -100)
        assert score == -32767, f"Expected -32767, got {score}"

    print("PASS")


def test_u32_operations():
    """Test uint32 IP operations."""
    print("Testing u32 operations...", end=" ")

    with Sauron() as s:
        ip = Sauron.ip_to_u32("172.16.0.50")
        assert ip == 0xAC100032, f"Expected 0xAC100032, got {hex(ip)}"

        s.set_u32(ip, 500)
        score = s.get_u32(ip)
        assert score == 500, f"Expected 500, got {score}"

        score = s.incr_u32(ip, -200)
        assert score == 300, f"Expected 300, got {score}"

        # Verify string and u32 access same data
        score_str = s.get("172.16.0.50")
        assert score_str == 300, f"String get expected 300, got {score_str}"

    print("PASS")


def test_decay():
    """Test decay operation."""
    print("Testing decay...", end=" ")

    with Sauron() as s:
        s.set("192.168.2.1", 1000)
        s.set("192.168.2.2", -1000)
        s.set("192.168.2.3", 10)  # Should be deleted with deadzone=10

        modified = s.decay(0.5, 10)
        assert modified >= 3, f"Expected at least 3 modified, got {modified}"

        score = s.get("192.168.2.1")
        assert score == 500, f"Expected 500, got {score}"

        score = s.get("192.168.2.2")
        assert score == -500, f"Expected -500, got {score}"

        score = s.get("192.168.2.3")
        assert score == 0, f"Expected 0 (within deadzone), got {score}"

    print("PASS")


def test_statistics():
    """Test statistics functions."""
    print("Testing statistics...", end=" ")

    with Sauron() as s:
        assert s.count() == 0, "Initial count should be 0"

        s.set("10.0.0.1", 100)
        s.set("10.0.1.1", 200)
        s.set("10.1.0.1", 300)

        assert s.count() == 3, f"Expected count 3, got {s.count()}"
        assert s.block_count() == 3, f"Expected 3 blocks, got {s.block_count()}"
        assert s.memory_usage() > 2000000, "Memory should be > 2MB"

        stats = s.stats()
        assert stats['count'] == 3
        assert stats['blocks'] == 3

    print("PASS")


def test_persistence():
    """Test save/load operations."""
    print("Testing persistence...", end=" ")

    with tempfile.NamedTemporaryFile(delete=False, suffix='.dat') as f:
        temp_file = f.name

    try:
        # Save
        with Sauron() as s:
            s.set("192.168.10.1", 100)
            s.set("192.168.10.2", -200)
            s.set("10.20.30.40", 500)
            s.save(temp_file)

        # Load in new context
        with Sauron() as s:
            s.load(temp_file)
            assert s.get("192.168.10.1") == 100
            assert s.get("192.168.10.2") == -200
            assert s.get("10.20.30.40") == 500

        # Test non-existent file
        with Sauron() as s:
            try:
                s.load("/nonexistent/path/file.dat")
                assert False, "Should have raised SauronIOError"
            except SauronIOError:
                pass  # Expected

    finally:
        os.unlink(temp_file)

    print("PASS")


def test_ip_conversion():
    """Test IP string/u32 conversion utilities."""
    print("Testing IP conversion...", end=" ")

    # String to u32
    assert Sauron.ip_to_u32("192.168.1.1") == 0xC0A80101
    assert Sauron.ip_to_u32("10.0.0.1") == 0x0A000001
    assert Sauron.ip_to_u32("255.255.255.255") == 0xFFFFFFFF
    assert Sauron.ip_to_u32("invalid") == 0
    assert Sauron.ip_to_u32("256.1.1.1") == 0

    # u32 to string
    assert Sauron.u32_to_ip(0xC0A80101) == "192.168.1.1"
    assert Sauron.u32_to_ip(0x0A000001) == "10.0.0.1"

    print("PASS")


def test_context_manager():
    """Test context manager and cleanup."""
    print("Testing context manager...", end=" ")

    s = Sauron()
    s.set("10.0.0.1", 100)
    s.close()

    # Should be safe to close multiple times
    s.close()

    # Should raise error after close
    try:
        s.get("10.0.0.1")
        assert False, "Should have raised SauronError"
    except SauronError:
        pass  # Expected

    print("PASS")


def test_version():
    """Test version string."""
    print("Testing version...", end=" ")

    with Sauron() as s:
        version = s.version
        assert version.startswith("0."), f"Unexpected version: {version}"

    print("PASS")


def benchmark():
    """Run performance benchmark."""
    print("\nPerformance Benchmark")
    print("=" * 50)

    count = 1000000

    with Sauron() as s:
        # Benchmark SET (u32)
        start = time.perf_counter()
        for i in range(count):
            ip = ((i & 0xFFFF) << 16) | (i & 0xFF)
            s.set_u32(ip, i & 0x7FFF)
        elapsed = time.perf_counter() - start
        print(f"SET (u32):  {count/elapsed:,.0f} ops/sec")

        # Benchmark GET (u32)
        start = time.perf_counter()
        for i in range(count):
            ip = ((i & 0xFFFF) << 16) | (i & 0xFF)
            s.get_u32(ip)
        elapsed = time.perf_counter() - start
        print(f"GET (u32):  {count/elapsed:,.0f} ops/sec")

        # Benchmark INCR (u32)
        start = time.perf_counter()
        for i in range(count):
            ip = 0xC0A80000 | (i & 0xFF)
            s.incr_u32(ip, 1)
        elapsed = time.perf_counter() - start
        print(f"INCR (u32): {count/elapsed:,.0f} ops/sec")

        # Benchmark string operations (slower due to encoding)
        start = time.perf_counter()
        for i in range(count // 10):
            s.get(f"10.{(i>>16)&0xFF}.{(i>>8)&0xFF}.{i&0xFF}")
        elapsed = time.perf_counter() - start
        print(f"GET (str):  {(count//10)/elapsed:,.0f} ops/sec")

        print(f"\nFinal: {s.count():,} scores, {s.block_count():,} blocks, "
              f"{s.memory_usage():,} bytes")


def main():
    """Run all tests."""
    print(f"Sauron Python Bindings Test Suite\n")

    try:
        with Sauron() as s:
            print(f"Library version: {s.version}\n")
    except SauronError as e:
        print(f"Error: {e}")
        print("Make sure libsauron.so is built and accessible.")
        sys.exit(1)

    test_basic_operations()
    test_saturation()
    test_u32_operations()
    test_decay()
    test_statistics()
    test_persistence()
    test_ip_conversion()
    test_context_manager()
    test_version()

    print("\nAll tests passed!")

    # Run benchmark if requested
    if len(sys.argv) > 1 and sys.argv[1] == "--benchmark":
        benchmark()


if __name__ == "__main__":
    main()
