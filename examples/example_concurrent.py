#!/usr/bin/env python3
"""
Sauron Library - Concurrent Stress Test (Python)

Exercises thread safety by running simultaneous:
- Random IP readers (multiple threads)
- Bulk score updaters (multiple threads)
- Decay operations (single thread, periodic)

Note: Python's GIL means threads don't run truly in parallel for Python code,
but the C library operations do release the GIL during execution, allowing
real concurrency at the C level.

Run:
    LD_LIBRARY_PATH=../src/.libs python3 example_concurrent.py [duration] [readers] [writers]
    LD_LIBRARY_PATH=../src/.libs python3 example_concurrent.py 10 4 2

Copyright (c) 2024-2026, Ron Dilley
"""

import os
import sys
import time
import random
import threading
import argparse
from pathlib import Path
from dataclasses import dataclass
from typing import List

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "python"))

from sauron import Sauron, SAURON_SCORE_MIN, SAURON_SCORE_MAX


@dataclass
class ThreadStats:
    """Statistics collected by each thread."""
    reads: int = 0
    writes: int = 0
    decays: int = 0
    read_errors: int = 0
    write_errors: int = 0


class ConcurrentStressTest:
    """Concurrent stress test for Sauron library."""

    def __init__(self, duration: int, num_readers: int, num_writers: int):
        self.duration = duration
        self.num_readers = num_readers
        self.num_writers = num_writers
        self.sauron = Sauron()
        self.running = threading.Event()
        self.running.set()
        self.stats_lock = threading.Lock()
        self.all_stats: List[ThreadStats] = []

    def random_valid_ip(self) -> int:
        """Generate a random non-bogon IP as uint32."""
        while True:
            # Generate random IP avoiding known bogon ranges
            first_octet = random.randint(1, 223)
            if first_octet == 127:
                continue  # Skip loopback

            ip = (first_octet << 24) | random.randint(0, 0xFFFFFF)

            if not self.sauron.is_bogon(ip):
                return ip

    def reader_thread(self, thread_id: int) -> ThreadStats:
        """Reader thread: continuously reads random IPs."""
        stats = ThreadStats()
        local_rng = random.Random(thread_id + time.time_ns())

        while self.running.is_set():
            try:
                ip = self.random_valid_ip()
                score = self.sauron.get_u32(ip)

                # Validate score is in range
                if score < SAURON_SCORE_MIN or score > SAURON_SCORE_MAX:
                    stats.read_errors += 1

                stats.reads += 1

                # Yield occasionally
                if stats.reads % 10000 == 0:
                    time.sleep(0)  # Yield to other threads

            except Exception as e:
                stats.read_errors += 1

        return stats

    def writer_thread(self, thread_id: int) -> ThreadStats:
        """Writer thread: continuously sets/increments random IPs."""
        stats = ThreadStats()
        local_rng = random.Random(thread_id + time.time_ns() + 12345)

        while self.running.is_set():
            try:
                ip = self.random_valid_ip()
                value = local_rng.randint(-500, 500)
                op = local_rng.randint(0, 2)

                if op == 0:
                    result = self.sauron.set_u32(ip, value)
                elif op == 1:
                    result = self.sauron.incr_u32(ip, value)
                else:
                    result = self.sauron.decr_u32(ip, abs(value))

                # Validate result
                if result < SAURON_SCORE_MIN or result > SAURON_SCORE_MAX:
                    stats.write_errors += 1

                stats.writes += 1

                # Yield occasionally
                if stats.writes % 1000 == 0:
                    time.sleep(0)

            except Exception as e:
                stats.write_errors += 1

        return stats

    def bulk_loader_thread(self, thread_id: int) -> ThreadStats:
        """Bulk loader thread: periodically bulk loads batches."""
        stats = ThreadStats()
        batch_size = 5000

        while self.running.is_set():
            try:
                # Generate batch of updates
                lines = []
                for _ in range(batch_size):
                    ip = self.random_valid_ip()
                    value = random.randint(-100, 100)
                    is_relative = random.random() < 0.5

                    ip_str = Sauron.u32_to_ip(ip)
                    if is_relative:
                        if value >= 0:
                            lines.append(f"{ip_str},+{value}")
                        else:
                            lines.append(f"{ip_str},+{value}")  # +negative for relative decrement
                    else:
                        lines.append(f"{ip_str},{value}")

                data = "\n".join(lines)
                result = self.sauron.bulk_load_string(data)
                stats.writes += result.sets + result.updates

                # Small delay between bulk loads
                time.sleep(0.01)

            except Exception as e:
                stats.write_errors += 1

        return stats

    def decay_thread(self, thread_id: int) -> ThreadStats:
        """Decay thread: periodically applies decay."""
        stats = ThreadStats()
        decay_interval = 0.5  # seconds

        while self.running.is_set():
            try:
                modified = self.sauron.decay(0.99, 1)
                stats.decays += modified
                time.sleep(decay_interval)
            except Exception as e:
                pass  # Decay errors are non-fatal

        return stats

    def stats_reporter_thread(self):
        """Periodically reports statistics."""
        interval = 1
        last_reads = 0
        last_writes = 0
        last_time = time.time()
        elapsed_sec = 0

        while self.running.is_set():
            time.sleep(interval)
            elapsed_sec += interval

            # Aggregate current stats
            total_reads = sum(s.reads for s in self.all_stats)
            total_writes = sum(s.writes for s in self.all_stats)

            now = time.time()
            dt = now - last_time

            read_rate = (total_reads - last_reads) / dt / 1e6
            write_rate = (total_writes - last_writes) / dt / 1e6

            print(f"  [{elapsed_sec:2d}s] Reads: {total_reads:>12,} ({read_rate:.2f}M/s) | "
                  f"Writes: {total_writes:>12,} ({write_rate:.2f}M/s) | "
                  f"Count: {self.sauron.count():,} | Blocks: {self.sauron.block_count()}")

            last_reads = total_reads
            last_writes = total_writes
            last_time = now

    def run_thread_with_stats(self, target, thread_id: int):
        """Wrapper to run thread and collect stats."""
        stats = target(thread_id)
        with self.stats_lock:
            self.all_stats.append(stats)

    def run(self):
        """Run the concurrent stress test."""
        print("Sauron Concurrent Stress Test (Python)")
        print("=" * 50)
        print(f"Duration: {self.duration} seconds")
        print(f"Reader threads: {self.num_readers}")
        print(f"Writer threads: {self.num_writers}")
        print(f"Bulk loader threads: 1")
        print(f"Decay thread: 1 (every 500ms)")
        print(f"Library version: {self.sauron.version}")
        print()

        # Pre-populate with some data
        print("Pre-populating with 100K entries...")
        for i in range(100000):
            ip = self.random_valid_ip()
            self.sauron.set_u32(ip, i % 1000)

        print(f"Initial count: {self.sauron.count():,}, blocks: {self.sauron.block_count()}")
        print()

        # Create thread list
        threads = []
        self.all_stats = [ThreadStats() for _ in range(self.num_readers + self.num_writers + 2)]

        print("Starting concurrent operations...")
        print()
        start_time = time.time()

        # Start reader threads
        for i in range(self.num_readers):
            t = threading.Thread(
                target=self._reader_wrapper,
                args=(i,),
                daemon=True
            )
            threads.append(t)
            t.start()

        # Start writer threads
        for i in range(self.num_writers):
            t = threading.Thread(
                target=self._writer_wrapper,
                args=(self.num_readers + i,),
                daemon=True
            )
            threads.append(t)
            t.start()

        # Start bulk loader thread
        t = threading.Thread(
            target=self._bulk_wrapper,
            args=(self.num_readers + self.num_writers,),
            daemon=True
        )
        threads.append(t)
        t.start()

        # Start decay thread
        t = threading.Thread(
            target=self._decay_wrapper,
            args=(self.num_readers + self.num_writers + 1,),
            daemon=True
        )
        threads.append(t)
        t.start()

        # Start stats reporter
        stats_thread = threading.Thread(target=self.stats_reporter_thread, daemon=True)
        stats_thread.start()

        # Run for specified duration
        time.sleep(self.duration)

        # Signal threads to stop
        self.running.clear()
        print("\nStopping threads...")

        # Wait for threads (with timeout)
        for t in threads:
            t.join(timeout=2.0)

        elapsed = time.time() - start_time

        # Aggregate results
        total_reads = sum(s.reads for s in self.all_stats)
        total_writes = sum(s.writes for s in self.all_stats)
        total_decays = sum(s.decays for s in self.all_stats)
        read_errors = sum(s.read_errors for s in self.all_stats)
        write_errors = sum(s.write_errors for s in self.all_stats)

        print()
        print("=" * 50)
        print("RESULTS")
        print("=" * 50)
        print(f"Duration: {elapsed:.2f} seconds")
        print(f"Total reads: {total_reads:,} ({total_reads/elapsed/1e6:.2f}M/sec)")
        print(f"Total writes: {total_writes:,} ({total_writes/elapsed/1e6:.2f}M/sec)")
        print(f"Total decay modifications: {total_decays:,}")
        print(f"Read errors: {read_errors}")
        print(f"Write errors: {write_errors}")
        print(f"Final count: {self.sauron.count():,}")
        print(f"Final blocks: {self.sauron.block_count()}")
        print(f"Final memory: {self.sauron.memory_usage() / (1024*1024):.2f} MB")

        passed = read_errors == 0 and write_errors == 0
        print(f"\nRESULT: {'PASS - No errors detected' if passed else 'FAIL - Errors detected'}")

        self.sauron.close()
        return 0 if passed else 1

    def _reader_wrapper(self, idx: int):
        """Wrapper for reader thread to store stats."""
        stats = self.reader_thread(idx)
        self.all_stats[idx] = stats

    def _writer_wrapper(self, idx: int):
        """Wrapper for writer thread to store stats."""
        stats = self.writer_thread(idx)
        self.all_stats[idx] = stats

    def _bulk_wrapper(self, idx: int):
        """Wrapper for bulk loader thread to store stats."""
        stats = self.bulk_loader_thread(idx)
        self.all_stats[idx] = stats

    def _decay_wrapper(self, idx: int):
        """Wrapper for decay thread to store stats."""
        stats = self.decay_thread(idx)
        self.all_stats[idx] = stats


def main():
    parser = argparse.ArgumentParser(description="Sauron Concurrent Stress Test")
    parser.add_argument("duration", type=int, nargs="?", default=10,
                        help="Test duration in seconds (default: 10)")
    parser.add_argument("readers", type=int, nargs="?", default=4,
                        help="Number of reader threads (default: 4)")
    parser.add_argument("writers", type=int, nargs="?", default=2,
                        help="Number of writer threads (default: 2)")
    args = parser.parse_args()

    test = ConcurrentStressTest(args.duration, args.readers, args.writers)
    return test.run()


if __name__ == "__main__":
    sys.exit(main())
