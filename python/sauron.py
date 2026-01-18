# Sauron - High-Speed IPv4 Scoring Engine
# Python ctypes bindings
#
# Copyright (c) 2024-2026, Ron Dilley
# All rights reserved.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

"""
Python ctypes wrapper for libsauron.

Provides a Pythonic interface to the high-performance IPv4 scoring engine.

Thread Safety:
    The underlying C library is thread-safe for all operations. Multiple threads
    can safely call get/set/incr/decr/decay concurrently on the same Sauron
    instance. The library uses:
    - Lock-free atomic reads for get operations
    - Per-block spinlocks for write operations
    - Striped allocation locks for new block creation

    In Python, the GIL (Global Interpreter Lock) provides additional safety,
    but the library is safe even without the GIL (e.g., with free-threading
    Python builds or when called from C extensions that release the GIL).

    Note: Do not share a Sauron instance across processes (use multiprocessing).
    Each process should create its own instance or use save/load for persistence.
"""

import ctypes
import ctypes.util
import os
from pathlib import Path
from typing import Optional, Tuple, NamedTuple


# Error codes
SAURON_OK = 0
SAURON_ERR_NULL = -1
SAURON_ERR_INVALID = -2
SAURON_ERR_NOMEM = -3
SAURON_ERR_IO = -4
SAURON_ERR_BOGON = -5

SAURON_SCORE_MIN = -32767
SAURON_SCORE_MAX = 32767


def _validate_score(score: int, name: str = "score") -> int:
    """Validate score is within int16_t range."""
    if not isinstance(score, int):
        raise TypeError(f"{name} must be an integer, got {type(score).__name__}")
    if score < SAURON_SCORE_MIN or score > SAURON_SCORE_MAX:
        raise ValueError(
            f"{name} must be in range {SAURON_SCORE_MIN} to {SAURON_SCORE_MAX}, got {score}"
        )
    return score


class SauronError(Exception):
    """Base exception for Sauron errors."""
    pass


class SauronIOError(SauronError):
    """I/O error during save/load operations."""
    pass


class SauronMemoryError(SauronError):
    """Memory allocation error."""
    pass


class BulkLoadResult(NamedTuple):
    """Result of a bulk load operation."""
    lines_processed: int
    lines_skipped: int
    sets: int
    updates: int
    parse_errors: int
    elapsed_seconds: float
    lines_per_second: float


class _BulkResultStruct(ctypes.Structure):
    """ctypes structure for sauron_bulk_result_t."""
    _fields_ = [
        ("lines_processed", ctypes.c_uint64),
        ("lines_skipped", ctypes.c_uint64),
        ("sets", ctypes.c_uint64),
        ("updates", ctypes.c_uint64),
        ("parse_errors", ctypes.c_uint64),
        ("elapsed_seconds", ctypes.c_double),
        ("lines_per_second", ctypes.c_double),
    ]


def _find_library() -> str:
    """Find the libsauron shared library."""
    # Check common locations
    search_paths = [
        # Development build
        Path(__file__).parent.parent / "src" / ".libs" / "libsauron.so",
        # Installed system-wide
        "/usr/local/lib/libsauron.so",
        "/usr/lib/libsauron.so",
        # Use ctypes finder
    ]

    for path in search_paths:
        if path.exists():
            return str(path)

    # Try system library finder
    lib_path = ctypes.util.find_library("sauron")
    if lib_path:
        return lib_path

    raise SauronError(
        "Could not find libsauron.so. "
        "Please ensure the library is installed or set LD_LIBRARY_PATH."
    )


class Sauron:
    """
    High-Speed IPv4 Scoring Engine.

    Thread-safe library for tracking threat/trust scores for IPv4 addresses
    at rates exceeding 2M operations per second.

    Scores are 16-bit signed integers:
    - Positive scores indicate risk/threat level
    - Negative scores indicate trust level
    - Zero means neutral or no data

    Usage:
        with Sauron() as s:
            s.set("192.168.1.100", 50)
            s.incr("192.168.1.100", 10)
            score = s.get("192.168.1.100")

        # Or without context manager:
        s = Sauron()
        try:
            s.set("10.0.0.1", 100)
        finally:
            s.close()
    """

    def __init__(self, library_path: Optional[str] = None):
        """
        Initialize the scoring engine.

        Args:
            library_path: Optional path to libsauron.so. If not provided,
                         the library will be searched in standard locations.
        """
        if library_path is None:
            library_path = _find_library()

        self._lib = ctypes.CDLL(library_path)
        self._setup_functions()

        self._ctx = self._lib.sauron_create()
        if not self._ctx:
            raise SauronMemoryError("Failed to create scoring engine context")

    def _setup_functions(self):
        """Configure ctypes function signatures."""
        # Context management
        self._lib.sauron_create.argtypes = []
        self._lib.sauron_create.restype = ctypes.c_void_p

        self._lib.sauron_destroy.argtypes = [ctypes.c_void_p]
        self._lib.sauron_destroy.restype = None

        # Score operations (string IP)
        self._lib.sauron_get.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        self._lib.sauron_get.restype = ctypes.c_int16

        self._lib.sauron_set.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int16]
        self._lib.sauron_set.restype = ctypes.c_int16

        self._lib.sauron_incr.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int16]
        self._lib.sauron_incr.restype = ctypes.c_int16

        self._lib.sauron_decr.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int16]
        self._lib.sauron_decr.restype = ctypes.c_int16

        self._lib.sauron_delete.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        self._lib.sauron_delete.restype = ctypes.c_int

        # Score operations (uint32 IP) - faster
        self._lib.sauron_get_u32.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        self._lib.sauron_get_u32.restype = ctypes.c_int16

        self._lib.sauron_set_u32.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int16]
        self._lib.sauron_set_u32.restype = ctypes.c_int16

        self._lib.sauron_incr_u32.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int16]
        self._lib.sauron_incr_u32.restype = ctypes.c_int16

        self._lib.sauron_decr_u32.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int16]
        self._lib.sauron_decr_u32.restype = ctypes.c_int16

        self._lib.sauron_delete_u32.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        self._lib.sauron_delete_u32.restype = ctypes.c_int

        # Decay
        self._lib.sauron_decay.argtypes = [ctypes.c_void_p, ctypes.c_float, ctypes.c_int16]
        self._lib.sauron_decay.restype = ctypes.c_uint64

        # Statistics
        self._lib.sauron_count.argtypes = [ctypes.c_void_p]
        self._lib.sauron_count.restype = ctypes.c_uint64

        self._lib.sauron_block_count.argtypes = [ctypes.c_void_p]
        self._lib.sauron_block_count.restype = ctypes.c_uint64

        self._lib.sauron_memory_usage.argtypes = [ctypes.c_void_p]
        self._lib.sauron_memory_usage.restype = ctypes.c_size_t

        # Persistence
        self._lib.sauron_save.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        self._lib.sauron_save.restype = ctypes.c_int

        self._lib.sauron_load.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        self._lib.sauron_load.restype = ctypes.c_int

        # Clear
        self._lib.sauron_clear.argtypes = [ctypes.c_void_p]
        self._lib.sauron_clear.restype = ctypes.c_int

        # Bulk load
        self._lib.sauron_bulk_load.argtypes = [
            ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(_BulkResultStruct)
        ]
        self._lib.sauron_bulk_load.restype = ctypes.c_int

        self._lib.sauron_bulk_load_buffer.argtypes = [
            ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t, ctypes.POINTER(_BulkResultStruct)
        ]
        self._lib.sauron_bulk_load_buffer.restype = ctypes.c_int

        # Extended get (sauron_get_ex)
        self._lib.sauron_get_ex.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_int16)]
        self._lib.sauron_get_ex.restype = ctypes.c_int

        # Utilities
        self._lib.sauron_ip_to_u32.argtypes = [ctypes.c_char_p]
        self._lib.sauron_ip_to_u32.restype = ctypes.c_uint32

        self._lib.sauron_version.argtypes = []
        self._lib.sauron_version.restype = ctypes.c_char_p

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
        return False

    def close(self):
        """
        Destroy the scoring engine and free resources.

        Safe to call multiple times.
        """
        if self._ctx:
            self._lib.sauron_destroy(self._ctx)
            self._ctx = None

    def __del__(self):
        """Destructor - ensure cleanup."""
        self.close()

    def _check_ctx(self):
        """Ensure context is valid."""
        if not self._ctx:
            raise SauronError("Scoring engine has been closed")

    # String IP operations

    def get(self, ip: str) -> int:
        """
        Get the score for an IP address.

        Args:
            ip: IPv4 address in dotted-decimal notation (e.g., "192.168.1.1")

        Returns:
            Score value (-32767 to +32767), or 0 if not found
        """
        self._check_ctx()
        return self._lib.sauron_get(self._ctx, ip.encode('utf-8'))

    def set(self, ip: str, score: int) -> int:
        """
        Set the score for an IP address.

        Args:
            ip: IPv4 address in dotted-decimal notation
            score: Score value (-32767 to +32767)

        Returns:
            Previous score value

        Raises:
            ValueError: If score is out of range
            TypeError: If score is not an integer
        """
        self._check_ctx()
        _validate_score(score)
        return self._lib.sauron_set(self._ctx, ip.encode('utf-8'), score)

    def incr(self, ip: str, delta: int) -> int:
        """
        Increment the score for an IP address.

        Uses saturating arithmetic - won't overflow past -32767/+32767.

        Args:
            ip: IPv4 address in dotted-decimal notation
            delta: Value to add (can be negative)

        Returns:
            New score value after increment

        Raises:
            ValueError: If delta is out of range
            TypeError: If delta is not an integer
        """
        self._check_ctx()
        _validate_score(delta, "delta")
        return self._lib.sauron_incr(self._ctx, ip.encode('utf-8'), delta)

    def decr(self, ip: str, delta: int) -> int:
        """
        Decrement the score for an IP address.

        Equivalent to incr(ip, -delta).

        Args:
            ip: IPv4 address in dotted-decimal notation
            delta: Value to subtract

        Returns:
            New score value after decrement

        Raises:
            ValueError: If delta is out of range
            TypeError: If delta is not an integer
        """
        self._check_ctx()
        _validate_score(delta, "delta")
        return self._lib.sauron_decr(self._ctx, ip.encode('utf-8'), delta)

    def delete(self, ip: str) -> bool:
        """
        Delete the score for an IP address (set to 0).

        Args:
            ip: IPv4 address in dotted-decimal notation

        Returns:
            True if successful
        """
        self._check_ctx()
        return self._lib.sauron_delete(self._ctx, ip.encode('utf-8')) == SAURON_OK

    # uint32 IP operations (faster - no string parsing)

    def get_u32(self, ip: int) -> int:
        """
        Get the score for an IP address (uint32 version).

        Faster than get() as it skips IP string parsing.

        Args:
            ip: IPv4 address as uint32 in host byte order

        Returns:
            Score value (-32767 to +32767), or 0 if not found
        """
        self._check_ctx()
        return self._lib.sauron_get_u32(self._ctx, ip)

    def set_u32(self, ip: int, score: int) -> int:
        """
        Set the score for an IP address (uint32 version).

        Args:
            ip: IPv4 address as uint32 in host byte order
            score: Score value (-32767 to +32767)

        Returns:
            Previous score value

        Raises:
            ValueError: If score is out of range
            TypeError: If score is not an integer
        """
        self._check_ctx()
        _validate_score(score)
        return self._lib.sauron_set_u32(self._ctx, ip, score)

    def incr_u32(self, ip: int, delta: int) -> int:
        """
        Increment the score for an IP address (uint32 version).

        Args:
            ip: IPv4 address as uint32 in host byte order
            delta: Value to add (can be negative)

        Returns:
            New score value after increment

        Raises:
            ValueError: If delta is out of range
            TypeError: If delta is not an integer
        """
        self._check_ctx()
        _validate_score(delta, "delta")
        return self._lib.sauron_incr_u32(self._ctx, ip, delta)

    def decr_u32(self, ip: int, delta: int) -> int:
        """
        Decrement the score for an IP address (uint32 version).

        Args:
            ip: IPv4 address as uint32 in host byte order
            delta: Value to subtract

        Returns:
            New score value after decrement

        Raises:
            ValueError: If delta is out of range
            TypeError: If delta is not an integer
        """
        self._check_ctx()
        _validate_score(delta, "delta")
        return self._lib.sauron_decr_u32(self._ctx, ip, delta)

    def delete_u32(self, ip: int) -> bool:
        """
        Delete the score for an IP address (uint32 version).

        Args:
            ip: IPv4 address as uint32 in host byte order

        Returns:
            True if successful
        """
        self._check_ctx()
        return self._lib.sauron_delete_u32(self._ctx, ip) == SAURON_OK

    # Decay

    def decay(self, factor: float, deadzone: int = 10) -> int:
        """
        Apply decay to all scores.

        Multiplies each score by the decay factor and removes scores
        that fall within the deadzone (near zero).

        Args:
            factor: Decay factor (0.0 to 1.0), e.g., 0.9 reduces by 10%
            deadzone: Delete scores with absolute value <= this value

        Returns:
            Number of scores modified or deleted
        """
        self._check_ctx()
        return self._lib.sauron_decay(self._ctx, factor, deadzone)

    # Statistics

    def count(self) -> int:
        """
        Get the number of active scores.

        Returns:
            Number of IP addresses with non-zero scores
        """
        self._check_ctx()
        return self._lib.sauron_count(self._ctx)

    def block_count(self) -> int:
        """
        Get the number of allocated /24 blocks.

        Returns:
            Number of CIDR blocks currently allocated
        """
        self._check_ctx()
        return self._lib.sauron_block_count(self._ctx)

    def memory_usage(self) -> int:
        """
        Get the current memory usage in bytes.

        Returns:
            Total memory allocated by the scoring engine
        """
        self._check_ctx()
        return self._lib.sauron_memory_usage(self._ctx)

    def stats(self) -> dict:
        """
        Get comprehensive statistics.

        Returns:
            Dict with 'count', 'blocks', and 'memory' keys
        """
        self._check_ctx()
        return {
            'count': self.count(),
            'blocks': self.block_count(),
            'memory': self.memory_usage(),
        }

    # Clear

    def clear(self) -> None:
        """
        Clear all scores without destroying the context.

        More efficient than close/recreate cycle.
        """
        self._check_ctx()
        ret = self._lib.sauron_clear(self._ctx)
        if ret != SAURON_OK:
            raise SauronError("Failed to clear scores")

    # Extended operations

    def get_ex(self, ip: int) -> Optional[int]:
        """
        Get the score for an IP address with explicit not-found handling.

        Unlike get_u32(), this method distinguishes between "score is 0"
        and "IP not found". Returns None if not found, the actual score
        (including 0) if found.

        Args:
            ip: IPv4 address as uint32 in host byte order

        Returns:
            Score value if found, None if not found
        """
        self._check_ctx()
        score_out = ctypes.c_int16()
        ret = self._lib.sauron_get_ex(self._ctx, ip, ctypes.byref(score_out))
        if ret == SAURON_OK:
            return score_out.value
        return None

    # Persistence

    def save(self, filename: str) -> None:
        """
        Save all scores to a binary archive file.

        Uses atomic write (temp file + fsync + rename) for safety.

        Args:
            filename: Path to save the archive

        Raises:
            SauronIOError: If save fails
        """
        self._check_ctx()
        ret = self._lib.sauron_save(self._ctx, filename.encode('utf-8'))
        if ret != SAURON_OK:
            raise SauronIOError(f"Failed to save archive: {filename}")

    def load(self, filename: str) -> None:
        """
        Load scores from a binary archive file.

        Existing scores are cleared before loading.

        Args:
            filename: Path to the archive file

        Raises:
            SauronIOError: If load fails
        """
        self._check_ctx()
        ret = self._lib.sauron_load(self._ctx, filename.encode('utf-8'))
        if ret != SAURON_OK:
            raise SauronIOError(f"Failed to load archive: {filename}")

    # Bulk loading

    def bulk_load(self, filename: str) -> BulkLoadResult:
        """
        Bulk load IP score changes from a CSV file.

        File format: one entry per line, comma-separated:
            IP,CHANGE

        Where CHANGE is:
            - Absolute value: "100" (sets score to 100)
            - Relative positive: "+10" (adds 10 to current score)
            - Relative negative: "-5" (subtracts 5 from current score)

        Example file:
            192.168.1.1,100
            192.168.1.2,+50
            10.0.0.1,-25

        Args:
            filename: Path to CSV file

        Returns:
            BulkLoadResult with statistics and timing

        Raises:
            SauronIOError: If file cannot be read
        """
        self._check_ctx()
        result = _BulkResultStruct()
        ret = self._lib.sauron_bulk_load(
            self._ctx, filename.encode('utf-8'), ctypes.byref(result)
        )
        if ret != SAURON_OK:
            raise SauronIOError(f"Failed to bulk load: {filename}")

        return BulkLoadResult(
            lines_processed=result.lines_processed,
            lines_skipped=result.lines_skipped,
            sets=result.sets,
            updates=result.updates,
            parse_errors=result.parse_errors,
            elapsed_seconds=result.elapsed_seconds,
            lines_per_second=result.lines_per_second,
        )

    def bulk_load_string(self, data: str) -> BulkLoadResult:
        """
        Bulk load IP score changes from a string buffer.

        Same format as bulk_load() but reads from a string.

        Args:
            data: CSV data as string

        Returns:
            BulkLoadResult with statistics and timing
        """
        self._check_ctx()
        encoded = data.encode('utf-8')
        result = _BulkResultStruct()
        ret = self._lib.sauron_bulk_load_buffer(
            self._ctx, encoded, len(encoded), ctypes.byref(result)
        )
        if ret != SAURON_OK:
            raise SauronError("Failed to bulk load from buffer")

        return BulkLoadResult(
            lines_processed=result.lines_processed,
            lines_skipped=result.lines_skipped,
            sets=result.sets,
            updates=result.updates,
            parse_errors=result.parse_errors,
            elapsed_seconds=result.elapsed_seconds,
            lines_per_second=result.lines_per_second,
        )

    # Utilities

    @staticmethod
    def ip_to_u32(ip: str) -> int:
        """
        Convert an IPv4 string to uint32.

        Args:
            ip: IPv4 address in dotted-decimal notation

        Returns:
            IP address as uint32 in host byte order, or 0 if invalid
        """
        # Local implementation to avoid loading library just for this
        parts = ip.split('.')
        if len(parts) != 4:
            return 0
        try:
            octets = [int(p) for p in parts]
            if not all(0 <= o <= 255 for o in octets):
                return 0
            return (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]
        except ValueError:
            return 0

    @staticmethod
    def u32_to_ip(ip: int) -> str:
        """
        Convert a uint32 to IPv4 string.

        Args:
            ip: IP address as uint32 in host byte order

        Returns:
            IPv4 address in dotted-decimal notation
        """
        return f"{(ip >> 24) & 0xFF}.{(ip >> 16) & 0xFF}.{(ip >> 8) & 0xFF}.{ip & 0xFF}"

    @property
    def version(self) -> str:
        """Get the library version string."""
        return self._lib.sauron_version().decode('utf-8')
