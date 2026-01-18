# Sauron - High-Speed IPv4 Scoring Engine
# Python bindings package
#
# Copyright (c) 2024-2026, Ron Dilley
# All rights reserved.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

"""
Sauron - High-Speed IPv4 Scoring Engine

Python bindings for libsauron, a high-performance library for tracking
threat/trust scores for IPv4 addresses at rates exceeding 2M ops/sec.

Usage:
    from sauron import Sauron

    with Sauron() as s:
        s.set("192.168.1.100", 50)
        s.incr("192.168.1.100", 10)
        score = s.get("192.168.1.100")
        print(f"Score: {score}")  # Score: 60
"""

__version__ = "0.1.0"
__author__ = "Ron Dilley"
__email__ = "ron.dilley@uberadmin.com"

from .sauron import Sauron, SauronError, SauronIOError, SauronMemoryError

__all__ = ['Sauron', 'SauronError', 'SauronIOError', 'SauronMemoryError']
