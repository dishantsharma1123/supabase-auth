"""
Snowflake ID Generator

This module provides a Snowflake ID generator that generates unique, sortable,
time-based IDs similar to Twitter's Snowflake IDs.

Snowflake ID structure (64-bit):
- 1 bit: unused (always 0)
- 41 bits: timestamp (milliseconds since epoch)
- 10 bits: machine ID (supports up to 1024 machines)
- 12 bits: sequence number (supports up to 4096 IDs per millisecond)
"""

import secrets
import string

import time
import threading
from typing import Optional


class SnowflakeGenerator:
    """
    Thread-safe Snowflake ID generator.
    """

    # Twitter's Snowflake epoch: 2010-11-04 01:42:54 UTC
    EPOCH = 1288834974657

    def __init__(self, machine_id: int = 1):
        """
        Initialize the Snowflake generator.

        Args:
            machine_id: A unique identifier for this machine (0-1023)
        """
        if machine_id < 0 or machine_id > 1023:
            raise ValueError("Machine ID must be between 0 and 1023")

        self.machine_id = machine_id
        self.sequence = 0
        self.last_timestamp = -1
        self.lock = threading.Lock()

    def _current_timestamp(self) -> int:
        """Get current timestamp in milliseconds."""
        return int(time.time() * 1000)

    def _wait_next_millis(self, last_timestamp: int) -> int:
        """Wait until the next millisecond."""
        timestamp = self._current_timestamp()
        while timestamp <= last_timestamp:
            timestamp = self._current_timestamp()
        return timestamp

    def generate(self) -> int:
        """
        Generate a new Snowflake ID.

        Returns:
            A unique Snowflake ID as an integer.
        """
        with self.lock:
            timestamp = self._current_timestamp()

            # Handle clock moving backwards
            if timestamp < self.last_timestamp:
                raise RuntimeError(
                    f"Clock moved backwards. Refusing to generate ID for "
                    f"{self.last_timestamp - timestamp}ms"
                )

            # Same millisecond - increment sequence
            if timestamp == self.last_timestamp:
                self.sequence = (self.sequence + 1) & 0xFFF  # 12 bits
                if self.sequence == 0:
                    # Sequence overflow - wait for next millisecond
                    timestamp = self._wait_next_millis(self.last_timestamp)
            else:
                # New millisecond - reset sequence
                self.sequence = 0

            self.last_timestamp = timestamp

            # Build the Snowflake ID
            snowflake_id = (
                ((timestamp - self.EPOCH) << 22)  # 41 bits for timestamp
                | (self.machine_id << 12)           # 10 bits for machine ID
                | self.sequence                      # 12 bits for sequence
            )

            return snowflake_id

    def parse(self, snowflake_id: int) -> dict:
        """
        Parse a Snowflake ID to extract its components.

        Args:
            snowflake_id: The Snowflake ID to parse.

        Returns:
            A dictionary containing the parsed components.
        """
        timestamp = (snowflake_id >> 22) + self.EPOCH
        machine_id = (snowflake_id >> 12) & 0x3FF
        sequence = snowflake_id & 0xFFF

        return {
            "snowflake_id": snowflake_id,
            "timestamp": timestamp,
            "datetime": time.strftime(
                "%Y-%m-%d %H:%M:%S", time.gmtime(timestamp / 1000)
            ),
            "machine_id": machine_id,
            "sequence": sequence,
        }


# Global Snowflake generator instance
# You can configure the machine_id via environment variable or config
_snowflake_generator: Optional[SnowflakeGenerator] = None


def get_snowflake_generator(machine_id: int = 1) -> SnowflakeGenerator:
    """
    Get the global Snowflake generator instance.

    Args:
        machine_id: A unique identifier for this machine (0-1023)

    Returns:
        The Snowflake generator instance.
    """
    global _snowflake_generator
    if _snowflake_generator is None:
        _snowflake_generator = SnowflakeGenerator(machine_id)
    return _snowflake_generator


def generate_snowflake_id(machine_id: int = 1) -> int:
    """
    Generate a new Snowflake ID.

    Args:
        machine_id: A unique identifier for this machine (0-1023)

    Returns:
        A unique Snowflake ID as an integer.
    """
    return get_snowflake_generator(machine_id).generate()


def parse_snowflake_id(snowflake_id: int) -> dict:
    """
    Parse a Snowflake ID to extract its components.

    Args:
        snowflake_id: The Snowflake ID to parse.

    Returns:
        A dictionary containing the parsed components.
    """
    return get_snowflake_generator().parse(snowflake_id)


def generate_csrf_token() -> str:
    """
    Generate a cryptographically secure CSRF token for API security.
    Uses 128 bits of entropy (32 bytes) for strong security.
    
    Returns:
        A random 64-character hexadecimal string.
    """
    return secrets.token_hex(32)
