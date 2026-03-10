"""Entropy analyzer for ransomware-like file modifications."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import math
from typing import Iterable


@dataclass(frozen=True)
class EntropyResult:
    """Entropy metrics before/after file changes."""

    entropy_before: float
    entropy_after: float
    entropy_delta: float


class EntropyAnalyzer:
    """Compute Shannon entropy from byte streams and files."""

    @staticmethod
    def shannon_entropy(content: bytes) -> float:
        """Return Shannon entropy in bits per byte."""

        if not content:
            return 0.0

        counts: dict[int, int] = {}
        for byte in content:
            counts[byte] = counts.get(byte, 0) + 1

        total = len(content)
        entropy = 0.0

        for count in counts.values():
            probability = count / total
            entropy -= probability * math.log2(probability)

        return entropy

    def compare(self, before: bytes, after: bytes) -> EntropyResult:
        """Compare entropy between two byte buffers."""

        before_entropy = self.shannon_entropy(before)
        after_entropy = self.shannon_entropy(after)
        return EntropyResult(
            entropy_before=before_entropy,
            entropy_after=after_entropy,
            entropy_delta=after_entropy - before_entropy,
        )

    def compare_files(self, before_path: Path, after_path: Path) -> EntropyResult:
        """Compare entropy values for two files."""

        before_content = before_path.read_bytes() if before_path.exists() else b""
        after_content = after_path.read_bytes() if after_path.exists() else b""
        return self.compare(before_content, after_content)
