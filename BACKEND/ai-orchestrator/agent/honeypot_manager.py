"""Honeypot file management for ransomware bait detection."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


DEFAULT_FILENAMES = (
    "salary_2026.xlsx",
    "wallet-seed-backup.txt",
    "company_payroll_q1.csv",
    "confidential_client_data.docx",
)


@dataclass(frozen=True)
class HoneypotFile:
    """Metadata for one honeypot file."""

    path: str
    created: bool


class HoneypotManager:
    """Create and validate honeypot files in monitored directories."""

    def __init__(self, directories: Iterable[str], marker: str = "UNIFIED_SECURITY_HONEYPOT") -> None:
        self.directories = [Path(directory).expanduser().resolve() for directory in directories]
        self.marker = marker

    def ensure_honeypots(self) -> list[HoneypotFile]:
        """Create honeypot files if missing and return metadata."""

        created_files: list[HoneypotFile] = []
        content = f"{self.marker}\nDo not modify this file.\n"

        for directory in self.directories:
            directory.mkdir(parents=True, exist_ok=True)
            for filename in DEFAULT_FILENAMES:
                file_path = directory / filename
                if file_path.exists():
                    created_files.append(HoneypotFile(path=str(file_path), created=False))
                    continue
                file_path.write_text(content, encoding="utf-8")
                created_files.append(HoneypotFile(path=str(file_path), created=True))

        return created_files

    def is_honeypot_path(self, file_path: str) -> bool:
        """Return True if provided path belongs to managed honeypots."""

        candidate = Path(file_path).expanduser().resolve()
        for directory in self.directories:
            if directory in candidate.parents and candidate.name in DEFAULT_FILENAMES:
                return True
        return False
