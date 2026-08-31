from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from .model import Language


class Severity(StrEnum):
    """
    Defines the severity classification of detected vulnerabilities.
    """

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True, slots=True)
class Finding:
    """
    Represents a vulnerability identified during source code analysis.

    A Finding is the final output of a vulnerability detection rule.
    It contains all information required for reporting, including the
    affected source location and a recommended remediation.
    """

    vulnerability_rule_id: str
    vulnerability_rule_name: str

    description: str
    recommendation: str

    severity: Severity

    source_file_path: Path
    programming_language: Language

    line_number: int
    column_number: int
