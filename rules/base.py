from __future__ import annotations

from abc import ABC, abstractmethod

from scanner.findings import Finding
from scanner.model import AnalysisContext


class Rule(ABC):
    """
    Abstract base class for all vulnerability detection rules.

    This class defines the common interface that every analysis rule
    must implement. The architecture is designed to allow additional
    rules to be added in the future without changing the scanner core.

    Each concrete rule should:
    - provide identifying metadata (id, name, description)
    - implement the analyse method
    - return zero or more findings for a given analysis context
    """

    id: str
    name: str
    description: str

    @abstractmethod
    def analyse(self, context: AnalysisContext) -> list[Finding]:
        """
        Analyse the provided context and return detected security findings.

        This method represents the common entry point used by the scanner
        to execute individual rules. Concrete implementations define the
        actual vulnerability detection logic.

        Args:
            context (AnalysisContext): Data required for performing the analysis.

        Returns:
            list[Finding]: A list containing all vulnerabilities detected by
            this rule. An empty list should be returned if no issues are found.
        """
        ...
