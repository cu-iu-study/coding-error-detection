from __future__ import annotations

from collections import Counter
from pathlib import Path

from scanner.findings import Finding, Severity


class ConsoleReporter:
    """
    Formats vulnerability findings for console output.

    This class is intentionally limited to presentation logic.
    The scanner itself is responsible for detecting vulnerabilities,
    while the reporter transforms the resulting Finding objects into
    a human-readable console report.

    The implementation is modular and can easily be extended by adding
    further reporter implementations (e.g. JSON, HTML or SARIF) without
    modifying the scanner itself.
    """

    # Number of source code lines shown before and after a finding.
    _CONTEXT_LINES: int = 2

    # Formatting constants.
    _HEADER_SEPARATOR: str = "=" * 80
    _SECTION_SEPARATOR: str = "-" * 80

    # User interface text constants.
    _REPORT_TITLE: str = "Vulnerability Scanner"
    _SUMMARY_TITLE: str = "Summary"
    _FILE_LABEL: str = "File"
    _LOCATION_LABEL: str = "Location:"
    _DESCRIPTION_LABEL: str = "Description:"
    _RECOMMENDATION_LABEL: str = "Recommendation:"
    _CODE_LABEL: str = "Code:"
    _NO_FINDINGS_MESSAGE: str = "No vulnerabilities detected."
    _TOTAL_FINDINGS_LABEL: str = "Total findings"

    def report(self, findings: list[Finding]) -> None:
        """
        Creates the complete console report.

        The report is divided into three sections:
        1. Report header
        2. Findings grouped by source file
        3. Summary grouped by severity
        """

        print(self._HEADER_SEPARATOR)
        print(self._REPORT_TITLE)
        print(self._HEADER_SEPARATOR)

        if not findings:
            print()
            print(self._NO_FINDINGS_MESSAGE)
            print()
            print(self._HEADER_SEPARATOR)
            return

        grouped_findings: dict[Path, list[Finding]] = self._group_findings_by_file(
            findings
        )

        for source_file_path, file_findings in grouped_findings.items():

            print()
            print(f"{self._FILE_LABEL}: {source_file_path}")

            for finding in file_findings:

                print()
                print(self._SECTION_SEPARATOR)

                self._print_finding(finding)

        self._print_summary(findings)

    def _print_finding(self, finding: Finding) -> None:
        """
        Prints all information belonging to a single finding.
        """

        finding_header: str = (
            f"[{finding.severity}] "
            f"{finding.vulnerability_rule_name} "
            f"({finding.vulnerability_rule_id})"
        )

        print(finding_header)

        print()
        print(self._LOCATION_LABEL)
        print(
            f"  {finding.source_file_path}:"
            f"{finding.line_number}:"
            f"{finding.column_number}"
        )

        print()
        print(self._DESCRIPTION_LABEL)
        print(f"  {finding.description}")

        print()
        print(self._RECOMMENDATION_LABEL)
        print(f"  {finding.recommendation}")

        print()
        print(self._CODE_LABEL)
        print()

        self._print_code_context(
            finding.source_file_path,
            finding.line_number,
        )

    def _print_code_context(
        self, source_file_path: Path, target_line_number: int
    ) -> None:
        """
        Prints a configurable amount of source code surrounding the finding.

        Displaying neighbouring source lines helps the user understand the
        reported vulnerability without manually opening the source file.
        """

        source_lines: list[str] = source_file_path.read_text(
            encoding="utf-8",
        ).splitlines()

        first_line_number: int = max(1, target_line_number - self._CONTEXT_LINES)

        last_line_number: int = min(
            len(source_lines), target_line_number + self._CONTEXT_LINES
        )

        for current_line_number in range(first_line_number, last_line_number + 1):

            line_marker: str = ">" if current_line_number == target_line_number else " "

            print(
                f"{line_marker}"
                f"{current_line_number:5d} | "
                f"{source_lines[current_line_number - 1]}"
            )

    def _print_summary(self, findings: list[Finding]) -> None:
        """
        Prints a summary containing the total number of findings and the
        distribution across all supported severity levels.
        """

        severity_counter: Counter[Severity] = Counter(
            finding.severity for finding in findings
        )

        print()
        print(self._HEADER_SEPARATOR)
        print(self._SUMMARY_TITLE)
        print()

        print(f"{self._TOTAL_FINDINGS_LABEL} : {len(findings)}")
        print()

        # Iterate over all supported severity levels to ensure that every
        # severity is displayed, even if no finding exists for it.
        for severity in Severity:
            print(f"{severity.value:<8} : {severity_counter[severity]}")

        print(self._HEADER_SEPARATOR)

    @staticmethod
    def _group_findings_by_file(findings: list[Finding]) -> dict[Path, list[Finding]]:
        """
        Groups findings by their source file.

        Grouping findings improves the readability of the report and keeps
        all findings belonging to the same file together.
        """

        grouped_findings: dict[Path, list[Finding]] = {}

        for finding in findings:

            grouped_findings.setdefault(finding.source_file_path, []).append(finding)

        return grouped_findings
