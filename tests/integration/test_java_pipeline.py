from __future__ import annotations

from pathlib import Path

from scanner.adapter import Adapter
from scanner.engine import RuleEngine
from scanner.findings import Finding, Severity
from scanner.parser import Parser

# Directory containing Java source files used as test input.
# The test resources represent different security scenarios and allow
# verification of the complete scanner pipeline.
JAVA_TEST_RESOURCE_DIRECTORY: Path = Path(__file__).parent / "resources" / "java"


# Test resource file names.
SAFE_JAVA_FILE: str = "safe.java"
HARDCODED_CREDENTIALS_FILE: str = "hardcoded_credentials.java"
UNSAFE_CODE_EXECUTION_FILE: str = "unsafe_code_execution.java"
COMMAND_INJECTION_FILE: str = "command_injection.java"
MULTIPLE_HARDCODED_CREDENTIALS_FILE: str = "multiple_hardcoded_credentials.java"
SORTED_FINDINGS_FILE: str = "sorted_findings.java"
ALL_RULES_FILE: str = "all_rules.java"


# Vulnerability rule identifiers.
HARDCODED_CREDENTIALS_RULE_ID: str = "GEN001"
UNSAFE_CODE_EXECUTION_RULE_ID: str = "GEN002"
COMMAND_INJECTION_RULE_ID: str = "GEN003"


# Expected source code locations used by the test resources.
FIRST_VULNERABILITY_LINE: int = 5
SECOND_VULNERABILITY_LINE: int = 7
THIRD_VULNERABILITY_LINE: int = 9


def _analyse_java_source_file(java_file_name: str) -> list[Finding]:
    """
    Execute the complete Java security analysis pipeline.

    The scanner architecture separates responsibilities into independent
    modules:
    - Parser: Converts source code into an analyzable representation.
    - Adapter: Transforms parser output into the format required by rules.
    - RuleEngine: Applies security rules and creates findings.

    Keeping these steps separated allows additional parsers, adapters,
    or security rules to be added without changing the complete pipeline.
    """

    parser: Parser = Parser()
    adapter: Adapter = Adapter()
    rule_engine: RuleEngine = RuleEngine()

    source_file_path: Path = JAVA_TEST_RESOURCE_DIRECTORY / java_file_name

    parsed_source = parser.parse(source_file_path)

    analysis_context = adapter.adapt(parsed_source)

    findings: list[Finding] = rule_engine.analyse(
        analysis_context,
    )

    return findings


def test_safe_file() -> None:
    """
    Verify that Java source code without vulnerabilities
    does not produce any findings.
    """

    findings: list[Finding] = _analyse_java_source_file(
        SAFE_JAVA_FILE,
    )

    assert findings == []


def test_hardcoded_credentials() -> None:
    """
    Verify detection of hardcoded credentials.
    """

    findings: list[Finding] = _analyse_java_source_file(
        HARDCODED_CREDENTIALS_FILE,
    )

    assert len(findings) == 1

    finding: Finding = findings[0]

    assert finding.vulnerability_rule_id == HARDCODED_CREDENTIALS_RULE_ID
    assert finding.severity is Severity.HIGH
    assert finding.line_number == FIRST_VULNERABILITY_LINE


def test_unsafe_code_execution() -> None:
    """
    Verify detection of unsafe code execution vulnerabilities.
    """

    findings: list[Finding] = _analyse_java_source_file(
        UNSAFE_CODE_EXECUTION_FILE,
    )

    assert len(findings) == 1

    finding: Finding = findings[0]

    assert finding.vulnerability_rule_id == UNSAFE_CODE_EXECUTION_RULE_ID
    assert finding.line_number == FIRST_VULNERABILITY_LINE


def test_command_injection() -> None:
    """
    Verify detection of command injection vulnerabilities.
    """

    findings: list[Finding] = _analyse_java_source_file(
        COMMAND_INJECTION_FILE,
    )

    assert len(findings) == 1

    finding: Finding = findings[0]

    assert finding.vulnerability_rule_id == COMMAND_INJECTION_RULE_ID
    assert finding.line_number == FIRST_VULNERABILITY_LINE


def test_multiple_hardcoded_credentials() -> None:
    """
    Verify that all hardcoded credentials are detected.

    This ensures the scanner does not stop after finding the first
    vulnerability occurrence.
    """

    findings: list[Finding] = _analyse_java_source_file(
        MULTIPLE_HARDCODED_CREDENTIALS_FILE,
    )

    assert len(findings) == 3

    assert all(
        finding.vulnerability_rule_id == HARDCODED_CREDENTIALS_RULE_ID
        for finding in findings
    )

    assert [finding.line_number for finding in findings] == [
        FIRST_VULNERABILITY_LINE,
        SECOND_VULNERABILITY_LINE,
        THIRD_VULNERABILITY_LINE,
    ]


def test_sorted_findings() -> None:
    """
    Verify that findings are returned in source-code order.

    Deterministic ordering improves reproducibility and makes the
    scanner output easier to consume by other components.
    """

    findings: list[Finding] = _analyse_java_source_file(
        SORTED_FINDINGS_FILE,
    )

    assert len(findings) == 3

    assert [finding.line_number for finding in findings] == [
        FIRST_VULNERABILITY_LINE,
        SECOND_VULNERABILITY_LINE,
        THIRD_VULNERABILITY_LINE,
    ]

    assert [finding.vulnerability_rule_id for finding in findings] == [
        UNSAFE_CODE_EXECUTION_RULE_ID,
        HARDCODED_CREDENTIALS_RULE_ID,
        COMMAND_INJECTION_RULE_ID,
    ]


def test_all_rules() -> None:
    """
    Verify that every implemented security rule detects its vulnerability.

    This test provides coverage for the currently implemented rule set.
    Additional rules can be added by extending this expected collection.
    """

    findings: list[Finding] = _analyse_java_source_file(
        ALL_RULES_FILE,
    )

    assert len(findings) == 3

    detected_rule_ids: set[str] = {
        finding.vulnerability_rule_id for finding in findings
    }

    assert detected_rule_ids == {
        HARDCODED_CREDENTIALS_RULE_ID,
        UNSAFE_CODE_EXECUTION_RULE_ID,
        COMMAND_INJECTION_RULE_ID,
    }
