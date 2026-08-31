from __future__ import annotations

from pathlib import Path

from scanner.adapter import Adapter
from scanner.engine import RuleEngine
from scanner.findings import Finding, Severity
from scanner.parser import Parser

# Directory containing JavaScript source files used as test input.
# The resources represent different security scenarios and verify the
# behaviour of the complete scanner pipeline.
JAVASCRIPT_TEST_RESOURCE_DIRECTORY: Path = (
    Path(__file__).parent / "resources" / "javascript"
)


# Test resource file names.
SAFE_JAVASCRIPT_FILE: str = "safe.js"
HARDCODED_CREDENTIALS_FILE: str = "hardcoded_credentials.js"
UNSAFE_CODE_EXECUTION_FILE: str = "unsafe_code_execution.js"
COMMAND_INJECTION_FILE: str = "command_injection.js"
MULTIPLE_HARDCODED_CREDENTIALS_FILE: str = "multiple_hardcoded_credentials.js"
SORTED_FINDINGS_FILE: str = "sorted_findings.js"
ALL_RULES_FILE: str = "all_rules.js"


# Vulnerability rule identifiers.
HARDCODED_CREDENTIALS_RULE_ID: str = "GEN001"
UNSAFE_CODE_EXECUTION_RULE_ID: str = "GEN002"
COMMAND_INJECTION_RULE_ID: str = "GEN003"


# Expected source code locations used by the test resources.
FIRST_VULNERABILITY_LINE: int = 1
SECOND_VULNERABILITY_LINE: int = 3
THIRD_VULNERABILITY_LINE: int = 5


def _analyse_javascript_source_file(javascript_file_name: str) -> list[Finding]:
    """
    Execute the complete JavaScript security analysis pipeline.

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

    source_file_path: Path = JAVASCRIPT_TEST_RESOURCE_DIRECTORY / javascript_file_name

    parsed_source = parser.parse(
        source_file_path,
    )

    analysis_context = adapter.adapt(
        parsed_source,
    )

    findings: list[Finding] = rule_engine.analyse(
        analysis_context,
    )

    return findings


def test_safe_file() -> None:
    """
    Verify that JavaScript source code without vulnerabilities
    does not produce any findings.
    """

    findings: list[Finding] = _analyse_javascript_source_file(
        SAFE_JAVASCRIPT_FILE,
    )

    assert findings == []


def test_hardcoded_credentials() -> None:
    """
    Verify detection of hardcoded credentials.
    """

    findings: list[Finding] = _analyse_javascript_source_file(
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

    findings: list[Finding] = _analyse_javascript_source_file(
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

    findings: list[Finding] = _analyse_javascript_source_file(
        COMMAND_INJECTION_FILE,
    )

    assert len(findings) == 1

    finding: Finding = findings[0]

    assert finding.vulnerability_rule_id == COMMAND_INJECTION_RULE_ID
    assert finding.line_number == FIRST_VULNERABILITY_LINE


def test_multiple_hardcoded_credentials() -> None:
    """
    Verify that all hardcoded credentials are detected.

    This ensures the scanner identifies every occurrence instead of
    stopping after the first detected vulnerability.
    """

    findings: list[Finding] = _analyse_javascript_source_file(
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

    Stable ordering ensures deterministic scanner results and makes
    findings easier to process by future reporting components.
    """

    findings: list[Finding] = _analyse_javascript_source_file(
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
    Verify that all currently implemented security rules
    detect their corresponding vulnerabilities.

    Additional rules can be added by extending the expected rule
    identifier collection.
    """

    findings: list[Finding] = _analyse_javascript_source_file(
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
