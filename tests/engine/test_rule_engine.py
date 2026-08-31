from __future__ import annotations

from pathlib import Path

import pytest

from scanner.engine import RuleEngine
from scanner.findings import Finding, Severity
from scanner.model import AnalysisContext, Language
from rules.base import Rule

from tests.rules.conftest import analysis_input, create_context


class DummyRule(Rule):
    """
    Simple mock rule used for RuleEngine unit tests.
    """

    id = "TEST001"
    name = "Dummy Rule"
    description = "Dummy rule for unit testing."

    def __init__(
        self,
        findings: list[Finding],
    ) -> None:

        self._findings = findings
        self.executed = False

    def analyse(
        self,
        context: AnalysisContext,
    ) -> list[Finding]:

        self.executed = True
        return self._findings


class FailingRule(Rule):
    """
    Rule that always raises an exception.
    """

    id = "FAIL001"
    name = "Failing Rule"
    description = "Raises an exception."

    def analyse(
        self,
        context: AnalysisContext,
    ) -> list[Finding]:

        raise RuntimeError("Test exception")


def create_finding(
    *,
    rule_id: str = "TEST001",
    line: int = 1,
    column: int = 1,
    file_name: str = "example.py",
) -> Finding:
    """
    Create a Finding for RuleEngine tests.
    """

    return Finding(
        vulnerability_rule_id=rule_id,
        vulnerability_rule_name="Dummy Rule",
        description="Dummy description",
        recommendation="Dummy recommendation",
        severity=Severity.LOW,
        source_file_path=Path(file_name),
        programming_language=Language.PYTHON,
        line_number=line,
        column_number=column,
    )


@pytest.fixture
def empty_engine() -> RuleEngine:
    """
    Create a RuleEngine without the default rules.
    """

    engine = RuleEngine()

    for rule in engine.registered_rules:
        engine.unregister_rule(rule)

    return engine


def test_default_rules_registered() -> None:
    """
    Verify that the default rules are registered during initialization.
    """

    engine = RuleEngine()

    assert len(engine.registered_rules) == 3


def test_register_rule(empty_engine: RuleEngine) -> None:
    """
    Verify that a rule can be registered.
    """

    rule = DummyRule([])

    empty_engine.register_rule(rule)

    assert empty_engine.registered_rules == (rule,)


def test_unregister_rule(empty_engine: RuleEngine) -> None:
    """
    Verify that a registered rule can be removed.
    """

    rule = DummyRule([])

    empty_engine.register_rule(rule)

    empty_engine.unregister_rule(rule)

    assert empty_engine.registered_rules == ()


def test_analyse_without_rules(empty_engine: RuleEngine, analysis_input) -> None:
    """
    Verify that analysing without registered rules returns no findings.
    """

    findings = empty_engine.analyse(
        create_context(analysis_input),
    )

    assert findings == []


def test_single_rule_execution(empty_engine: RuleEngine, analysis_input) -> None:
    """
    Verify that a single registered rule is executed.
    """

    rule = DummyRule(
        [
            create_finding(),
        ],
    )

    empty_engine.register_rule(rule)

    findings = empty_engine.analyse(
        create_context(analysis_input),
    )

    assert rule.executed

    assert len(findings) == 1

    assert findings[0].vulnerability_rule_id == "TEST001"


def test_multiple_rule_execution(empty_engine: RuleEngine, analysis_input) -> None:
    """
    Verify that every registered rule is executed.
    """

    first_rule = DummyRule(
        [
            create_finding(rule_id="RULE001"),
        ],
    )

    second_rule = DummyRule(
        [
            create_finding(rule_id="RULE002"),
        ],
    )

    empty_engine.register_rule(first_rule)
    empty_engine.register_rule(second_rule)

    findings = empty_engine.analyse(
        create_context(analysis_input),
    )

    assert first_rule.executed
    assert second_rule.executed

    assert len(findings) == 2

    assert findings[0].vulnerability_rule_id == "RULE001"
    assert findings[1].vulnerability_rule_id == "RULE002"


def test_multiple_findings_from_single_rule(
    empty_engine: RuleEngine, analysis_input
) -> None:
    """
    Verify that multiple findings returned by one rule are preserved.
    """

    rule = DummyRule(
        [
            create_finding(line=1),
            create_finding(line=5),
            create_finding(line=10),
        ],
    )

    empty_engine.register_rule(rule)

    findings = empty_engine.analyse(
        create_context(analysis_input),
    )

    assert len(findings) == 3

    assert findings[0].line_number == 1
    assert findings[1].line_number == 5
    assert findings[2].line_number == 10


def test_findings_are_sorted(empty_engine: RuleEngine, analysis_input) -> None:
    """
    Verify that findings are sorted by file, line and column.
    """

    rule = DummyRule(
        [
            create_finding(
                file_name="b.py",
                line=20,
            ),
            create_finding(
                file_name="a.py",
                line=10,
            ),
            create_finding(
                file_name="a.py",
                line=5,
            ),
            create_finding(
                file_name="a.py",
                line=5,
                column=2,
            ),
        ],
    )

    empty_engine.register_rule(rule)

    findings = empty_engine.analyse(
        create_context(analysis_input),
    )

    assert findings[0].source_file_path == Path("a.py")
    assert findings[0].line_number == 5
    assert findings[0].column_number == 1

    assert findings[1].source_file_path == Path("a.py")
    assert findings[1].line_number == 5
    assert findings[1].column_number == 2

    assert findings[2].source_file_path == Path("a.py")
    assert findings[2].line_number == 10

    assert findings[3].source_file_path == Path("b.py")
    assert findings[3].line_number == 20


def test_rule_without_findings(empty_engine: RuleEngine, analysis_input) -> None:
    """
    Verify that rules returning no findings are handled correctly.
    """

    empty_engine.register_rule(
        DummyRule([]),
    )

    findings = empty_engine.analyse(
        create_context(analysis_input),
    )

    assert findings == []


def test_exception_is_propagated(empty_engine: RuleEngine, analysis_input) -> None:
    """
    Verify that exceptions raised by rules are propagated.
    """

    empty_engine.register_rule(
        FailingRule(),
    )

    with pytest.raises(RuntimeError):
        empty_engine.analyse(
            create_context(analysis_input),
        )


def test_register_duplicate_rule(empty_engine: RuleEngine) -> None:
    """
    Verify that registering the same rule twice raises an exception.
    """

    rule = DummyRule([])

    empty_engine.register_rule(rule)

    with pytest.raises(ValueError):
        empty_engine.register_rule(rule)
