from __future__ import annotations

from scanner.findings import Severity
from scanner.model import (
    FunctionCall,
    StringLiteral,
    UnknownExpression,
    VariableReference,
)
from rules.generic.command_injection import CommandInjectionRule

from conftest import create_context


def test_detect_os_system_variable(analysis_input) -> None:
    """
    Verify that the rule reports a finding when a variable is passed to
    os.system().

    Variable references cannot be evaluated statically and therefore
    represent a potential command injection source. The generated finding
    must contain the correct vulnerability metadata and source position.
    """

    command_injection_rule: CommandInjectionRule = CommandInjectionRule()

    analysis_context = create_context(
        analysis_input,
        function_calls=[
            FunctionCall(
                line_number=1,
                column_number=1,
                qualifier="os",
                function_name="system",
                arguments=(
                    VariableReference(
                        line_number=1,
                        column_number=11,
                        variable_name="command",
                    ),
                ),
            ),
        ],
    )

    findings = command_injection_rule.analyse(analysis_context)

    assert len(findings) == 1

    detected_finding = findings[0]

    assert detected_finding.vulnerability_rule_id == "GEN003"
    assert detected_finding.severity is Severity.CRITICAL
    assert detected_finding.line_number == 1
    assert detected_finding.column_number == 1


def test_detect_unknown_expression(analysis_input) -> None:
    """
    Verify that unsupported expressions passed to os.system() are treated
    as potential command injection sources.

    Expressions that cannot be resolved statically should be analysed
    conservatively to avoid missing possible vulnerabilities.
    """

    command_injection_rule: CommandInjectionRule = CommandInjectionRule()

    analysis_context = create_context(
        analysis_input,
        function_calls=[
            FunctionCall(
                line_number=1,
                column_number=1,
                qualifier="os",
                function_name="system",
                arguments=(
                    UnknownExpression(
                        line_number=1,
                        column_number=11,
                        source_text="command.strip()",
                    ),
                ),
            ),
        ],
    )

    findings = command_injection_rule.analyse(analysis_context)

    assert len(findings) == 1

    detected_finding = findings[0]

    assert detected_finding.vulnerability_rule_id == "GEN003"
    assert detected_finding.severity is Severity.CRITICAL
    assert detected_finding.line_number == 1
    assert detected_finding.column_number == 1


def test_ignore_literal_argument(analysis_input) -> None:
    """
    Verify that constant string literals are not reported.

    Hard-coded command strings are considered deterministic and therefore
    are not treated as user-controlled input by this rule.
    """

    command_injection_rule: CommandInjectionRule = CommandInjectionRule()

    analysis_context = create_context(
        analysis_input,
        function_calls=[
            FunctionCall(
                line_number=1,
                column_number=1,
                qualifier="os",
                function_name="system",
                arguments=(
                    StringLiteral(
                        line_number=1,
                        column_number=11,
                        value="dir",
                    ),
                ),
            ),
        ],
    )

    assert command_injection_rule.analyse(analysis_context) == []


def test_ignore_safe_function(analysis_input) -> None:
    """
    Verify that calls to unrelated functions are ignored.

    The rule should analyse only security-relevant command execution
    functions.
    """

    command_injection_rule: CommandInjectionRule = CommandInjectionRule()

    analysis_context = create_context(
        analysis_input,
        function_calls=[
            FunctionCall(
                line_number=1,
                column_number=1,
                qualifier=None,
                function_name="print",
                arguments=(
                    VariableReference(
                        line_number=1,
                        column_number=7,
                        variable_name="command",
                    ),
                ),
            ),
        ],
    )

    assert command_injection_rule.analyse(analysis_context) == []
