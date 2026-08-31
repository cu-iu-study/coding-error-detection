from __future__ import annotations

from scanner.findings import Severity
from scanner.model import (
    FunctionCall,
    VariableReference,
)
from rules.generic.unsafe_code_execution import (
    UnsafeCodeExecutionRule,
)

from conftest import create_context


def test_detect_unqualified_unsafe_function(analysis_input) -> None:
    """
    Verify that calls to unsafe functions without a qualifier are reported.

    The generated finding must contain the correct vulnerability metadata
    and source code position.
    """

    unsafe_code_execution_rule: UnsafeCodeExecutionRule = UnsafeCodeExecutionRule()

    analysis_context = create_context(
        analysis_input,
        function_calls=[
            FunctionCall(
                line_number=1,
                column_number=1,
                qualifier=None,
                function_name="eval",
                arguments=(
                    VariableReference(
                        line_number=1,
                        column_number=6,
                        variable_name="code",
                    ),
                ),
            ),
        ],
    )

    findings = unsafe_code_execution_rule.analyse(analysis_context)

    assert len(findings) == 1

    detected_finding = findings[0]

    assert detected_finding.vulnerability_rule_id == "GEN002"
    assert detected_finding.severity is Severity.HIGH
    assert detected_finding.line_number == 1
    assert detected_finding.column_number == 1


def test_detect_qualified_unsafe_function(analysis_input) -> None:
    """
    Verify that qualified calls to unsafe functions are reported.

    The generated finding must contain the correct vulnerability metadata
    and source code position.
    """

    unsafe_code_execution_rule: UnsafeCodeExecutionRule = UnsafeCodeExecutionRule()

    analysis_context = create_context(
        analysis_input,
        function_calls=[
            FunctionCall(
                line_number=1,
                column_number=1,
                qualifier="builtins",
                function_name="exec",
                arguments=(),
            ),
        ],
    )

    findings = unsafe_code_execution_rule.analyse(analysis_context)

    assert len(findings) == 1

    detected_finding = findings[0]

    assert detected_finding.vulnerability_rule_id == "GEN002"
    assert detected_finding.severity is Severity.HIGH
    assert detected_finding.line_number == 1
    assert detected_finding.column_number == 1


def test_ignore_safe_function(analysis_input) -> None:
    """
    Verify that unrelated unqualified function calls are ignored.
    """

    unsafe_code_execution_rule: UnsafeCodeExecutionRule = UnsafeCodeExecutionRule()

    analysis_context = create_context(
        analysis_input,
        function_calls=[
            FunctionCall(
                line_number=1,
                column_number=1,
                qualifier=None,
                function_name="print",
                arguments=(),
            ),
        ],
    )

    assert unsafe_code_execution_rule.analyse(analysis_context) == []


def test_ignore_qualified_safe_function(analysis_input) -> None:
    """
    Verify that qualified calls to unrelated functions are ignored.
    """

    unsafe_code_execution_rule: UnsafeCodeExecutionRule = UnsafeCodeExecutionRule()

    analysis_context = create_context(
        analysis_input,
        function_calls=[
            FunctionCall(
                line_number=1,
                column_number=1,
                qualifier="builtins",
                function_name="print",
                arguments=(),
            ),
        ],
    )

    assert unsafe_code_execution_rule.analyse(analysis_context) == []
