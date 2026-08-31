from __future__ import annotations

from scanner.findings import Severity
from scanner.model import (
    Assignment,
    StringLiteral,
    UnknownExpression,
    VariableReference,
)
from rules.generic.hardcoded_credentials import HardcodedCredentialsRule

from conftest import create_context


def test_detect_password_literal(analysis_input) -> None:
    """
    Verify that hardcoded password assignments are detected.

    Assigning a literal value to a variable that represents a credential
    can expose sensitive information directly in the source code. The rule
    should create a finding with the appropriate vulnerability metadata.
    """

    hardcoded_credentials_rule: HardcodedCredentialsRule = HardcodedCredentialsRule()

    analysis_context = create_context(
        analysis_input,
        assignments=[
            Assignment(
                line_number=1,
                column_number=1,
                assigned_variable=VariableReference(
                    line_number=1,
                    column_number=1,
                    variable_name="password",
                ),
                assigned_value=StringLiteral(
                    line_number=1,
                    column_number=12,
                    value="secret123",
                ),
            ),
        ],
    )

    findings = hardcoded_credentials_rule.analyse(analysis_context)

    assert len(findings) == 1

    detected_finding = findings[0]

    # Finding identity
    assert detected_finding.vulnerability_rule_id == "GEN001"

    # Finding severity
    assert detected_finding.severity is Severity.HIGH

    # Finding source position
    assert detected_finding.line_number == 1
    assert detected_finding.column_number == 1


def test_ignore_variable_reference(analysis_input) -> None:
    """
    Verify that references to other variables are not reported.

    The rule only detects credentials that are directly embedded as
    literal values. Resolving variable dependencies would require a
    separate data-flow analysis component.
    """

    hardcoded_credentials_rule: HardcodedCredentialsRule = HardcodedCredentialsRule()

    analysis_context = create_context(
        analysis_input,
        assignments=[
            Assignment(
                line_number=1,
                column_number=1,
                assigned_variable=VariableReference(
                    line_number=1,
                    column_number=1,
                    variable_name="password",
                ),
                assigned_value=VariableReference(
                    line_number=1,
                    column_number=15,
                    variable_name="secret",
                ),
            ),
        ],
    )

    assert hardcoded_credentials_rule.analyse(analysis_context) == []


def test_ignore_unknown_expression(analysis_input) -> None:
    """
    Verify that unresolved expressions are not reported.

    Expressions whose values cannot be determined statically are outside
    the responsibility of this rule. They may be handled by future rules
    that perform more advanced data-flow analysis.
    """

    hardcoded_credentials_rule: HardcodedCredentialsRule = HardcodedCredentialsRule()

    analysis_context = create_context(
        analysis_input,
        assignments=[
            Assignment(
                line_number=1,
                column_number=1,
                assigned_variable=VariableReference(
                    line_number=1,
                    column_number=1,
                    variable_name="password",
                ),
                assigned_value=UnknownExpression(
                    line_number=1,
                    column_number=15,
                    source_text="token.strip()",
                ),
            ),
        ],
    )

    assert hardcoded_credentials_rule.analyse(analysis_context) == []


def test_ignore_non_secret_variable(analysis_input) -> None:
    """
    Verify that assignments to unrelated variables are ignored.
    """

    hardcoded_credentials_rule: HardcodedCredentialsRule = HardcodedCredentialsRule()

    analysis_context = create_context(
        analysis_input,
        assignments=[
            Assignment(
                line_number=1,
                column_number=1,
                assigned_variable=VariableReference(
                    line_number=1,
                    column_number=1,
                    variable_name="counter",
                ),
                assigned_value=StringLiteral(
                    line_number=1,
                    column_number=12,
                    value="secret123",
                ),
            ),
        ],
    )

    assert hardcoded_credentials_rule.analyse(analysis_context) == []


def test_ignore_short_password_literal(analysis_input) -> None:
    """
    Verify that short literal values are not reported.

    Literal values below the minimum length threshold are ignored because
    they are unlikely to represent hardcoded credentials.
    """

    hardcoded_credentials_rule: HardcodedCredentialsRule = HardcodedCredentialsRule()

    analysis_context = create_context(
        analysis_input,
        assignments=[
            Assignment(
                line_number=1,
                column_number=1,
                assigned_variable=VariableReference(
                    line_number=1,
                    column_number=1,
                    variable_name="password",
                ),
                assigned_value=StringLiteral(
                    line_number=1,
                    column_number=12,
                    value="abcde",
                ),
            ),
        ],
    )

    assert hardcoded_credentials_rule.analyse(analysis_context) == []
