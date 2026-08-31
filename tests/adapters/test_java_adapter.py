from __future__ import annotations

from pathlib import Path

import pytest

from scanner.adapter import Adapter
from scanner.model import (
    AnalysisContext,
    StringLiteral,
    UnknownExpression,
    VariableReference,
)
from scanner.parser import Parser

# Directory containing all Java adapter test resources.
TEST_RESOURCES_DIRECTORY: Path = Path(__file__).parent / "resources" / "java"

# Test resource file names.
ASSIGNMENTS_SOURCE_FILE: str = "assignments.java"
FUNCTION_CALLS_SOURCE_FILE: str = "function_calls.java"
MIXED_SOURCE_FILE: str = "mixed.java"
EMPTY_SOURCE_FILE: str = "empty.java"
SYNTAX_ERROR_SOURCE_FILE: str = "syntax_error.java"


@pytest.fixture(scope="module")
def parser() -> Parser:
    """
    Create a shared parser instance.

    The parser is reused across all tests to reflect its intended usage
    within the application and to avoid unnecessary object creation.
    """

    return Parser()


@pytest.fixture(scope="module")
def adapter() -> Adapter:
    """
    Create the adapter under test.

    The adapter transforms the parser output into an AnalysisContext that
    can be consumed by later analysis stages. Separating parsing and
    adaptation keeps the overall architecture modular and allows both
    components to evolve independently.
    """

    return Adapter()


def analyse_source_file(
    parser: Parser, adapter: Adapter, source_file_name: str
) -> AnalysisContext:
    """
    Parse and adapt a source file used by the test suite.

    This helper function removes duplicated setup code from the individual
    tests and provides a single location for creating an AnalysisContext.
    """

    analysis_input = parser.parse(
        TEST_RESOURCES_DIRECTORY / source_file_name,
    )

    return adapter.adapt(analysis_input)


def test_extract_assignments(parser: Parser, adapter: Adapter) -> None:
    """
    Verify that variable assignments are extracted correctly.

    The adapter should preserve the assigned variable, the assigned value,
    and the original source position for every assignment encountered.
    """

    analysis_context: AnalysisContext = analyse_source_file(
        parser,
        adapter,
        ASSIGNMENTS_SOURCE_FILE,
    )

    assert len(analysis_context.assignments) == 3

    first_assignment = analysis_context.assignments[0]

    assert first_assignment.assigned_variable.variable_name == "password"
    assert isinstance(first_assignment.assigned_value, StringLiteral)
    assert first_assignment.assigned_value.value == "secret123"

    second_assignment = analysis_context.assignments[1]

    assert second_assignment.assigned_variable.variable_name == "token"
    assert isinstance(second_assignment.assigned_value, VariableReference)
    assert second_assignment.assigned_value.variable_name == "password"

    third_assignment = analysis_context.assignments[2]

    assert third_assignment.assigned_variable.variable_name == "secret"
    assert isinstance(third_assignment.assigned_value, UnknownExpression)
    assert third_assignment.assigned_value.source_text == "token.strip()"


def test_extract_function_calls(parser: Parser, adapter: Adapter) -> None:
    """
    Verify that function calls are extracted correctly.

    Both qualified and unqualified function calls should be detected
    together with their arguments.
    """

    analysis_context: AnalysisContext = analyse_source_file(
        parser,
        adapter,
        FUNCTION_CALLS_SOURCE_FILE,
    )

    assert len(analysis_context.function_calls) == 3

    first_call = analysis_context.function_calls[0]

    assert first_call.qualifier is None
    assert first_call.function_name == "eval"
    assert len(first_call.arguments) == 1
    assert isinstance(first_call.arguments[0], VariableReference)

    second_call = analysis_context.function_calls[1]

    assert second_call.qualifier == "os"
    assert second_call.function_name == "system"
    assert len(second_call.arguments) == 1

    third_call = analysis_context.function_calls[2]

    assert third_call.qualifier == "subprocess"
    assert third_call.function_name == "run"


def test_extract_function_call_arguments(parser: Parser, adapter: Adapter) -> None:
    """
    Verify that function call arguments preserve their original expression
    types.

    Literal values, variable references and unsupported expressions should
    be represented by their corresponding model classes.
    """

    analysis_context: AnalysisContext = analyse_source_file(
        parser,
        adapter,
        MIXED_SOURCE_FILE,
    )

    function_call = analysis_context.function_calls[-2]

    assert function_call.function_name == "run"
    assert len(function_call.arguments) == 3

    assert isinstance(function_call.arguments[0], StringLiteral)
    assert isinstance(function_call.arguments[1], VariableReference)
    assert isinstance(function_call.arguments[2], UnknownExpression)

    assert function_call.arguments[2].source_text == "token.strip()"


def test_preserve_source_order(parser: Parser, adapter: Adapter) -> None:
    """
    Verify that assignments and function calls remain in their original
    source order.

    Preserving the source order simplifies later analysis stages because
    no additional sorting is required.
    """

    analysis_context: AnalysisContext = analyse_source_file(
        parser,
        adapter,
        MIXED_SOURCE_FILE,
    )

    assert [
        assignment.assigned_variable.variable_name
        for assignment in analysis_context.assignments
    ] == [
        "password",
        "token",
        "secret",
    ]

    assert [
        function_call.function_name for function_call in analysis_context.function_calls
    ] == [
        "strip",
        "eval",
        "system",
        "run",
        "strip",
    ]


def test_source_positions(parser: Parser, adapter: Adapter) -> None:
    """
    Verify that all extracted elements preserve their original source
    location.

    Accurate source positions enable later analysis stages to generate
    precise diagnostics and findings.
    """

    analysis_context: AnalysisContext = analyse_source_file(
        parser,
        adapter,
        MIXED_SOURCE_FILE,
    )

    first_assignment = analysis_context.assignments[0]

    assert first_assignment.assigned_variable.variable_name == "password"
    assert first_assignment.line_number == 3
    assert first_assignment.column_number == 16

    second_assignment = analysis_context.assignments[1]

    assert second_assignment.assigned_variable.variable_name == "token"
    assert second_assignment.line_number == 5
    assert second_assignment.column_number == 16

    third_assignment = analysis_context.assignments[2]

    assert third_assignment.assigned_variable.variable_name == "secret"
    assert third_assignment.line_number == 7
    assert third_assignment.column_number == 16

    eval_call = analysis_context.function_calls[1]

    assert eval_call.function_name == "eval"
    assert eval_call.line_number == 9
    assert eval_call.column_number == 9

    system_call = analysis_context.function_calls[2]

    assert system_call.qualifier == "os"
    assert system_call.function_name == "system"
    assert system_call.line_number == 11
    assert system_call.column_number == 12

    run_call = analysis_context.function_calls[3]

    assert run_call.qualifier is None
    assert run_call.function_name == "run"
    assert run_call.line_number == 13
    assert run_call.column_number == 9

    string_literal = run_call.arguments[0]

    assert isinstance(string_literal, StringLiteral)
    assert string_literal.line_number == 14
    assert string_literal.column_number == 13

    variable_reference = run_call.arguments[1]

    assert isinstance(variable_reference, VariableReference)
    assert variable_reference.line_number == 15
    assert variable_reference.column_number == 13

    unknown_expression = run_call.arguments[2]

    assert isinstance(unknown_expression, UnknownExpression)
    assert unknown_expression.line_number == 16
    assert unknown_expression.column_number == 13


def test_empty_file(parser: Parser, adapter: Adapter) -> None:
    """
    Verify that an empty source file produces an empty AnalysisContext.

    Downstream analysis stages should always receive a valid context,
    even if no language constructs were extracted.
    """

    analysis_context: AnalysisContext = analyse_source_file(
        parser,
        adapter,
        EMPTY_SOURCE_FILE,
    )

    assert analysis_context.assignments == ()
    assert analysis_context.function_calls == ()


def test_syntax_error(parser: Parser, adapter: Adapter) -> None:
    """
    Verify that syntactically invalid source code is still processed.

    Tree-sitter provides a syntax tree even for invalid source code,
    allowing the adapter and later analysis stages to inspect incomplete
    programs without aborting the analysis.
    """

    analysis_context: AnalysisContext = analyse_source_file(
        parser,
        adapter,
        SYNTAX_ERROR_SOURCE_FILE,
    )

    assert isinstance(analysis_context, AnalysisContext)
    assert analysis_context.analysis_input.syntax_tree.root_node.has_error
