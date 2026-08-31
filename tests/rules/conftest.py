from __future__ import annotations

from pathlib import Path

import pytest

from scanner.model import (
    AnalysisContext,
    AnalysisInput,
    Assignment,
    FunctionCall,
    Language,
)


class DummySyntaxTree:
    """
    Minimal placeholder representing a syntax tree during rule tests.

    Rule tests focus on analysing already extracted program structures.
    They do not require a real parser syntax tree, therefore a lightweight
    replacement is used to keep tests independent from the parser component.

    This separation keeps the rule tests fast and ensures that each test
    validates only the behaviour of the component under test.
    """


@pytest.fixture
def analysis_input() -> AnalysisInput:
    """
    Create a minimal AnalysisInput instance for unit tests.

    The created object contains only the information required by analysis
    rules. Parser-specific details are replaced with test placeholders
    because rules operate on the analysis model rather than directly on
    source code.
    """

    source_file_path: Path = Path("example.py")
    source_code: str = ""
    source_code_bytes: bytes = b""

    return AnalysisInput(
        source_file_path=source_file_path,
        programming_language=Language.PYTHON,
        source_code=source_code,
        source_code_bytes=source_code_bytes,
        syntax_tree=DummySyntaxTree(),  # type: ignore[arg-type]
    )


def create_context(
    analysis_input: AnalysisInput,
    *,
    assignments: list[Assignment] | None = None,
    function_calls: list[FunctionCall] | None = None,
) -> AnalysisContext:
    """
    Create an AnalysisContext for rule unit tests.

    The helper allows individual tests to provide only the program elements
    relevant for the rule being tested. This keeps security rule tests
    isolated and avoids unnecessary dependencies on the parser or adapter
    components.

    Lists are converted into tuples because AnalysisContext represents the
    extracted program structure as immutable analysis data.
    """

    assignment_list: list[Assignment] = assignments or []
    function_call_list: list[FunctionCall] = function_calls or []

    return AnalysisContext(
        analysis_input=analysis_input,
        assignments=tuple(assignment_list),
        function_calls=tuple(function_call_list),
    )
