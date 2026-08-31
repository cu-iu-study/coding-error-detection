from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from tree_sitter import Tree

# File extensions are defined as constants to avoid duplicated literal values.
# They can be extended easily when additional programming languages are supported.
PYTHON_FILE_EXTENSION: str = ".py"
JAVA_FILE_EXTENSION: str = ".java"
JAVASCRIPT_FILE_EXTENSION: str = ".js"


class Language(StrEnum):
    """
    Supported programming languages for source code analysis.
    """

    PYTHON = "python"
    JAVA = "java"
    JAVASCRIPT = "javascript"

    @property
    def file_extension(self) -> str:
        """
        Returns the default source file extension for the programming language.

        This abstraction allows external components to determine file types
        without implementing language-specific logic themselves.
        """
        return {
            Language.PYTHON: PYTHON_FILE_EXTENSION,
            Language.JAVA: JAVA_FILE_EXTENSION,
            Language.JAVASCRIPT: JAVASCRIPT_FILE_EXTENSION,
        }[self]


@dataclass(frozen=True, slots=True)
class AnalysisInput:
    """
    Immutable input container required for source code analysis.

    Language-specific adapters consume this object and transform the parsed
    syntax tree into a language-independent analysis representation.
    """

    source_file_path: Path
    programming_language: Language

    source_code: str
    source_code_bytes: bytes

    syntax_tree: Tree


@dataclass(frozen=True, slots=True)
class AnalysisNode:
    """
    Base class for all language-independent analysis elements.

    Every analysis element stores its original source location to enable
    traceability between detected structures and the source code.
    """

    line_number: int
    column_number: int


@dataclass(frozen=True, slots=True)
class StringLiteral(AnalysisNode):
    """
    Represents a string value directly defined in the source code.

    Example:
        username = "admin"

    The value field would contain:
        admin
    """

    value: str


@dataclass(frozen=True, slots=True)
class VariableReference(AnalysisNode):
    """
    Represents a reference to an existing variable.

    Example:
        execute(user_input)

    The variable reference would contain:
        user_input
    """

    variable_name: str


@dataclass(frozen=True, slots=True)
class UnknownExpression(AnalysisNode):
    """
    Represents an expression that cannot currently be classified.

    This fallback type keeps the analysis model extensible because language
    adapters can still provide information without requiring immediate support
    for every possible language construct.
    """

    source_text: str


# An expression is intentionally limited to the constructs currently required
# by the specification. Additional expression types can be introduced later
# without changing existing analysis consumers.
Expression = StringLiteral | VariableReference | UnknownExpression


@dataclass(frozen=True, slots=True)
class Assignment(AnalysisNode):
    """
    Represents a variable assignment statement.

    Example:
        query = user_input

    The assignment stores both the affected variable and the assigned value,
    allowing later analysis rules to track data flow.
    """

    assigned_variable: VariableReference
    assigned_value: Expression | None


@dataclass(frozen=True, slots=True)
class FunctionCall(AnalysisNode):
    """
    Represents a function or method invocation.

    Example:
        database.execute(query)

    The qualifier stores the optional object or module name, while the function
    name stores the called operation.
    """

    qualifier: str | None
    function_name: str
    arguments: tuple[Expression, ...]


@dataclass(frozen=True, slots=True)
class AnalysisContext:
    """
    Immutable result produced by a language-specific analysis adapter.

    The context contains only language-independent information so that
    vulnerability detection components can operate consistently across
    different programming languages.
    """

    analysis_input: AnalysisInput
    assignments: tuple[Assignment, ...]
    function_calls: tuple[FunctionCall, ...]
