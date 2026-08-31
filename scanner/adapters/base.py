from __future__ import annotations

from abc import ABC, abstractmethod
from tree_sitter import Node

from scanner.model import (
    AnalysisContext,
    AnalysisInput,
    AnalysisNode,
    StringLiteral,
    UnknownExpression,
    VariableReference,
)


class BaseAdapter(ABC):
    """
    Abstract base class for language-specific adapters.

    Each supported programming language provides its own adapter that extracts
    language-specific information from the parsed source code. The extracted
    information is transformed into a normalized AnalysisContext, which serves
    as the language-independent interface for the Rule Engine.

    This architecture separates language-specific parsing from vulnerability
    detection, making the scanner modular and easily extensible. Supporting an
    additional programming language only requires implementing this adapter
    without modifying the remaining analysis pipeline.
    """

    # ------------------------------------------------------------------
    # General constants
    # ------------------------------------------------------------------

    _TREE_SITTER_INDEX_OFFSET: int = 1
    _MIN_QUOTED_STRING_LENGTH: int = 2
    _UTF8_ENCODING: str = "utf-8"

    _SINGLE_QUOTE: str = "'"
    _DOUBLE_QUOTE: str = '"'

    def adapt(self, analysis_input: AnalysisInput) -> AnalysisContext:
        """
        Create a normalized analysis context from the given analysis input.

        This method defines the common workflow for every language adapter.
        Concrete subclasses are responsible for extracting language-specific
        syntax elements, while this method combines the extracted information
        into a single AnalysisContext.

        The implementation follows the Template Method design pattern to
        guarantee a consistent analysis process across all supported
        programming languages.

        Args:
            analysis_input:
                Parsed source code and additional information required for
                the language-specific analysis.

        Returns:
            A normalized AnalysisContext containing all extracted information
            required by the Rule Engine.
        """

        # Extract all assignment expressions from the source code.
        assignments: list[AnalysisNode] = self._extract_assignments(analysis_input)

        # Extract all function call expressions from the source code.
        function_calls: list[AnalysisNode] = self._extract_function_calls(
            analysis_input
        )

        # Convert mutable lists into immutable tuples before creating the
        # analysis context to prevent accidental modification during later
        # processing stages.
        return AnalysisContext(
            analysis_input=analysis_input,
            assignments=tuple(assignments),
            function_calls=tuple(function_calls),
        )

    @abstractmethod
    def _extract_assignments(self, analysis_input: AnalysisInput) -> list[AnalysisNode]:
        """
        Extract all assignment expressions from the analyzed source code.

        The concrete implementation depends on the programming language and
        its corresponding abstract syntax tree (AST) representation.

        Args:
            analysis_input:
                Parsed source code that should be analyzed.

        Returns:
            A list containing one AnalysisNode for each detected assignment.
        """
        ...

    @abstractmethod
    def _extract_function_calls(
        self, analysis_input: AnalysisInput
    ) -> list[AnalysisNode]:
        """
        Extract all function call expressions from the analyzed source code.

        The concrete implementation depends on the programming language and
        its corresponding abstract syntax tree (AST) representation.

        Args:
            analysis_input:
                Parsed source code that should be analyzed.

        Returns:
            A list containing one AnalysisNode for each detected function call.
        """
        ...

    def _create_string_literal(self, node: Node) -> StringLiteral:
        """
        Create a language-independent string literal from a Tree-sitter node.

        Args:
            node:
                Tree-sitter string node.

        Returns:
            The corresponding string literal model.
        """

        line: int
        column: int

        line, column = self._source_position(node)

        return StringLiteral(
            line_number=line,
            column_number=column,
            value=self._strip_quotes(self._text(node)),
        )

    def _create_variable_reference(self, node: Node) -> VariableReference:
        """
        Create a language-independent variable reference from a Tree-sitter node.

        Args:
            node:
                Tree-sitter identifier node.

        Returns:
            The corresponding variable reference model.
        """

        line: int
        column: int

        line, column = self._source_position(node)

        return VariableReference(
            line_number=line, column_number=column, variable_name=self._text(node)
        )

    def _create_unknown_expression(self, node: Node) -> UnknownExpression:
        """
        Create a language-independent unknown expression from a Tree-sitter node.

        Args:
            node:
                Tree-sitter unknown expression node.

        Returns:
            The corresponding unknown expression model.
        """

        line: int
        column: int

        line, column = self._source_position(node)

        return UnknownExpression(
            line_number=line, column_number=column, source_text=self._text(node)
        )

    @staticmethod
    def _source_position(node: Node) -> tuple[int, int]:
        """
        Return the 1-based source position of a Tree-sitter node.

        Tree-sitter internally stores source locations using zero-based
        indices. The analysis model uses one-based line and column numbers
        to improve readability for users and rule implementations.

        Args:
            node:
                Tree-sitter node whose source position should be returned.

        Returns:
            A tuple containing the one-based line and column number.
        """

        return (
            node.start_point.row + BaseAdapter._TREE_SITTER_INDEX_OFFSET,
            node.start_point.column + BaseAdapter._TREE_SITTER_INDEX_OFFSET,
        )

    @staticmethod
    def _strip_quotes(string_literal: str) -> str:
        """
        Remove the surrounding quotation marks from a string literal.

        The method supports both single-quoted and double-quoted string
        literals. If the supplied text is not enclosed by matching
        quotation marks, it is returned unchanged.

        Args:
            string_literal:
                String literal exactly as represented in the Tree-sitter AST.

        Returns:
            The unquoted string literal.
        """

        if len(string_literal) < BaseAdapter._MIN_QUOTED_STRING_LENGTH:
            return string_literal

        opening_quote: str = string_literal[0]
        closing_quote: str = string_literal[-1]

        if opening_quote == closing_quote and opening_quote in (
            BaseAdapter._SINGLE_QUOTE,
            BaseAdapter._DOUBLE_QUOTE,
        ):
            return string_literal[1:-1]

        return string_literal

    @staticmethod
    def _text(node: Node) -> str:
        """
        Decode the UTF-8 encoded source code represented by a Tree-sitter node.

        Tree-sitter stores the original source code as bytes. This helper
        converts the byte sequence into a Python string so it can be used
        by the language-independent analysis model.

        Args:
            node:
                Tree-sitter node whose source text should be returned.

        Returns:
            The decoded source code represented by the given node.
        """

        return node.text.decode(BaseAdapter._UTF8_ENCODING)
