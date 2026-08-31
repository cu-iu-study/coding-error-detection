from __future__ import annotations

from tree_sitter import Language, Node, Query, QueryCursor

import tree_sitter_javascript

from scanner.adapters.base import BaseAdapter
from scanner.model import (
    AnalysisInput,
    Assignment,
    Expression,
    FunctionCall,
    StringLiteral,
    VariableReference,
)


class JavaScriptAdapter(BaseAdapter):
    """
    Tree-sitter based language adapter for JavaScript source code.

    This adapter is responsible for extracting language-specific
    constructs from a JavaScript Abstract Syntax Tree (AST) and converting
    them into the language-independent analysis model used by the
    Rule Engine.

    The current implementation intentionally supports only the language
    constructs required by the project specification. The internal
    architecture is designed to be easily extensible by introducing
    additional Tree-sitter queries and expression mappings without
    changing the public interface.
    """

    # -------------------------------------------------------------------------
    # Tree-sitter language configuration
    # -------------------------------------------------------------------------

    _JAVASCRIPT_LANGUAGE: Language = Language(tree_sitter_javascript.language())

    # -------------------------------------------------------------------------
    # Tree-sitter node types
    # -------------------------------------------------------------------------

    _IDENTIFIER_NODE_TYPE: str = "identifier"
    _PROPERTY_IDENTIFIER_NODE_TYPE: str = "property_identifier"
    _STRING_LITERAL_NODE_TYPE: str = "string"
    _MEMBER_EXPRESSION_NODE_TYPE: str = "member_expression"

    # -------------------------------------------------------------------------
    # Tree-sitter field names
    # -------------------------------------------------------------------------

    _OBJECT_FIELD_NAME: str = "object"
    _PROPERTY_FIELD_NAME: str = "property"

    # -------------------------------------------------------------------------
    # Tree-sitter query capture names
    # -------------------------------------------------------------------------

    _TARGET_CAPTURE_NAME: str = "target"
    _VALUE_CAPTURE_NAME: str = "value"
    _FUNCTION_CAPTURE_NAME: str = "function"
    _ARGUMENTS_CAPTURE_NAME: str = "arguments"

    # ------------------------------------------------------------------
    # Tree-sitter query definitions
    # ------------------------------------------------------------------

    _VARIABLE_DECLARATION_QUERY_SOURCE: str = """
        (variable_declarator
            name: (_) @target
            value: (_) @value
        )
        """

    _ASSIGNMENT_QUERY_SOURCE: str = """
        (assignment_expression
            left: (_) @target
            right: (_) @value
        )
        """

    _FIELD_DEFINIION_QUERY_SOURCE: str = """
        (field_definition
            property: (_) @target
            value: (_) @value
        )
        """

    _FUNCTION_CALL_QUERY_SOURCE: str = """
        (call_expression
            function: (_) @function
            arguments: (arguments) @arguments
        )
        """

    _VARIABLE_DECLARATION_QUERY: Query = Query(
        _JAVASCRIPT_LANGUAGE,
        _VARIABLE_DECLARATION_QUERY_SOURCE,
    )

    _ASSIGNMENT_QUERY: Query = Query(
        _JAVASCRIPT_LANGUAGE,
        _ASSIGNMENT_QUERY_SOURCE,
    )

    _FIELD_DEFINIION_QUERY: Query = Query(
        _JAVASCRIPT_LANGUAGE,
        _FIELD_DEFINIION_QUERY_SOURCE,
    )

    _FUNCTION_CALL_QUERY: Query = Query(
        _JAVASCRIPT_LANGUAGE,
        _FUNCTION_CALL_QUERY_SOURCE,
    )

    def _extract_assignments(self, analysis: AnalysisInput) -> list[Assignment]:
        """
        Extract all supported assignment statements from the JavaScript AST.

        Only assignments whose target can be represented as a
        VariableReference are currently supported. More complex
        assignment targets (e.g. attribute assignments or subscript
        assignments) are intentionally ignored because they are not
        required by the current specification.

        JavaScript represents assignments in different syntax tree structures depending
        on whether a variable is declared or assigned later. This method normalises
        both representations into the common Assignment model so that the rule
        engine can process them independently of the original JavaScript syntax.

        Args:
            analysis:
                Parsed source code including the Tree-sitter syntax tree.

        Returns:
            A list containing all extracted assignment model objects.
        """

        extracted_assignments: list[Assignment] = []

        assignment_queries: tuple[Query, ...] = (
            self._VARIABLE_DECLARATION_QUERY,
            self._ASSIGNMENT_QUERY,
            self._FIELD_DEFINIION_QUERY,
        )

        for assignment_query in assignment_queries:

            # Execute the Tree-sitter query to locate every assignment node.
            query_matches = QueryCursor(assignment_query).matches(
                analysis.syntax_tree.root_node
            )

            for _, query_captures in query_matches:

                target_node: Node = query_captures[self._TARGET_CAPTURE_NAME][0]
                value_node: Node = query_captures[self._VALUE_CAPTURE_NAME][0]

                target_expression: Expression | None = self._expression(target_node)
                value_expression: Expression | None = self._expression(value_node)

                # Only variable references can be used as assignment targets in the
                # language-independent analysis model.
                if not isinstance(target_expression, VariableReference):
                    continue

                line_number: int
                column_number: int

                line_number, column_number = self._source_position(target_node)

                extracted_assignments.append(
                    Assignment(
                        line_number=line_number,
                        column_number=column_number,
                        assigned_variable=target_expression,
                        assigned_value=value_expression,
                    )
                )

        return extracted_assignments

    def _extract_function_calls(self, analysis: AnalysisInput) -> list[FunctionCall]:
        """
        Extract all function calls from the JavaScript AST.

        Every function call is transformed into the language-independent
        FunctionCall model. Supported argument expressions are converted
        using the internal expression mapping. Unsupported argument types
        are ignored intentionally and can be added in future extensions.

        Args:
            analysis:
                Parsed source code including the Tree-sitter syntax tree.

        Returns:
            A list containing all extracted function calls.
        """

        extracted_function_calls: list[FunctionCall] = []

        # Execute the Tree-sitter query to locate every function call.
        query_matches = QueryCursor(self._FUNCTION_CALL_QUERY).matches(
            analysis.syntax_tree.root_node
        )

        for _, query_captures in query_matches:

            function_node: Node = query_captures[self._FUNCTION_CAPTURE_NAME][0]
            arguments_node: Node = query_captures[self._ARGUMENTS_CAPTURE_NAME][0]

            qualifier: str | None
            function_name: str

            qualifier, function_name = self._qualified_name(function_node)

            extracted_arguments: list[Expression] = []

            # Convert every supported argument expression into the
            # language-independent analysis model.
            for argument_node in arguments_node.named_children:

                argument_expression: Expression = self._expression(argument_node)

                extracted_arguments.append(argument_expression)

            line_number: int
            column_number: int

            line_number, column_number = self._source_position(function_node)

            extracted_function_calls.append(
                FunctionCall(
                    line_number=line_number,
                    column_number=column_number,
                    qualifier=qualifier,
                    function_name=function_name,
                    arguments=tuple(extracted_arguments),
                )
            )

        return extracted_function_calls

    def _expression(self, node: Node) -> Expression | None:
        """
        Convert a Tree-sitter expression node into the language-independent
        analysis model.

        Only expression types required by the current project specification
        are currently supported. Unsupported expression types return
        None and are intentionally ignored by the extraction process.

        The method acts as the central extension point for introducing
        additional JavaScript expression types without changing the public
        interface of the adapter.

        Args:
            node:
                Tree-sitter node representing a JavaScript expression.

        Returns:
            The corresponding language-independent expression object or
            None if the node type is currently unsupported.
        """

        node_type: str = node.type

        match node_type:

            case self._IDENTIFIER_NODE_TYPE:
                return self._create_variable_reference(node)

            case self._STRING_LITERAL_NODE_TYPE:
                return self._create_string_literal(node)

            case _:

                # Only the expression types required by the current
                # specification are supported. Additional mappings can be
                # introduced here without modifying the adapter's public API.

                return self._create_unknown_expression(node)

    def _qualified_name(self, node: Node) -> tuple[str | None, str]:
        """
        Resolve a function expression into a qualifier/name pair.

        Nested attribute accesses are processed recursively.

        Example:

            console.log()
                qualifier = "console"
                name = "log"

        Args:
            node:
                Tree-sitter node representing the callable expression.

        Returns:
            A tuple consisting of

            - the fully qualified object path (or None)
            - the callable name
        """

        node_type: str = node.type

        if node_type == self._IDENTIFIER_NODE_TYPE:
            return None, self._text(node)

        if node_type == self._MEMBER_EXPRESSION_NODE_TYPE:

            object_node = node.child_by_field_name(self._OBJECT_FIELD_NAME)
            property_node = node.child_by_field_name(self._PROPERTY_FIELD_NAME)

            assert object_node is not None
            assert property_node is not None

            qualifier: str | None
            object_name: str

            qualifier, object_name = self._qualified_name(object_node)
            property_name: str = self._text(property_node)

            if qualifier is None:
                qualifier = object_name
            else:
                qualifier = f"{qualifier}.{object_name}"

            return qualifier, property_name

        return None, self._text(node)
