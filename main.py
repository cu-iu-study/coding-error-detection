from __future__ import annotations

import argparse
import sys
from pathlib import Path

from reports.console import ConsoleReporter
from scanner.adapter import Adapter
from scanner.engine import RuleEngine
from scanner.findings import Finding
from scanner.model import (
    Assignment,
    StringLiteral,
    UnknownExpression,
    VariableReference,
)
from scanner.parser import Parser

# Application return codes.
SUCCESS_EXIT_CODE: int = 0
ERROR_EXIT_CODE: int = 1

# Formatting constants.
_HEADER_SEPARATOR: str = "=" * 80
_SECTION_SEPARATOR: str = "-" * 80


def _parse_arguments() -> argparse.Namespace:
    """
    Parse command line arguments.

    The command line interface is intentionally kept separate from the
    analysis implementation. This allows the scanner logic to be reused
    by other interfaces in the future, for example a graphical user interface
    or an automated analysis pipeline.
    """

    argument_parser: argparse.ArgumentParser = argparse.ArgumentParser(
        prog="error-coding-detection",
        description="Static vulnerability scanner based on Tree-sitter.",
        epilog=("Example:\n" "  python main.py samples/vulnerable/example.py\n"),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    argument_parser.add_argument(
        "file",
        type=Path,
        help="Source file to analyse.",
    )

    argument_parser.add_argument(
        "--debug",
        action="store_true",
        help="Print the generated AnalysisContext before executing the rules.",
    )

    return argument_parser.parse_args()


def _print_expression(expression: object) -> None:
    """
    Print an expression from the language-independent analysis model.

    The adapter converts language-specific syntax trees into a small set of
    generic expression types. Handling these types here keeps the debug output
    independent from the original programming language syntax.
    """

    if isinstance(expression, StringLiteral):
        print(f'    StringLiteral("{expression.value}")')

    elif isinstance(expression, VariableReference):
        print(f"    VariableReference({expression.variable_name})")

    elif isinstance(expression, UnknownExpression):
        print(f'    UnknownExpression("{expression.source_text}")')


def _print_analysis_context(analysis_context: AnalysisContext) -> None:
    """
    Print the generated language-independent analysis model.

    This debug representation helps developers and evaluators understand
    the intermediate representation used by the rule engine. The model is
    intentionally separated from the parser to support future extensions
    with additional programming languages.
    """

    print(_HEADER_SEPARATOR)
    print("Analysis Context")
    print(_HEADER_SEPARATOR)

    print(f"File      : " f"{analysis_context.analysis_input.source_file_path}")
    print(
        f"Language  : " f"{analysis_context.analysis_input.programming_language.value}"
    )
    print()

    print("Assignments")
    print(_SECTION_SEPARATOR)

    if not analysis_context.assignments:
        print("None")

    else:
        for assignment in analysis_context.assignments:
            print(
                f"{assignment.line_number}:{assignment.column_number} "
                f"{assignment.assigned_variable}"
            )

            _print_expression(assignment.assigned_value)

            print()

    print()
    print("Function Calls")
    print(_SECTION_SEPARATOR)

    if not analysis_context.function_calls:
        print("None")

    else:
        for function_call in analysis_context.function_calls:

            qualified_function_name: str = (
                f"{function_call.qualifier}." f"{function_call.function_name}"
                if function_call.qualifier
                else function_call.function_name
            )

            print(
                f"{function_call.line_number}:"
                f"{function_call.column_number} "
                f"{qualified_function_name}"
            )

            if not function_call.arguments:
                print("    No arguments")

            else:
                for argument in function_call.arguments:
                    _print_expression(argument)

            print()

    print(_HEADER_SEPARATOR)
    print()


def main() -> int:
    """
    Execute the complete vulnerability scanning workflow.

    The application flow follows a layered architecture:

    Source file
        -> Parser
        -> Adapter
        -> Language-independent analysis model
        -> Rule engine
        -> Reporter

    Each component has a dedicated responsibility, which allows individual
    parts of the scanner to be replaced or extended independently.
    """

    command_line_arguments: argparse.Namespace = _parse_arguments()

    try:
        source_parser: Parser = Parser()
        parser_result: AnalysisInput = source_parser.parse(command_line_arguments.file)

        analysis_adapter: Adapter = Adapter()
        analysis_context: AnalysisContext = analysis_adapter.adapt(parser_result)

        if command_line_arguments.debug:
            _print_analysis_context(analysis_context)

        rule_engine: RuleEngine = RuleEngine()
        findings: list[Finding] = rule_engine.analyse(analysis_context)

        console_reporter: ConsoleReporter = ConsoleReporter()
        console_reporter.report(findings)

        return SUCCESS_EXIT_CODE

    except FileNotFoundError as error:
        print(
            f"Error: File not found: {error}",
            file=sys.stderr,
        )

    except PermissionError as error:
        print(
            f"Error: Cannot access file: {error}",
            file=sys.stderr,
        )

    except ValueError as error:
        print(
            f"Error: {error}",
            file=sys.stderr,
        )

    except KeyboardInterrupt:
        print(
            "\nAnalysis cancelled.",
            file=sys.stderr,
        )

    except Exception as error:
        print(
            f"Unexpected error: {error}",
            file=sys.stderr,
        )

        # The exception is intentionally not re-raised because this is a CLI
        # application. Users receive an error code instead of a stack trace.

    return ERROR_EXIT_CODE


if __name__ == "__main__":
    raise SystemExit(main())
