from __future__ import annotations

from pathlib import Path

import pytest

from scanner.model import AnalysisInput, Language
from scanner.parser import Parser

# Directory containing all parser test resources.
TEST_RESOURCES_DIRECTORY: Path = Path(__file__).parent / "resources"

# Test resource file names.
PYTHON_SOURCE_FILE: str = "hello.py"
JAVA_SOURCE_FILE: str = "Hello.java"
JAVASCRIPT_SOURCE_FILE: str = "hello.js"
EMPTY_SOURCE_FILE: str = "empty.py"
UNSUPPORTED_SOURCE_FILE: str = "hello.c"
MISSING_SOURCE_FILE: str = "does_not_exist.py"
INVALID_UTF8_SOURCE_FILE: str = "invalid_utf8.py"
SYNTAX_ERROR_SOURCE_FILE: str = "syntax_error.py"


@pytest.fixture(scope="module")
def parser() -> Parser:
    """
    Create a shared parser instance for all tests in this module.

    Reusing the parser improves test execution time and reflects the
    intended architecture, where the parser can be instantiated once
    and reused for analysing multiple source files.
    """
    return Parser()


@pytest.mark.parametrize(
    ("source_file_name", "expected_language"),
    [
        (PYTHON_SOURCE_FILE, Language.PYTHON),
        (JAVA_SOURCE_FILE, Language.JAVA),
        (JAVASCRIPT_SOURCE_FILE, Language.JAVASCRIPT),
    ],
)
def test_parse_supported_languages(
    parser: Parser, source_file_name: str, expected_language: Language
) -> None:
    """
    Verify that supported source files are parsed successfully.

    The parser is expected to

    - detect the correct programming language,
    - read the complete source code,
    - create an AnalysisInput instance,
    - generate a valid Tree-sitter syntax tree.

    The implementation currently supports only the languages required
    by the specification. However, the architecture is intentionally
    designed to allow additional languages to be integrated with minimal
    modifications.
    """

    analysis_result: AnalysisInput = parser.parse(
        TEST_RESOURCES_DIRECTORY / source_file_name
    )

    assert isinstance(analysis_result, AnalysisInput)

    assert analysis_result.programming_language is expected_language
    assert analysis_result.source_file_path.name == source_file_name
    assert analysis_result.source_code != ""

    assert analysis_result.syntax_tree is not None
    assert analysis_result.syntax_tree.root_node is not None


def test_parse_empty_file(parser: Parser) -> None:
    """
    Verify that an empty source file still produces a valid analysis result.

    Tree-sitter always creates a syntax tree, even if the source file
    does not contain any code. This behaviour allows subsequent analysis
    stages to operate on a consistent data structure.
    """

    analysis_result: AnalysisInput = parser.parse(
        TEST_RESOURCES_DIRECTORY / EMPTY_SOURCE_FILE
    )

    assert analysis_result.programming_language is Language.PYTHON
    assert analysis_result.source_code == ""
    assert analysis_result.syntax_tree.root_node is not None


def test_unsupported_file_extension(parser: Parser) -> None:
    """
    Verify that unsupported source file extensions are rejected.

    The parser should only accept languages that are explicitly supported.
    This prevents undefined behaviour and simplifies future language
    extensions by maintaining a central language mapping.
    """

    with pytest.raises(ValueError):
        parser.parse(TEST_RESOURCES_DIRECTORY / UNSUPPORTED_SOURCE_FILE)


def test_missing_file(parser: Parser) -> None:
    """
    Verify that parsing a non-existing source file raises FileNotFoundError.
    """

    with pytest.raises(FileNotFoundError):
        parser.parse(TEST_RESOURCES_DIRECTORY / MISSING_SOURCE_FILE)


def test_invalid_utf8(parser: Parser) -> None:
    """
    Verify that source files with invalid UTF-8 encoding are rejected.

    Tree-sitter expects UTF-8 encoded input, therefore all source
    files must have valid UTF-8 encoding.
    """

    with pytest.raises(ValueError):
        parser.parse(TEST_RESOURCES_DIRECTORY / INVALID_UTF8_SOURCE_FILE)


def test_parse_file_with_syntax_error(parser: Parser) -> None:
    """
    Verify that syntactically invalid source code still produces
    a syntax tree.

    Tree-sitter is fault tolerant and reports syntax errors inside the
    generated syntax tree instead of aborting the parsing process. This
    behaviour enables later analysis stages to inspect incomplete or
    erroneous source code.
    """

    analysis_result: AnalysisInput = parser.parse(
        TEST_RESOURCES_DIRECTORY / SYNTAX_ERROR_SOURCE_FILE
    )

    assert analysis_result.syntax_tree is not None
    assert analysis_result.syntax_tree.root_node.has_error
