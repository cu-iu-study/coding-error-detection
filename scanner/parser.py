from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import tree_sitter_java
import tree_sitter_javascript
import tree_sitter_python
from tree_sitter import Language as TSLanguage
from tree_sitter import Parser as TSParser

from .model import AnalysisInput, Language

# ============================================================================
# Constants
# ============================================================================

# Encoding used for reading source files. Tree-sitter expects UTF-8 encoded
# input, therefore all source files must be decoded using the same encoding.
_SOURCE_FILE_ENCODING: str = "utf-8"

# Text fragments used when constructing formatted error messages.
_LINE_SEPARATOR: str = "\n"
_SUPPORTED_LANGUAGE_INDENT: str = "  • "


class Parser:
    """
    Parse a source code file into a Tree-sitter syntax tree.

    This class is responsible for transforming a source file into
    an AnalysisInput object. The resulting object contains the original
    source code together with its parsed Tree-sitter syntax tree and serves as
    the input for the subsequent analysis pipeline.

    The implementation is intentionally modular and easily extensible.
    Supporting an additional programming language only requires:

    1. Extending the Language enumeration.
    2. Registering the corresponding Tree-sitter language factory below.

    No changes to the parsing workflow itself are required.
    """

    # Registry of Tree-sitter language factories. Each factory creates the
    # underlying language definition that is required by a Tree-sitter parser.
    _LANGUAGE_FACTORIES: dict[Language, Callable[[], TSLanguage]] = {
        Language.PYTHON: tree_sitter_python.language,
        Language.JAVA: tree_sitter_java.language,
        Language.JAVASCRIPT: tree_sitter_javascript.language,
    }

    # Automatically derive the mapping between file extensions and the internal
    # language enumeration to avoid maintaining duplicate configuration.
    _FILE_EXTENSION_TO_LANGUAGE: dict[str, Language] = {
        language.file_extension: language for language in Language
    }

    def __init__(self) -> None:
        """
        Initialize the parser cache.

        Tree-sitter parser instances can safely be reused for multiple source
        files of the same programming language. Therefore, parser instances are
        created lazily and cached after their first use.
        """
        self._cached_parsers: dict[Language, TSParser] = {}

    def parse(self, path: str | Path) -> AnalysisInput:
        """
        Parse a source file into an AnalysisInput object.

        Args:
            path:
                Path to the source file.

        Returns:
            AnalysisInput containing the source code and its syntax tree.

        Raises:
            FileNotFoundError:
                If the specified file does not exist.

            ValueError:
                If the file extension is unsupported or the file is not encoded
                as valid UTF-8.
        """
        source_file_path: Path = Path(path).resolve()

        if not source_file_path.is_file():
            raise FileNotFoundError(f"File not found: {source_file_path}")

        detected_language: Language = self._detect_language(source_file_path)

        source_code_bytes: bytes
        source_code: str
        source_code_bytes, source_code = self._read_source_file(source_file_path)

        tree_sitter_parser: TSParser = self._get_parser(detected_language)
        syntax_tree = tree_sitter_parser.parse(source_code_bytes)

        return AnalysisInput(
            source_file_path=source_file_path,
            programming_language=detected_language,
            source_code=source_code,
            source_code_bytes=source_code_bytes,
            syntax_tree=syntax_tree,
        )

    def _read_source_file(self, source_file_path: Path) -> tuple[bytes, str]:
        """
        Read and validate a source file.

        The file is returned both as UTF-8 encoded bytes and as a decoded
        string because both representations are required during the analysis
        process. Tree-sitter parses bytes directly, while later analysis stages
        frequently operate on the decoded source code.

        Args:
            source_file_path:
                Path to the source file.

        Returns:
            Tuple containing the source bytes and decoded source code.

        Raises:
            ValueError:
                If the source file is not encoded as valid UTF-8.
        """
        try:
            source_code_bytes: bytes = source_file_path.read_bytes()
            source_code: str = source_code_bytes.decode(_SOURCE_FILE_ENCODING)
        except UnicodeDecodeError as exception:
            raise ValueError(
                f"File is not valid {_SOURCE_FILE_ENCODING}: " f"{source_file_path}"
            ) from exception

        return source_code_bytes, source_code

    def _get_parser(self, language: Language) -> TSParser:
        """
        Return a cached Tree-sitter parser for the specified language.

        Parser instances are created only once per programming language to
        avoid repeatedly initializing the same Tree-sitter grammar.

        Args:
            language:
                Programming language for which a parser is required.

        Returns:
            Cached or newly created Tree-sitter parser.
        """
        if language not in self._cached_parsers:
            tree_sitter_parser: TSParser = TSParser()
            tree_sitter_parser.language = self._create_language(language)

            self._cached_parsers[language] = tree_sitter_parser

        return self._cached_parsers[language]

    @classmethod
    def _create_language(cls, language: Language) -> TSLanguage:
        """
        Create the Tree-sitter language object for a programming language.

        Args:
            language:
                Programming language to initialize.

        Returns:
            Tree-sitter language object.
        """
        return TSLanguage(cls._LANGUAGE_FACTORIES[language]())

    @classmethod
    def _detect_language(cls, source_file_path: Path) -> Language:
        """
        Determine the programming language based on the file extension.

        Args:
            source_file_path:
                Path to the source file.

        Returns:
            Detected programming language.

        Raises:
            ValueError:
                If the file extension is not supported.
        """
        try:
            return cls._FILE_EXTENSION_TO_LANGUAGE[source_file_path.suffix.lower()]
        except KeyError as exception:
            supported_languages: str = _LINE_SEPARATOR.join(
                (
                    f"{_SUPPORTED_LANGUAGE_INDENT}"
                    f"{language.value:<10} ({language.file_extension})"
                )
                for language in Language
            )

            raise ValueError(
                f"Unsupported file extension "
                f"'{source_file_path.suffix}'."
                f"{_LINE_SEPARATOR}{_LINE_SEPARATOR}"
                f"Supported languages:"
                f"{_LINE_SEPARATOR}"
                f"{supported_languages}"
            ) from exception
