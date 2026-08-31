from __future__ import annotations

from scanner.adapters.base import BaseAdapter
from scanner.adapters.java import JavaAdapter
from scanner.adapters.javascript import JavaScriptAdapter
from scanner.adapters.python import PythonAdapter
from scanner.model import AnalysisContext, AnalysisInput, Language


class Adapter:
    """
    Central dispatcher for language-specific source code adapters.

    The scanner architecture is designed to be modular and extensible. Each
    supported programming language provides its own adapter implementation that
    transforms language-specific syntax into a common AnalysisContext. This
    dispatcher selects the appropriate adapter based on the language specified
    in the analysis request.
    """

    def __init__(self) -> None:
        """
        Initialize all available language adapters.

        The adapters are stored in a lookup table to avoid conditional
        statements and to simplify the integration of additional programming
        languages in the future.
        """

        self._adapters: dict[Language, BaseAdapter] = {
            Language.PYTHON: PythonAdapter(),
            Language.JAVA: JavaAdapter(),
            Language.JAVASCRIPT: JavaScriptAdapter(),
        }

    def adapt(self, analysis_input: AnalysisInput) -> AnalysisContext:
        """
        Transform the given source code into a language-independent analysis context.

        Args:
            analysis_input:
                Contains the source code and its associated programming language.

        Returns:
            A normalized AnalysisContext that can be processed by the rule engine.
        """

        return self._adapters[analysis_input.programming_language].adapt(analysis_input)
