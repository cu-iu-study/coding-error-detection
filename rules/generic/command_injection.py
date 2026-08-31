from __future__ import annotations

from scanner.findings import Finding, Severity
from scanner.model import AnalysisContext, StringLiteral
from rules.base import Rule
from rules.constants import COMMAND_EXECUTION_FUNCTIONS, FunctionIdentifier

# Rule metadata constants are defined separately to avoid duplicated literals
# and make future changes easier when additional rules are introduced.
RULE_ID: str = "GEN003"
RULE_NAME: str = "Potential Command Injection"
RULE_DESCRIPTION: str = "User-controlled command execution detected."
RULE_RECOMMENDATION: str = (
    "Avoid passing user input directly to command execution APIs."
)

# Generic message used when creating a security finding.
COMMAND_INJECTION_MESSAGE: str = "Potential command injection detected."


class CommandInjectionRule(Rule):
    """
    Detects potentially unsafe usage of command execution functions.

    This implementation follows a rule-based architecture where each security
    rule analyses information collected by the scanner and returns findings.
    The current implementation focuses on identifying dynamic arguments passed
    to known command execution APIs.

    The design intentionally keeps the rule independent from a specific parser
    or programming language implementation. This allows additional detection
    strategies, such as data-flow analysis, to be integrated in the future.
    """

    id: str = RULE_ID
    name: str = RULE_NAME
    description: str = RULE_DESCRIPTION
    recommendation: str = RULE_RECOMMENDATION
    severity: Severity = Severity.CRITICAL

    def analyse(self, context: AnalysisContext) -> list[Finding]:
        """
        Analyse all function calls from the provided analysis context.

        A finding is created when a known command execution function receives
        an argument that is not a static string literal. Dynamic values may
        originate from user-controlled sources and therefore represent a
        potential command injection risk.

        Args:
            context: Contains the extracted source code information required
                for security analysis.

        Returns:
            A list containing all detected command injection findings.
        """

        findings: list[Finding] = []

        # Inspect every function call identified by the scanner. The rule only
        # evaluates calls that match known command execution APIs.
        for function_call in context.function_calls:

            if not self._is_command_execution_function(function_call):
                continue

            if not function_call.arguments:
                continue

            # Static string literals cannot be influenced by external input and
            # therefore do not represent a command injection risk in this rule.
            if all(
                isinstance(argument, StringLiteral)
                for argument in function_call.arguments
            ):
                continue

            findings.append(
                Finding(
                    vulnerability_rule_id=self.id,
                    vulnerability_rule_name=self.name,
                    description=COMMAND_INJECTION_MESSAGE,
                    recommendation=self.recommendation,
                    severity=self.severity,
                    source_file_path=context.analysis_input.source_file_path,
                    programming_language=context.analysis_input.programming_language,
                    line_number=function_call.line_number,
                    column_number=function_call.column_number,
                )
            )

        return findings

    def _is_command_execution_function(self, function_call: object) -> bool:
        """
        Determine whether a function call belongs to a known command execution
        API.

        The scanner stores functions as a combination of qualifier and function
        name. Both qualified calls (for example module.function) and standalone
        functions are supported to keep the rule compatible with different
        language parsers.

        Args:
            function_call: A detected function call from the analysis context.

        Returns:
            True if the function call matches a configured command execution
            function, otherwise False.
        """

        return (
            FunctionIdentifier(function_call.qualifier, function_call.function_name)
            in COMMAND_EXECUTION_FUNCTIONS
            or FunctionIdentifier(None, function_call.function_name)
            in COMMAND_EXECUTION_FUNCTIONS
        )
