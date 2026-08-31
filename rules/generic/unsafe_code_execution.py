from __future__ import annotations

from scanner.findings import Finding, Severity
from scanner.model import AnalysisContext, FunctionCall, StringLiteral
from rules.base import Rule
from rules.constants import UNSAFE_CODE_EXECUTION_FUNCTIONS, FunctionIdentifier

# Rule metadata constants are defined separately to avoid duplicated literals
# and make future changes easier when additional rules are introduced.
RULE_ID: str = "GEN002"
RULE_NAME: str = "Unsafe Code Execution"
RULE_DESCRIPTION: str = "Dynamic execution of source code detected."
RULE_RECOMMENDATION: str = "Avoid eval/exec-style APIs whenever possible."

# Generic message fragments.
UNSAFE_FUNCTION_DETECTED_MESSAGE_PREFIX: str = "Unsafe function"
UNSAFE_FUNCTION_NAME_SEPARATOR: str = "."


class UnsafeCodeExecutionRule(Rule):
    """
    Detects usage of unsafe dynamic code execution APIs.

    Dynamic execution functions can execute source code that is created during
    runtime. Such functionality may allow attackers to inject and execute
    arbitrary code if external input reaches these APIs.

    The rule currently relies on a configurable list of known unsafe execution
    functions. Keeping this information external allows the rule set to be
    extended for additional programming languages or execution mechanisms
    without modifying the detection logic.
    """

    id: str = RULE_ID
    name: str = RULE_NAME
    description: str = RULE_DESCRIPTION
    recommendation: str = RULE_RECOMMENDATION
    severity: Severity = Severity.HIGH

    def analyse(self, context: AnalysisContext) -> list[Finding]:
        """
        Analyse function calls for unsafe dynamic code execution.

        Every detected function call is compared against the configured list
        of unsafe execution APIs. If a match is found, a security finding is
        generated.

        Unlike command injection detection, this rule does not require
        argument analysis because the execution API itself represents the
        security risk.

        Args:
            context: Contains extracted source code information required for
                security analysis.

        Returns:
            A list containing all detected unsafe code execution findings.
        """

        findings: list[Finding] = []

        # Evaluate all function calls discovered by the scanner. Only calls
        # matching configured unsafe execution functions are reported.
        for function_call in context.function_calls:

            if not self._is_unsafe_execution_function(function_call):
                continue

            findings.append(
                Finding(
                    vulnerability_rule_id=self.id,
                    vulnerability_rule_name=self.name,
                    description=self._create_finding_message(function_call),
                    recommendation=self.recommendation,
                    severity=self.severity,
                    source_file_path=context.analysis_input.source_file_path,
                    programming_language=context.analysis_input.programming_language,
                    line_number=function_call.line_number,
                    column_number=function_call.column_number,
                )
            )

        return findings

    def _is_unsafe_execution_function(self, function_call: object) -> bool:
        """
        Determine whether a function call is a known unsafe execution API.

        Both qualified function calls (for example module.function) and
        standalone function calls are supported. This keeps the rule compatible
        with different parser implementations.

        Args:
            function_call: A function call extracted by the scanner.

        Returns:
            True if the function call matches a configured unsafe execution
            function, otherwise False.
        """

        return (
            FunctionIdentifier(function_call.qualifier, function_call.function_name)
            in UNSAFE_CODE_EXECUTION_FUNCTIONS
            or FunctionIdentifier(None, function_call.function_name)
            in UNSAFE_CODE_EXECUTION_FUNCTIONS
        )

    def _create_finding_message(self, function_call: object) -> str:
        """
        Create a descriptive finding message for a detected function call.

        The generated message contains the complete function name whenever a
        qualifier is available. This improves traceability for developers
        reviewing the security finding.

        Args:
            function_call: A function call extracted by the scanner.

        Returns:
            A human-readable security finding message.
        """

        qualified_function_name: str = (
            f"{function_call.qualifier}{UNSAFE_FUNCTION_NAME_SEPARATOR}"
            f"{function_call.function_name}"
            if function_call.qualifier
            else function_call.function_name
        )

        return (
            f"{UNSAFE_FUNCTION_DETECTED_MESSAGE_PREFIX} "
            f"'{qualified_function_name}' detected."
        )
