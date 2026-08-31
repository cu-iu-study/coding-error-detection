from __future__ import annotations

from scanner.findings import Finding, Severity
from scanner.model import AnalysisContext, StringLiteral
from rules.base import Rule
from rules.constants import CREDENTIAL_VARIABLE_NAMES, MINIMUM_SECRET_LENGTH

# Rule metadata constants are defined separately to avoid duplicated literals
# and make future changes easier when additional rules are introduced.
RULE_ID: str = "GEN001"
RULE_NAME: str = "Hardcoded Credentials"
RULE_DESCRIPTION: str = "Credentials should not be hardcoded in source code."
RULE_RECOMMENDATION: str = (
    "Store secrets in environment variables or a secrets manager."
)

# Generic message used when creating a security finding.
HARDCODED_CREDENTIAL_MESSAGE: str = "Possible hardcoded credential detected."


class HardcodedCredentialsRule(Rule):
    """
    Detects potentially hardcoded credentials in source code.

    The rule analyses variable assignments and identifies variables whose names
    indicate that they may contain sensitive information, such as passwords,
    tokens, or API keys.

    The current implementation intentionally uses a name-based heuristic because
    the scanner architecture is designed to support multiple independent rules.
    More advanced detection methods, such as value analysis or data-flow
    tracking, can be added later without changing the rule interface.
    """

    id: str = RULE_ID
    name: str = RULE_NAME
    description: str = RULE_DESCRIPTION
    recommendation: str = RULE_RECOMMENDATION
    severity: Severity = Severity.HIGH

    def analyse(self, context: AnalysisContext) -> list[Finding]:
        """
        Analyse assignments to detect possible hardcoded credentials.

        An assignment is reported when:
        1. The variable name indicates that it may contain a credential.
        2. The assigned value is a static string literal.
        3. The string length exceeds the configured minimum secret length.

        Static string detection is used because credentials embedded directly
        in source code are difficult to rotate and may be exposed through
        version control systems.

        Args:
            context: Contains extracted source code information required for
                security analysis.

        Returns:
            A list containing all detected hardcoded credential findings.
        """

        findings: list[Finding] = []

        # Iterate over all assignments collected by the scanner. Each assignment
        # is evaluated independently to determine whether it represents a
        # possible embedded secret.
        for assignment in context.assignments:

            assigned_value = assignment.assigned_value

            # Only static string values can be reliably classified by this
            # heuristic. Dynamic values require data-flow analysis.
            if not isinstance(assigned_value, StringLiteral):
                continue

            variable_name: str = assignment.assigned_variable.variable_name

            if not self._looks_like_secret(variable_name):
                continue

            secret_value: str = assigned_value.value

            if len(secret_value) < MINIMUM_SECRET_LENGTH:
                continue

            findings.append(
                Finding(
                    vulnerability_rule_id=self.id,
                    vulnerability_rule_name=self.name,
                    description=HARDCODED_CREDENTIAL_MESSAGE,
                    recommendation=self.recommendation,
                    severity=self.severity,
                    source_file_path=context.analysis_input.source_file_path,
                    programming_language=context.analysis_input.programming_language,
                    line_number=assignment.line_number,
                    column_number=assignment.column_number,
                )
            )

        return findings

    @staticmethod
    def _looks_like_secret(variable_name: str) -> bool:
        """
        Check whether a variable name indicates possible credential storage.

        The method performs a simple keyword-based comparison. The list of
        keywords is provided externally through CREDENTIAL_VARIABLES so that
        the detection strategy can be extended without modifying this rule.

        Args:
            variable_name: Name of the assigned variable.

        Returns:
            True if the variable name contains a known credential keyword,
            otherwise False.
        """

        normalized_variable_name: str = variable_name.lower()

        return any(
            credential_keyword in normalized_variable_name
            for credential_keyword in CREDENTIAL_VARIABLE_NAMES
        )
