from __future__ import annotations

from scanner.findings import Finding
from scanner.model import AnalysisContext
from rules.base import Rule
from rules.generic.command_injection import CommandInjectionRule
from rules.generic.hardcoded_credentials import HardcodedCredentialsRule
from rules.generic.unsafe_code_execution import UnsafeCodeExecutionRule


class RuleEngine:
    """
    Coordinates the execution of all registered security analysis rules.

    The RuleEngine acts as an extension point for the scanner architecture.
    New analysis rules can be added without modifying the execution workflow.
    This keeps the scanner modular and allows future rules to be integrated
    through the common Rule interface.
    """

    def __init__(self) -> None:
        """
        Initialize the RuleEngine with all default security rules.

        The default rules represent the currently supported security checks.
        Additional rules can be registered dynamically through the public
        register_rule method.
        """

        self._registered_rules: list[Rule] = [
            HardcodedCredentialsRule(),
            UnsafeCodeExecutionRule(),
            CommandInjectionRule(),
        ]

    @property
    def registered_rules(self) -> tuple[Rule, ...]:
        """
        Return all currently registered analysis rules.
        """

        return tuple(self._registered_rules)

    def register_rule(self, analysis_rule: Rule) -> None:
        """
        Register a new analysis rule.

        This method provides the extension mechanism of the scanner. External
        components can add additional security checks without changing the
        RuleEngine implementation.

        Raises:
            ValueError: If the analysis rule is already registered.
        """

        if analysis_rule in self._registered_rules:
            raise ValueError("The analysis rule is already registered.")

        self._registered_rules.append(analysis_rule)

    def unregister_rule(self, analysis_rule: Rule) -> None:
        """
        Remove an existing analysis rule.

        The caller must provide the same rule instance that was previously
        registered. This prevents accidentally removing a different rule with
        similar behaviour.
        """

        self._registered_rules.remove(analysis_rule)

    def analyse(self, analysis_context: AnalysisContext) -> list[Finding]:
        """
        Execute all registered rules against the provided analysis context.

        Each rule analyses the same context independently and returns its own
        findings. The RuleEngine combines all results and sorts them to provide
        deterministic output for further processing or reporting.
        """

        all_findings: list[Finding] = []

        for analysis_rule in self._registered_rules:
            rule_findings: list[Finding] = analysis_rule.analyse(analysis_context)

            all_findings.extend(rule_findings)

        all_findings.sort(
            key=lambda finding: (
                finding.source_file_path,
                finding.line_number,
                finding.column_number,
            )
        )

        return all_findings
