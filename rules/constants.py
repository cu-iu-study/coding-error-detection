from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class FunctionIdentifier:
    """
    Identifies a function or method that requires security analysis.

    The qualifier represents the optional module, class, or object name.
    The function name identifies the called operation.

    Example:
        os.system

    is represented as:

        qualifier="os"
        function_name="system"

    This abstraction keeps vulnerability rules independent from
    programming language specific syntax.
    """

    qualifier: str | None
    function_name: str


# Minimum length before a string value is considered relevant
# for potential hardcoded secret detection.
MINIMUM_SECRET_LENGTH: int = 6


# Variable names commonly associated with credentials.
# These identifiers are used as indicators during source code analysis.
CREDENTIAL_VARIABLE_NAMES: frozenset[str] = frozenset(
    {
        "password",
        "passwd",
        "pwd",
        "passphrase",
        "secret",
        "client_secret",
        "clientsecret",
        "app_secret",
        "application_secret",
        "shared_secret",
        "token",
        "access_token",
        "refresh_token",
        "id_token",
        "auth_token",
        "session_token",
        "oauth_token",
        "jwt",
        "bearer",
        "api_key",
        "apikey",
        "api_secret",
        "access_key",
        "secret_key",
        "consumer_key",
        "consumer_secret",
        "aws_access_key",
        "aws_secret_key",
        "aws_secret_access_key",
        "aws_session_token",
        "azure_key",
        "gcp_key",
        "private_key",
        "privatekey",
        "public_key",
        "ssh_key",
        "ssh_private_key",
        "pem",
        "keystore",
        "truststore",
        "db_password",
        "db_pass",
        "db_user",
        "db_username",
        "connection_string",
        "db_connection_string",
        "jdbc_url",
        "credential",
        "credentials",
        "username",
        "user",
        "login",
        "key",
        "master_key",
        "encryption_key",
        "signing_key",
        "license_key",
    }
)


# APIs that allow dynamic code execution.
# These functions require special handling because executing
# dynamically generated code can introduce security vulnerabilities.
UNSAFE_CODE_EXECUTION_FUNCTIONS: frozenset[FunctionIdentifier] = frozenset(
    {
        FunctionIdentifier("builtins", "eval"),
        FunctionIdentifier("builtins", "exec"),
        FunctionIdentifier("builtins", "compile"),
        FunctionIdentifier("ScriptEngine", "eval"),
        FunctionIdentifier("ScriptEngine", "compile"),
        FunctionIdentifier("CompiledScript", "eval"),
        FunctionIdentifier("global", "eval"),
        FunctionIdentifier("window", "eval"),
        FunctionIdentifier("vm", "runInThisContext"),
        FunctionIdentifier("vm", "runInContext"),
        FunctionIdentifier("vm", "runInNewContext"),
        FunctionIdentifier("vm", "compileFunction"),
        FunctionIdentifier(None, "eval"),
        FunctionIdentifier(None, "compile"),
        FunctionIdentifier(None, "Function"),
        FunctionIdentifier(None, "runInThisContext"),
        FunctionIdentifier(None, "runInContext"),
        FunctionIdentifier(None, "runInNewContext"),
        FunctionIdentifier(None, "compileFunction"),
    }
)


# APIs that can execute operating system commands.
# The list contains language-specific implementations and
# language-independent fallback identifiers.
COMMAND_EXECUTION_FUNCTIONS: frozenset[FunctionIdentifier] = frozenset(
    {
        FunctionIdentifier("os", "system"),
        FunctionIdentifier("os", "popen"),
        FunctionIdentifier("subprocess", "run"),
        FunctionIdentifier("subprocess", "Popen"),
        FunctionIdentifier("Runtime", "exec"),
        FunctionIdentifier("Runtime", "getRuntime"),
        FunctionIdentifier("ProcessBuilder", "start"),
        FunctionIdentifier("child_process", "exec"),
        FunctionIdentifier("child_process", "execSync"),
        FunctionIdentifier("child_process", "spawn"),
        FunctionIdentifier("node:child_process", "exec"),
        FunctionIdentifier("node:child_process", "spawn"),
        FunctionIdentifier(None, "exec"),
        FunctionIdentifier(None, "execSync"),
        FunctionIdentifier(None, "spawn"),
        FunctionIdentifier(None, "Popen"),
    }
)
