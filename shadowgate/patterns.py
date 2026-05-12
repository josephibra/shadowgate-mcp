from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Pattern


@dataclass(frozen=True)
class Rule:
    id: str
    label: str
    severity: str  # low | medium | high | critical
    category: str  # secret | command | injection | file_access | network
    pattern: Pattern[str]
    weight: int
    redact: bool = True


FLAGS = re.IGNORECASE | re.MULTILINE | re.DOTALL
LINE_FLAGS = re.IGNORECASE | re.MULTILINE

SECRET_RULES: list[Rule] = [
    Rule(
        "private_key_block",
        "Private key block detected",
        "critical",
        "secret",
        re.compile(r"-----BEGIN (?:OPENSSH|RSA|DSA|EC|PGP|PRIVATE) PRIVATE KEY-----.*?-----END (?:OPENSSH|RSA|DSA|EC|PGP|PRIVATE) PRIVATE KEY-----", FLAGS),
        100,
    ),
    Rule(
        "aws_access_key_id",
        "AWS access key ID detected",
        "critical",
        "secret",
        re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
        90,
    ),
    Rule(
        "openai_api_key",
        "OpenAI-style API key detected",
        "critical",
        "secret",
        re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
        90,
    ),
    Rule(
        "anthropic_api_key",
        "Anthropic-style API key detected",
        "critical",
        "secret",
        re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"),
        90,
    ),
    Rule(
        "github_token",
        "GitHub token detected",
        "critical",
        "secret",
        re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{30,}\b|\bgithub_pat_[A-Za-z0-9_]{40,}\b"),
        90,
    ),
    Rule(
        "stripe_secret_key",
        "Stripe secret key detected",
        "critical",
        "secret",
        re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{20,}\b"),
        90,
    ),
    Rule(
        "slack_token",
        "Slack token detected",
        "critical",
        "secret",
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
        85,
    ),
    Rule(
        "google_api_key",
        "Google API key detected",
        "high",
        "secret",
        re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
        80,
    ),
    Rule(
        "env_secret_assignment",
        "Environment secret assignment detected",
        "high",
        "secret",
        re.compile(r"(?im)^\s*(?:[A-Z0-9_]*?(?:API[_-]?KEY|SECRET|TOKEN|PASSWORD|PRIVATE[_-]?KEY)[A-Z0-9_]*?)\s*=\s*['\"]?[^'\"\s]{8,}['\"]?\s*$"),
        75,
    ),
]

COMMAND_RULES: list[Rule] = [
    Rule(
        "curl_pipe_shell",
        "Network download piped into shell",
        "critical",
        "command",
        re.compile(r"\b(?:curl|wget)\b[^\n|;]*(?:\||>)\s*(?:sudo\s+)?(?:sh|bash|zsh|python|python3|node)\b", LINE_FLAGS),
        95,
        redact=False,
    ),
    Rule(
        "destructive_rm_rf",
        "Destructive recursive deletion command",
        "critical",
        "command",
        re.compile(r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\s+(?:/|~|\$HOME|\.\.)", LINE_FLAGS),
        95,
        redact=False,
    ),
    Rule(
        "powershell_download_exec",
        "PowerShell download/execute pattern",
        "critical",
        "command",
        re.compile(r"\b(?:iex|Invoke-Expression)\b|\b(?:Invoke-WebRequest|iwr|wget|curl)\b.*\b(?:iex|Invoke-Expression)\b|powershell(?:\.exe)?\s+.*-enc\b", LINE_FLAGS),
        90,
        redact=False,
    ),
    Rule(
        "chmod_exec_then_run",
        "Downloaded file made executable and run",
        "high",
        "command",
        re.compile(r"\bchmod\s+\+x\b.*(?:&&|;).*\./", LINE_FLAGS),
        75,
        redact=False,
    ),
    Rule(
        "suspicious_sudo",
        "Potentially privileged command",
        "medium",
        "command",
        re.compile(r"\bsudo\b", LINE_FLAGS),
        35,
        redact=False,
    ),
]

FILE_ACCESS_RULES: list[Rule] = [
    Rule(
        "ssh_private_path",
        "SSH private key path mentioned",
        "critical",
        "file_access",
        re.compile(r"(?:~|\$HOME|/home/[^\s]+|/Users/[^\s]+)?/\.ssh/(?:id_rsa|id_ed25519|id_ecdsa|config)\b|\\.ssh\\(?:id_rsa|id_ed25519|id_ecdsa|config)\b", LINE_FLAGS),
        90,
        redact=True,
    ),
    Rule(
        "env_file_path",
        ".env or secret file path mentioned",
        "high",
        "file_access",
        re.compile(r"(?<![\w.-])\.env\b|secrets?\.json|credentials\.json", LINE_FLAGS),
        70,
        redact=True,
    ),
    Rule(
        "browser_cookie_path",
        "Browser cookie/session storage path mentioned",
        "critical",
        "file_access",
        re.compile(r"(?:Cookies|Login Data|Local State|Session Storage|key4\.db|cookies\.sqlite)", LINE_FLAGS),
        85,
        redact=False,
    ),
]

INJECTION_RULES: list[Rule] = [
    Rule(
        "ignore_instructions",
        "Instruction override phrase detected",
        "high",
        "injection",
        re.compile(r"\bignore\s+(?:all\s+)?(?:previous|prior|above|system|developer)\s+instructions\b", LINE_FLAGS),
        75,
        redact=False,
    ),
    Rule(
        "system_prompt_extraction",
        "System/developer prompt extraction attempt",
        "high",
        "injection",
        re.compile(r"\b(?:reveal|print|show|dump|exfiltrate)\b.{0,80}\b(?:system prompt|developer message|hidden instructions|tool instructions)\b", FLAGS),
        75,
        redact=False,
    ),
    Rule(
        "silent_tool_call",
        "Instruction to call tools silently or hide action",
        "high",
        "injection",
        re.compile(r"\b(?:silently|without telling|do not tell|hide this|secretly)\b.{0,80}\b(?:call|invoke|use)\b.{0,80}\btool\b", FLAGS),
        70,
        redact=False,
    ),
    Rule(
        "credential_harvest_instruction",
        "Credential harvesting instruction",
        "critical",
        "injection",
        re.compile(r"\b(?:send|upload|post|exfiltrate|copy)\b.{0,100}\b(?:token|api key|password|secret|private key|ssh key|cookie)\b", FLAGS),
        90,
        redact=False,
    ),
    Rule(
        "env_exfil_instruction",
        "Instruction to exfiltrate environment or credential files",
        "critical",
        "injection",
        re.compile(r"\b(?:send|upload|post|exfiltrate|copy)\b.{0,120}\b(?:contents?|data|file)\b.{0,80}\b(?:\.env|secrets?\.json|credentials\.json)\b.{0,120}\b(?:to|into|via|over|using)\b", FLAGS),
        90,
        redact=False,
    ),
]

NETWORK_RULES: list[Rule] = [
    Rule(
        "cloud_metadata_endpoint",
        "Cloud metadata endpoint mentioned",
        "critical",
        "network",
        re.compile(r"\b(?:169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200)\b", LINE_FLAGS),
        90,
        redact=False,
    ),
    Rule(
        "localhost_private_ip",
        "Private/local network target mentioned",
        "medium",
        "network",
        re.compile(r"\b(?:localhost|127\.0\.0\.1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b", LINE_FLAGS),
        45,
        redact=False,
    ),
]

ALL_RULES: list[Rule] = SECRET_RULES + COMMAND_RULES + FILE_ACCESS_RULES + INJECTION_RULES + NETWORK_RULES
