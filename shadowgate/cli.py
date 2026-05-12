from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from .server import (
    VERSION,
    create_security_report,
    evaluate_mcp_transaction,
    gate_mcp_response,
    gate_mcp_tool_call,
    get_audit_summary,
    get_data_paths,
    get_mcp_server_trust,
    get_policy,
    get_recent_audit_events,
    get_security_config,
    get_server_registry,
    health_check,
    inspect_mcp_tool_call,
    inspect_tool_schema,
    review_mcp_manifest,
    scan_batch,
    scan_text,
    analyze_text,
    set_mcp_server_trust,
    set_policy_mode,
    redact_secrets,
    get_risk_score,
    decide_policy,
    simulate_policy_modes,
)


def _print_json(data: Any) -> None:
    print(json.dumps(data, indent=2, ensure_ascii=False))


def _read_text_arg(value: str | None, file_path: str | None) -> str:
    if file_path:
        return Path(file_path).read_text(encoding="utf-8")
    if value is None:
        return sys.stdin.read()
    return value


def _admin_key(args: argparse.Namespace) -> str:
    return getattr(args, "admin_key", None) or os.environ.get("SHADOWGATE_ADMIN_KEY", "")


def _client_key(args: argparse.Namespace) -> str:
    return getattr(args, "client_key", None) or os.environ.get("SHADOWGATE_CLIENT_KEY", "")


def cmd_health(_: argparse.Namespace) -> None:
    _print_json(health_check())


def cmd_security_config(_: argparse.Namespace) -> None:
    _print_json(get_security_config())


def cmd_paths(_: argparse.Namespace) -> None:
    _print_json(get_data_paths())


def cmd_policy(_: argparse.Namespace) -> None:
    _print_json(get_policy())


def cmd_set_mode(args: argparse.Namespace) -> None:
    _print_json(set_policy_mode(args.mode, admin_key=_admin_key(args)))


def cmd_registry(args: argparse.Namespace) -> None:
    _print_json(get_server_registry(admin_key=_admin_key(args)))


def cmd_trust(args: argparse.Namespace) -> None:
    _print_json(get_mcp_server_trust(args.server))


def cmd_set_trust(args: argparse.Namespace) -> None:
    _print_json(
        set_mcp_server_trust(
            server_name=args.server,
            trust_level=args.trust_level,
            reason=args.reason or "",
            admin_key=_admin_key(args),
        )
    )



def cmd_analyze(args: argparse.Namespace) -> None:
    text_value = _read_text_arg(args.text, args.file)
    _print_json(analyze_text(text_value, client_key=_client_key(args)))


def cmd_scan(args: argparse.Namespace) -> None:
    text_value = _read_text_arg(args.text, args.file)
    _print_json(scan_text(text_value, client_key=_client_key(args)))


def cmd_redact(args: argparse.Namespace) -> None:
    text_value = _read_text_arg(args.text, args.file)
    _print_json(redact_secrets(text_value, client_key=_client_key(args)))


def cmd_score(args: argparse.Namespace) -> None:
    text_value = _read_text_arg(args.text, args.file)
    _print_json(get_risk_score(text_value, client_key=_client_key(args)))


def cmd_decide(args: argparse.Namespace) -> None:
    text_value = _read_text_arg(args.text, args.file)
    _print_json(decide_policy(text_value, strict=args.strict, client_key=_client_key(args)))


def cmd_simulate(args: argparse.Namespace) -> None:
    text_value = _read_text_arg(args.text, args.file)
    _print_json(simulate_policy_modes(text_value, client_key=_client_key(args)))

def cmd_gate_call(args: argparse.Namespace) -> None:
    _print_json(
        gate_mcp_tool_call(
            server_name=args.server,
            tool_name=args.tool,
            arguments_json=args.args_json,
            client_key=_client_key(args),
        )
    )

def cmd_gate_response(args: argparse.Namespace) -> None:
    response_text = _read_text_arg(args.text, args.file)
    _print_json(
        gate_mcp_response(
            server_name=args.server,
            tool_name=args.tool,
            response_text=response_text,
            client_key=_client_key(args),
        )
    )

def cmd_transaction(args: argparse.Namespace) -> None:
    response_text = _read_text_arg(args.response_text, args.response_file)
    _print_json(
        evaluate_mcp_transaction(
            server_name=args.server,
            tool_name=args.tool,
            arguments_json=args.args_json,
            response_text=response_text,
            client_key=_client_key(args),
        )
    )

def cmd_inspect_call(args: argparse.Namespace) -> None:
    _print_json(
        inspect_mcp_tool_call(
            server_name=args.server,
            tool_name=args.tool,
            arguments_json=args.args_json,
            client_key=_client_key(args),
        )
    )

def cmd_schema(args: argparse.Namespace) -> None:
    schema_json = _read_text_arg(args.schema_json, args.file)
    _print_json(
        inspect_tool_schema(
            server_name=args.server,
            tool_name=args.tool,
            schema_json=schema_json,
            client_key=_client_key(args),
        )
    )

def cmd_manifest(args: argparse.Namespace) -> None:
    manifest_json = _read_text_arg(args.manifest_json, args.file)
    _print_json(
        review_mcp_manifest(
            server_name=args.server,
            manifest_json=manifest_json,
            client_key=_client_key(args),
        )
    )

def cmd_batch(args: argparse.Namespace) -> None:
    if args.file:
        items = [
            line.strip()
            for line in Path(args.file).read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    else:
        items = args.items or []

    _print_json(scan_batch(items, client_key=_client_key(args)))

def cmd_audit_summary(args: argparse.Namespace) -> None:
    _print_json(get_audit_summary(admin_key=_admin_key(args)))


def cmd_audit_recent(args: argparse.Namespace) -> None:
    _print_json(get_recent_audit_events(limit=args.limit, admin_key=_admin_key(args)))


def cmd_report(args: argparse.Namespace) -> None:
    report = create_security_report(limit=args.limit, admin_key=_admin_key(args))

    if args.markdown:
        print(report.get("markdown", ""))
    else:
        _print_json(report)



def _add_client_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--client-key", default="")


def _add_admin_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--admin-key", default="")

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="shadowgate",
        description="ShadowGate MCP security scanner, policy engine, server registry, and gateway CLI.",
    )

    parser.add_argument("--version", action="store_true", help="Print ShadowGate version and exit.")

    sub = parser.add_subparsers(dest="command")

    p = sub.add_parser("health", help="Show health, version, tools, and active policy.")
    p.set_defaults(func=cmd_health)

    p = sub.add_parser("security-config", help="Show admin-auth security config.")
    p.set_defaults(func=cmd_security_config)

    p = sub.add_parser("paths", help="Show ShadowGate data directory paths.")
    p.set_defaults(func=cmd_paths)

    p = sub.add_parser("policy", help="Show active policy.")
    p.set_defaults(func=cmd_policy)

    p = sub.add_parser("set-mode", help="Set policy mode: monitor, balanced, or strict.")
    p.add_argument("mode", choices=["monitor", "balanced", "strict"])
    p.add_argument("--admin-key", default="")
    p.set_defaults(func=cmd_set_mode)

    p = sub.add_parser("registry", help="Show MCP server trust registry.")
    p.add_argument("--admin-key", default="")
    p.set_defaults(func=cmd_registry)

    p = sub.add_parser("trust", help="Show trust level for an MCP server.")
    p.add_argument("server")
    p.set_defaults(func=cmd_trust)

    p = sub.add_parser("set-trust", help="Set trust level for an MCP server.")
    p.add_argument("server")
    p.add_argument("trust_level", choices=["trusted", "untrusted", "monitor", "blocked"])
    p.add_argument("--reason", default="")
    p.add_argument("--admin-key", default="")
    p.set_defaults(func=cmd_set_trust)


    p = sub.add_parser("analyze", help="Professional merged text safety analysis.")
    p.add_argument("text", nargs="?")
    p.add_argument("--file")
    _add_client_arg(p)
    p.set_defaults(func=cmd_analyze)

    p = sub.add_parser("scan", help="Scan text or file.")
    p.add_argument("text", nargs="?", help="Text to scan. If omitted, stdin is used.")
    p.add_argument("--file", help="Read text from file.")
    _add_client_arg(p)
    p.set_defaults(func=cmd_scan)


    p = sub.add_parser("redact", help="Redact secrets from text or file.")
    p.add_argument("text", nargs="?")
    p.add_argument("--file")
    _add_client_arg(p)
    p.set_defaults(func=cmd_redact)

    p = sub.add_parser("score", help="Get risk score for text or file.")
    p.add_argument("text", nargs="?")
    p.add_argument("--file")
    _add_client_arg(p)
    p.set_defaults(func=cmd_score)

    p = sub.add_parser("decide", help="Run policy decision for text or file.")
    p.add_argument("text", nargs="?")
    p.add_argument("--file")
    p.add_argument("--strict", action="store_true", default=True)
    _add_client_arg(p)
    p.set_defaults(func=cmd_decide)

    p = sub.add_parser("simulate", help="Simulate policy modes for text or file.")
    p.add_argument("text", nargs="?")
    p.add_argument("--file")
    _add_client_arg(p)
    p.set_defaults(func=cmd_simulate)

    p = sub.add_parser("gate-call", help="Gateway-check an outgoing MCP tool call.")
    p.add_argument("--server", required=True)
    p.add_argument("--tool", required=True)
    p.add_argument("--args-json", required=True)
    _add_client_arg(p)
    p.set_defaults(func=cmd_gate_call)

    p = sub.add_parser("gate-response", help="Gateway-check an MCP response before delivery.")
    p.add_argument("--server", required=True)
    p.add_argument("--tool", required=True)
    p.add_argument("text", nargs="?", help="Response text. If omitted, stdin is used.")
    p.add_argument("--file", help="Read response text from file.")
    _add_client_arg(p)
    p.set_defaults(func=cmd_gate_response)

    p = sub.add_parser("transaction", help="Evaluate full MCP tool call + response transaction.")
    p.add_argument("--server", required=True)
    p.add_argument("--tool", required=True)
    p.add_argument("--args-json", required=True)
    p.add_argument("--response-text")
    p.add_argument("--response-file")
    _add_client_arg(p)
    p.set_defaults(func=cmd_transaction)

    p = sub.add_parser("inspect-call", help="Inspect outgoing MCP tool call without gateway wrapper.")
    p.add_argument("--server", required=True)
    p.add_argument("--tool", required=True)
    p.add_argument("--args-json", required=True)
    _add_client_arg(p)
    p.set_defaults(func=cmd_inspect_call)

    p = sub.add_parser("schema", help="Inspect MCP tool schema or description.")
    p.add_argument("--server", required=True)
    p.add_argument("--tool", required=True)
    p.add_argument("schema_json", nargs="?")
    p.add_argument("--file")
    _add_client_arg(p)
    p.set_defaults(func=cmd_schema)

    p = sub.add_parser("manifest", help="Review simplified MCP server manifest.")
    p.add_argument("--server", required=True)
    p.add_argument("manifest_json", nargs="?")
    p.add_argument("--file")
    _add_client_arg(p)
    p.set_defaults(func=cmd_manifest)

    p = sub.add_parser("batch", help="Scan multiple items.")
    p.add_argument("items", nargs="*")
    p.add_argument("--file")
    _add_client_arg(p)
    p.set_defaults(func=cmd_batch)

    p = sub.add_parser("audit-summary", help="Show audit summary.")
    p.add_argument("--admin-key", default="")
    p.set_defaults(func=cmd_audit_summary)

    p = sub.add_parser("audit-recent", help="Show recent audit events.")
    p.add_argument("--limit", type=int, default=10)
    p.add_argument("--admin-key", default="")
    p.set_defaults(func=cmd_audit_recent)

    p = sub.add_parser("report", help="Create security report.")
    p.add_argument("--limit", type=int, default=50)
    p.add_argument("--markdown", action="store_true")
    p.add_argument("--admin-key", default="")
    p.set_defaults(func=cmd_report)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.version:
        print(VERSION)
        return

    if not hasattr(args, "func"):
        parser.print_help()
        return

    args.func(args)


if __name__ == "__main__":
    main()
