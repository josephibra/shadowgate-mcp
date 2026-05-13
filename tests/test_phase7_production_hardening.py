import json

from shadowgate.auth import get_security_config
from shadowgate.server import create_security_report, gate_mcp_tool_call, health_check


def _clear_hardening_env(monkeypatch):
    for key in [
        "SHADOWGATE_HOST",
        "HOST",
        "PORT",
        "RAILWAY_ENVIRONMENT",
        "RAILWAY_PROJECT_ID",
        "FLY_APP_NAME",
        "RENDER",
        "RENDER_SERVICE_ID",
        "SHADOWGATE_ADMIN_KEY",
        "SHADOWGATE_CLIENT_KEY",
        "SHADOWGATE_DATA_DIR",
        "SHADOWGATE_AUDIT_MAX_EVENTS",
        "SHADOWGATE_AUDIT_RETENTION_DAYS",
        "SHADOWGATE_RATE_LIMIT_PER_MINUTE",
        "SHADOWGATE_RATE_LIMIT_BURST",
    ]:
        monkeypatch.delenv(key, raising=False)


def _warning_codes(config: dict) -> set[str]:
    return {item["code"] for item in config.get("production_warnings", [])}


def test_security_config_does_not_expose_raw_keys(monkeypatch):
    _clear_hardening_env(monkeypatch)
    monkeypatch.setenv("SHADOWGATE_ADMIN_KEY", "strong-admin-key-for-test")
    monkeypatch.setenv("SHADOWGATE_CLIENT_KEY", "strong-client-key-for-test")

    config = get_security_config()
    rendered = json.dumps(config, sort_keys=True)

    assert config["admin_auth_enabled"] is True
    assert config["client_auth_enabled"] is True
    assert "strong-admin-key-for-test" not in rendered
    assert "strong-client-key-for-test" not in rendered
    assert config["admin_key_fingerprint"]
    assert config["client_key_fingerprint"]


def test_weak_placeholder_keys_produce_warnings(monkeypatch):
    _clear_hardening_env(monkeypatch)
    monkeypatch.setenv("SHADOWGATE_ADMIN_KEY", "change-me-admin-key")
    monkeypatch.setenv("SHADOWGATE_CLIENT_KEY", "password")

    config = get_security_config()
    codes = _warning_codes(config)

    assert config["admin_key_weak"] is True
    assert config["client_key_weak"] is True
    assert "weak_admin_key" in codes
    assert "weak_client_key" in codes


def test_hosted_mode_without_keys_produces_warnings(monkeypatch):
    _clear_hardening_env(monkeypatch)
    monkeypatch.setenv("SHADOWGATE_HOST", "0.0.0.0")
    monkeypatch.setenv("PORT", "8000")

    config = get_security_config()
    codes = _warning_codes(config)

    assert config["hosted_mode"] is True
    assert "hosted_admin_key_missing" in codes
    assert "hosted_client_key_missing" in codes
    assert "hosted_data_dir_not_persistent" in codes
    assert "audit_max_events_unset" in codes
    assert "audit_retention_days_unset" in codes
    assert "rate_limit_per_minute_unset" in codes
    assert "rate_limit_burst_unset" in codes


def test_local_dev_mode_still_works(monkeypatch):
    _clear_hardening_env(monkeypatch)

    config = get_security_config()
    result = gate_mcp_tool_call(
        server_name="unknown",
        tool_name="run_command",
        arguments_json='{"command":"echo hello"}',
    )

    assert config["dev_mode"] is True
    assert config["hosted_mode"] is False
    assert config["production_warning_count"] == 0
    assert result["allow_execution"] is True
    assert result["gateway_action"] == "allow_with_warning"


def test_health_check_includes_security_warnings_and_config(monkeypatch):
    _clear_hardening_env(monkeypatch)
    monkeypatch.setenv("SHADOWGATE_HOST", "0.0.0.0")

    health = health_check()
    security = health["security_config"]

    assert health["ok"] is True
    assert security["hosted_mode"] is True
    assert "production_warnings" in security
    assert "hosted_admin_key_missing" in _warning_codes(security)


def test_audit_and_rate_limit_config_are_parsed(monkeypatch):
    _clear_hardening_env(monkeypatch)
    monkeypatch.setenv("SHADOWGATE_AUDIT_MAX_EVENTS", "5000")
    monkeypatch.setenv("SHADOWGATE_AUDIT_RETENTION_DAYS", "14")
    monkeypatch.setenv("SHADOWGATE_RATE_LIMIT_PER_MINUTE", "60")
    monkeypatch.setenv("SHADOWGATE_RATE_LIMIT_BURST", "10")

    config = get_security_config()

    assert config["audit_retention"]["max_events"]["value"] == 5000
    assert config["audit_retention"]["retention_days"]["value"] == 14
    assert config["rate_limit"]["per_minute"]["value"] == 60
    assert config["rate_limit"]["burst"]["value"] == 10


def test_security_report_exposes_production_hardening_without_raw_keys(
    monkeypatch,
    tmp_path,
):
    _clear_hardening_env(monkeypatch)
    monkeypatch.setenv("SHADOWGATE_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SHADOWGATE_ADMIN_KEY", "strong-admin-report-key")
    monkeypatch.setenv("SHADOWGATE_CLIENT_KEY", "strong-client-report-key")

    report = create_security_report(admin_key="strong-admin-report-key")
    rendered = json.dumps(report, sort_keys=True)

    assert report["auth"]["ok"] is True
    assert "production_hardening" in report["report_sections"]
    assert "strong-admin-report-key" not in rendered
    assert "strong-client-report-key" not in rendered
