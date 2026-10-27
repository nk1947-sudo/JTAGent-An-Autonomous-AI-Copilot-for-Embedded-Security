from scripts.demo import demo_env


def test_demo_ignores_inherited_hardware_and_paid_provider_settings(monkeypatch):
    hostile = {
        "TARGET_BACKEND": "openocd",
        "TARGET_PROFILE": "C:/private/live-profile.json",
        "REPLAY_MANIFEST": "C:/private/live-replay.json",
        "OPENOCD_TARGET": "am335x.cpu",
        "OPENOCD_PORT": "6666",
        "ARM_SNAPSHOTS": "1",
        "UART_AUDIT_ENABLED": "1",
        "UART_PORT": "COM12",
        "UART_AUDIT_PASSWORD": "real-serial-secret",
        "INFERENCE_BACKEND": "nebius",
        "NEBIUS_API_KEY": "paid-provider-secret",
        "NEBIUS_BASE_URL": "https://api.tokenfactory.nebius.com/v1",
        "OLLAMA_MODEL": "qwen3.5:4b",
        "ATTACK_LAB_LIVE_JTAG": "1",
        "EDGE_API_URL": "https://real-edge.invalid",
        "PUBLIC_ORIGIN": "https://real-dashboard.invalid",
        "COOKIE_SECURE": "1",
        "EDGE_API_KEY": "real-edge-secret",
        "DASHBOARD_PASSWORD": "real-dashboard-secret",
        "MAX_READ_BYTES": "16384",
        "RETAIN_RAW_LOCAL": "1",
        "EXPORT_DIR": "C:/private/export",
        "TAVILY_API_KEY": "external-search-secret",
        "LANGSMITH_API_KEY": "external-tracing-secret",
        "REDACT_VALUES": "private-value",
    }
    for key, value in hostile.items():
        monkeypatch.setenv(key, value)

    env = demo_env()

    assert env["TARGET_BACKEND"] == "mock"
    assert env["MOCK_VARIANT"] == "demo"
    assert env["INFERENCE_BACKEND"] == "scripted"
    assert env["ATTACK_LAB_LIVE_JTAG"] == "0"
    assert env["EDGE_API_URL"] == "http://127.0.0.1:8001"
    assert env["PUBLIC_ORIGIN"] == "http://127.0.0.1:8000" and env["COOKIE_SECURE"] == "0"
    assert env["MAX_READ_BYTES"] == "4096" and env["RETAIN_RAW_LOCAL"] == "0"
    assert env["EDGE_API_KEY"] != hostile["EDGE_API_KEY"]
    assert env["DASHBOARD_PASSWORD"] != hostile["DASHBOARD_PASSWORD"]
    assert env["REDACT_VALUES"] == "private-value"
    assert not any(
        key.startswith(("OPENOCD_", "UART_", "NEBIUS_", "OLLAMA_"))
        or key
        in {
            "TARGET_PROFILE",
            "REPLAY_MANIFEST",
            "ARM_SNAPSHOTS",
            "EXPORT_DIR",
            "TAVILY_API_KEY",
            "LANGSMITH_API_KEY",
        }
        for key in env
    )
