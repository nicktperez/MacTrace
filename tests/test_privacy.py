from mactrace.privacy import sanitize_command_line


def test_sanitizes_secret_flags_and_long_payloads():
    result = sanitize_command_line(
        ["curl", "--token", "super-secret", "--api-key=another-secret", "A" * 180]
    )
    assert "super-secret" not in result
    assert "another-secret" not in result
    assert "[REDACTED]" in result
    assert "[LONG_ARGUMENT_REDACTED]" in result


def test_command_is_bounded():
    result = sanitize_command_line(["python3", "-c", "x" * 500], max_chars=40)
    assert len(result) <= 40

