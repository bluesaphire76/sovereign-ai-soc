from __future__ import annotations

from datetime import datetime, timezone

from scripts.release_readiness import (
    Check,
    CommandResult,
    RESULT_NOT_READY,
    RESULT_READY,
    RESULT_WARNINGS,
    STATUS_FAIL,
    STATUS_OK,
    STATUS_WARN,
    build_report,
    command_check,
    contains_secret,
    parse_args,
    release_result,
    report_filenames,
)


def _check(status: str, *, strict_blocking: bool = False) -> Check:
    return Check(
        name="test",
        category="test",
        status=status,
        command=None,
        returncode=0,
        summary="test",
        duration_seconds=0.0,
        strict_blocking=strict_blocking,
    )


def test_parse_args_supports_release_modes() -> None:
    args = parse_args(["--json", "--strict", "--no-runtime", "--full", "--write-report"])

    assert args.json is True
    assert args.strict is True
    assert args.no_runtime is True
    assert args.full is True
    assert args.write_report is True


def test_release_result_distinguishes_warnings_and_failures() -> None:
    assert release_result([_check(STATUS_OK)], strict=False) == (RESULT_READY, 0)
    assert release_result([_check(STATUS_WARN)], strict=False) == (RESULT_WARNINGS, 0)
    assert release_result([_check(STATUS_FAIL)], strict=False) == (RESULT_NOT_READY, 1)


def test_strict_mode_only_blocks_classified_warnings() -> None:
    assert release_result([_check(STATUS_WARN)], strict=True) == (RESULT_WARNINGS, 0)
    assert release_result(
        [_check(STATUS_WARN, strict_blocking=True)],
        strict=True,
    ) == (RESULT_NOT_READY, 1)


def test_secret_detection_covers_common_tokens() -> None:
    assert contains_secret("Authorization: Bearer abcdefghijklmnopqrstuvwxyz")
    assert contains_secret("github_pat_abcdefghijklmnopqrstuvwxyz123456")
    assert contains_secret("password=do-not-print-this")
    assert contains_secret("-----BEGIN PRIVATE KEY-----")
    assert not contains_secret("password=<set-a-strong-password>")
    assert not contains_secret("api_key=$TOKEN")
    assert not contains_secret("release readiness completed")


def test_report_filenames_use_supplied_timestamp() -> None:
    now = datetime(2026, 6, 20, 12, 34, 56, tzinfo=timezone.utc)

    markdown_name, json_name = report_filenames(now)

    assert markdown_name == "release-readiness-20260620-123456.md"
    assert json_name == "release-readiness-20260620-123456.json"


def test_report_paths_are_only_exposed_when_writing_reports() -> None:
    repository = {
        "root": "/tmp/repository",
        "branch": "main",
        "commit": "abc1234",
        "clean_worktree": True,
        "status_short": "",
    }

    default_report = build_report(
        args=parse_args([]),
        repository=repository,
        checks=[_check(STATUS_OK)],
        report_paths=["reports/validation/example.json"],
    )
    written_report = build_report(
        args=parse_args(["--write-report"]),
        repository=repository,
        checks=[_check(STATUS_OK)],
        report_paths=["reports/validation/example.json"],
    )

    assert "report_paths" not in default_report
    assert written_report["report_paths"] == ["reports/validation/example.json"]


def test_command_check_uses_requested_working_directory(tmp_path) -> None:
    observed = {}

    def runner(args, *, cwd, timeout, env):
        observed["cwd"] = cwd
        return CommandResult(0, "ok\n", "", 0.01)

    check = command_check(
        name="cwd",
        category="test",
        args=["example"],
        runner=runner,
        cwd=tmp_path,
    )

    assert check.status == STATUS_OK
    assert observed["cwd"] == tmp_path


def test_command_check_redacts_secret_like_output() -> None:
    def runner(args, *, cwd, timeout, env):
        return CommandResult(0, "password=real-value\n", "", 0.01)

    check = command_check(
        name="secret",
        category="test",
        args=["example"],
        runner=runner,
    )

    assert check.status == STATUS_FAIL
    assert check.summary == "[REDACTED secret-like output]"
    assert "real-value" not in check.summary


def test_command_check_handles_timeout() -> None:
    def runner(args, *, cwd, timeout, env):
        return CommandResult(None, "", "", 1.0, timed_out=True)

    check = command_check(
        name="timeout",
        category="test",
        args=["example"],
        runner=runner,
        timeout=1,
    )

    assert check.status == STATUS_FAIL
    assert check.returncode is None
    assert check.summary == "Timed out after 1 seconds."
