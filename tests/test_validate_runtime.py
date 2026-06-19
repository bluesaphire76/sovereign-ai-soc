from pathlib import Path

import scripts.validate_runtime as validate_runtime


def make_repository(tmp_path: Path) -> Path:
    (tmp_path / ".git").mkdir()
    (tmp_path / "scripts").mkdir()
    for relative_path in (
        "README.md",
        "ai-soc",
        "scripts/doctor.py",
        "scripts/validate_public_ci_baseline.py",
    ):
        (tmp_path / relative_path).write_text("test\n", encoding="utf-8")
    return tmp_path


def test_standard_mode_warns_when_runtime_is_unavailable(
    tmp_path,
    monkeypatch,
):
    repository = make_repository(tmp_path)
    monkeypatch.setattr(
        validate_runtime,
        "local_http",
        lambda *_args, **_kwargs: (False, "unavailable"),
    )
    monkeypatch.setattr(
        validate_runtime,
        "local_tcp",
        lambda *_args, **_kwargs: (False, "unavailable"),
    )

    report, exit_code = validate_runtime.RuntimeValidator(
        strict=False,
        repository_root=repository,
    ).report()

    assert exit_code == 0
    assert report["result"] == "READY_WITH_WARNINGS"
    assert not [check for check in report["checks"] if check["status"] == "FAIL"]


def test_strict_mode_requires_backend_and_frontend(tmp_path, monkeypatch):
    repository = make_repository(tmp_path)
    monkeypatch.setattr(
        validate_runtime,
        "local_http",
        lambda *_args, **_kwargs: (False, "unavailable"),
    )
    monkeypatch.setattr(
        validate_runtime,
        "local_tcp",
        lambda *_args, **_kwargs: (False, "unavailable"),
    )

    report, exit_code = validate_runtime.RuntimeValidator(
        strict=True,
        repository_root=repository,
    ).report()

    assert exit_code == 1
    assert report["result"] == "NOT_READY"
    failed_ids = {
        check["check_id"]
        for check in report["checks"]
        if check["status"] == "FAIL"
    }
    assert failed_ids == {"backend", "frontend"}


def test_non_local_urls_are_refused():
    url, error = validate_runtime.safe_local_url("https://example.com/health")

    assert url is None
    assert "refused non-local URL" in error
