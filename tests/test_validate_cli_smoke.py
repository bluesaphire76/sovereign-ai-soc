from pathlib import Path

import scripts.validate_cli_smoke as cli_smoke


def make_repository(tmp_path: Path) -> Path:
    (tmp_path / "reports" / "validation").mkdir(parents=True)
    (tmp_path / "ai-soc").write_text("#!/bin/sh\n", encoding="utf-8")
    return tmp_path


def process_for_spec(
    spec: cli_smoke.CommandSpec,
    *,
    returncode: int = 0,
) -> cli_smoke.ProcessResult:
    if spec.json_results:
        if returncode == 1:
            result = next(iter(spec.nonzero_results))
        else:
            result = next(
                value
                for value in spec.json_results
                if value not in spec.nonzero_results
            )
        payload = {"result": result, "exit_code": returncode}
        if spec.json_identity:
            key, value = spec.json_identity
            payload[key] = value
        import json

        return cli_smoke.ProcessResult(
            returncode=returncode,
            stdout=json.dumps(payload),
        )

    output = "\n".join(spec.markers)
    if spec.any_markers:
        output += "\n" + spec.any_markers[0]
    if returncode == 1 and spec.nonzero_markers:
        output += "\n" + spec.nonzero_markers[0]
    return cli_smoke.ProcessResult(
        returncode=returncode,
        stdout=output,
    )


def ready_runner(repository_root, arguments, _timeout):
    del repository_root
    command_arguments = tuple(arguments[1:])
    specs = (*cli_smoke.REQUIRED_COMMANDS, *cli_smoke.GRACEFUL_COMMANDS)
    spec = next(item for item in specs if item.arguments == command_arguments)
    return process_for_spec(spec)


def test_complete_report_accepts_safe_commands(tmp_path):
    validator = cli_smoke.CliSmokeValidator(
        repository_root=make_repository(tmp_path),
        runner=ready_runner,
    )

    report, exit_code = validator.report()

    assert exit_code == 0
    assert report["result"] == "CLI_SMOKE_READY"
    assert report["summary"]["required"] == {
        "ok": 6,
        "fail": 0,
        "total": 6,
    }
    assert report["summary"]["graceful"] == {
        "ok": 8,
        "fail": 0,
        "total": 8,
    }


def test_expected_json_degradation_is_accepted():
    spec = next(
        item
        for item in cli_smoke.GRACEFUL_COMMANDS
        if item.arguments == ("demo-validate", "--no-runtime", "--json")
    )

    result = cli_smoke.evaluate_command(
        spec,
        process_for_spec(spec, returncode=1),
        required=False,
    )

    assert result.status == "OK"
    assert result.result == "DEMO_NOT_READY"


def test_required_nonzero_exit_is_rejected():
    spec = cli_smoke.REQUIRED_COMMANDS[0]

    result = cli_smoke.evaluate_command(
        spec,
        process_for_spec(spec, returncode=1),
        required=True,
    )

    assert result.status == "FAIL"
    assert "expected 0" in result.message


def test_traceback_is_rejected_even_with_zero_exit():
    spec = cli_smoke.REQUIRED_COMMANDS[0]
    process = process_for_spec(spec)
    process = cli_smoke.ProcessResult(
        returncode=0,
        stdout=process.stdout + "\nTraceback (most recent call last):",
    )

    result = cli_smoke.evaluate_command(spec, process, required=True)

    assert result.status == "FAIL"
    assert "unhandled Python error" in result.message


def test_real_looking_secret_is_rejected():
    spec = cli_smoke.REQUIRED_COMMANDS[0]
    process = process_for_spec(spec)
    process = cli_smoke.ProcessResult(
        returncode=0,
        stdout=process.stdout + "\nghp_abcdefghijklmnopqrstuvwxyz123456",
    )

    result = cli_smoke.evaluate_command(spec, process, required=True)

    assert result.status == "FAIL"
    assert "possible secret output" in result.message


def test_timeout_is_rejected():
    spec = cli_smoke.GRACEFUL_COMMANDS[0]

    result = cli_smoke.evaluate_command(
        spec,
        cli_smoke.ProcessResult(
            returncode=124,
            stdout="partial output",
            timed_out=True,
        ),
        required=False,
    )

    assert result.status == "FAIL"
    assert "timed out" in result.message


def test_protected_path_change_fails_the_responsible_command(tmp_path):
    repository = make_repository(tmp_path)

    def mutating_runner(_root, arguments, _timeout):
        command_arguments = tuple(arguments[1:])
        spec = next(
            item
            for item in cli_smoke.REQUIRED_COMMANDS
            if item.arguments == command_arguments
        )
        (repository / ".env").write_text("changed\n", encoding="utf-8")
        return process_for_spec(spec)

    validator = cli_smoke.CliSmokeValidator(
        repository_root=repository,
        runner=mutating_runner,
    )

    result = validator.run_spec(
        cli_smoke.REQUIRED_COMMANDS[0],
        required=True,
    )

    assert result.status == "FAIL"
    assert "modified protected local path" in result.message


def test_root_cli_help_lists_clean_demo_commands():
    result = cli_smoke.run_command(
        cli_smoke.REPOSITORY_ROOT,
        ("./ai-soc", "help"),
        5.0,
    )

    assert result.returncode == 0
    assert "demo-info [--json]" in result.stdout
    assert "demo-reset [--dry-run|--apply] [--json]" in result.stdout
