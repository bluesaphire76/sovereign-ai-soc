import unittest
from pathlib import Path

from executor.models import ExecutorMode
from executor.validators import validate_executor_action
from tests.test_executor_policy import executor_context, remediation_action


class ExecutorSafetyTests(unittest.TestCase):
    def test_executor_source_has_no_subprocess_or_shell_execution(self):
        executor_files = sorted(Path("executor").glob("*.py"))
        source = "\n".join(path.read_text() for path in executor_files)

        self.assertNotIn("import subprocess", source)
        self.assertNotIn("subprocess.", source)
        self.assertNotIn("os.system", source)
        self.assertNotIn("shell=True", source)
        self.assertNotIn("Popen", source)

    def test_action_model_forces_non_executable_flags(self):
        executor_action, *_ = executor_context(remediation_action(), mode=ExecutorMode.NOOP)
        object.__setattr__(executor_action, "execution_supported", True)
        object.__setattr__(executor_action, "production_impact_allowed", True)
        object.__setattr__(executor_action, "command_preview_is_executable", True)

        validation = validate_executor_action(executor_action)

        self.assertFalse(validation.valid)
        self.assertIn("EXECUTOR_ACTION_MUST_NOT_SUPPORT_REAL_EXECUTION", validation.issues)
        self.assertIn("EXECUTOR_ACTION_MUST_NOT_ALLOW_PRODUCTION_IMPACT", validation.issues)
        self.assertIn("EXECUTOR_COMMAND_PREVIEW_MUST_NOT_BE_EXECUTABLE", validation.issues)


if __name__ == "__main__":
    unittest.main()
