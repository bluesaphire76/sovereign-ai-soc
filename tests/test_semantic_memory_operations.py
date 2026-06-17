import unittest
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import HTTPException

from routers.semantic_memory import (
    HistoricalBackfillRequest,
    RetentionCleanupRequest,
    semantic_memory_historical_backfill,
    semantic_memory_retention_cleanup,
)


def request_for(role="ADMIN", username="admin"):
    return SimpleNamespace(
        state=SimpleNamespace(
            current_user={
                "id": 1,
                "username": username,
                "role": role,
            }
        )
    )


class SemanticMemoryOperationsTests(unittest.TestCase):
    def test_backfill_dry_run_does_not_require_confirmation(self):
        with patch(
            "routers.semantic_memory.run_indexing",
            return_value={
                "mode": "dry-run",
                "records_prepared": 12,
                "indexed_points": 0,
                "decision_boundary": "advisory only",
            },
        ) as runner:
            result = semantic_memory_historical_backfill(
                HistoricalBackfillRequest(apply=False, limit=100),
                request_for(),
            )

        runner.assert_called_once_with(
            limit=100,
            since_days=None,
            include_open=False,
            apply=False,
        )
        self.assertEqual(result["operation"], "historical_backfill")
        self.assertFalse(result["applied"])
        self.assertEqual(result["requested_by"], "admin")

    def test_backfill_apply_requires_confirmation(self):
        with self.assertRaises(HTTPException) as context:
            semantic_memory_historical_backfill(
                HistoricalBackfillRequest(apply=True, confirm=False),
                request_for(),
            )

        self.assertEqual(context.exception.status_code, 400)

    def test_retention_cleanup_rejects_non_admin(self):
        with self.assertRaises(HTTPException) as context:
            semantic_memory_retention_cleanup(
                RetentionCleanupRequest(apply=False),
                request_for(role="ANALYST", username="analyst"),
            )

        self.assertEqual(context.exception.status_code, 403)

    def test_retention_cleanup_apply_runs_with_confirmation(self):
        with patch(
            "routers.semantic_memory.run_retention",
            return_value={
                "mode": "APPLY",
                "candidates": 2,
                "deleted": 2,
                "decision_boundary": "historical only",
            },
        ) as runner:
            result = semantic_memory_retention_cleanup(
                RetentionCleanupRequest(
                    apply=True,
                    confirm=True,
                    retention_days=90,
                    max_records=250,
                ),
                request_for(),
            )

        runner.assert_called_once_with(
            apply=True,
            retention_days=90,
            max_records=250,
            include_open=False,
        )
        self.assertEqual(result["operation"], "retention_cleanup")
        self.assertTrue(result["applied"])
        self.assertEqual(result["deleted"], 2)


if __name__ == "__main__":
    unittest.main()
