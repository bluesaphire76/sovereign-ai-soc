from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Protocol

from models import Incident


class IncidentAccessPolicy(Protocol):
    def can_read_incident(
        self,
        incident: Incident,
        *,
        current_user: Mapping[str, Any] | None,
    ) -> bool: ...

    def authorized_incident_ids(
        self,
        db: Any,
        incident_ids: Iterable[int],
        *,
        current_user: Mapping[str, Any] | None,
    ) -> set[int]: ...


@dataclass(frozen=True)
class PlatformIncidentAccessPolicy:
    """Apply the platform's current global incident read boundary.

    The data model does not yet expose row-level incident ACLs. Keeping this
    policy typed and injectable ensures any future ACL predicate is applied
    before cross-incident facts enter the model-facing package.
    """

    readable_roles: frozenset[str] = frozenset({"ADMIN", "ANALYST"})

    def can_read_incident(
        self,
        incident: Incident,
        *,
        current_user: Mapping[str, Any] | None,
    ) -> bool:
        if current_user is None:
            return True
        return str(current_user.get("role") or "").strip().upper() in self.readable_roles

    def authorized_incident_ids(
        self,
        db: Any,
        incident_ids: Iterable[int],
        *,
        current_user: Mapping[str, Any] | None,
    ) -> set[int]:
        requested = list(
            dict.fromkeys(
                value
                for value in incident_ids
                if isinstance(value, int) and value > 0
            )
        )
        if not requested:
            return set()
        try:
            rows = db.query(Incident).filter(Incident.id.in_(requested)).all()
        except Exception:
            return set()
        return {
            int(row.id)
            for row in rows
            if self.can_read_incident(row, current_user=current_user)
        }


_DEFAULT_INCIDENT_ACCESS_POLICY = PlatformIncidentAccessPolicy()


def get_incident_access_policy() -> IncidentAccessPolicy:
    return _DEFAULT_INCIDENT_ACCESS_POLICY
