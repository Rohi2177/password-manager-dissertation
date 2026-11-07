"""Fake approvals used only in tests."""

from collections.abc import Iterable

from password_manager.broker.capabilities import ALLOWED_CAPABILITY_ACTIONS

MAX_APPROVALS = 128


class OneShotApprovalPolicy:
    """Allow only the fake actions listed by a test."""

    __slots__ = ("_approvals",)

    def __init__(self, approvals: Iterable[tuple[str, str]]) -> None:
        approval_list = list(approvals)

        if len(approval_list) > MAX_APPROVALS:
            raise ValueError("Too many test approvals.")
        self._approvals: dict[tuple[str, str], int] = {}

        for record_id, action in approval_list:
            if (
                not isinstance(record_id, str)
                or len(record_id) != 32
                or action not in ALLOWED_CAPABILITY_ACTIONS
            ):
                raise ValueError("Invalid test approval.")
            key = (record_id, action)
            self._approvals[key] = self._approvals.get(key, 0) + 1

    def approve(
        self,
        record_id: str,
        action: str,
        title: str | None = None,
    ) -> bool:

        del title
        key = (record_id, action)
        remaining = self._approvals.get(key, 0)

        if remaining < 1:
            return False

        if remaining == 1:
            del self._approvals[key]

        else:
            self._approvals[key] = remaining - 1
        return True
