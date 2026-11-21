"""WP3 conversation statuses added to the frozen contracts."""

from typing import get_args

from cyberredteam.contracts import TERMINAL_CONVERSATION_STATUSES, ConversationStatus


def test_engine_statuses_exist_and_every_non_running_status_is_terminal():
    statuses = set(get_args(ConversationStatus))
    assert {"stopped_killed", "stopped_target_error_streak", "cancelled"} <= statuses
    assert TERMINAL_CONVERSATION_STATUSES == statuses - {"running"}
