"""Candidate-campaign launcher seam.

The lead wires a real implementation (enqueue via WP7 jobs and wait for the
campaign to finish, returning its campaign_id). ``--candidate`` mode compares two
already-stored campaigns and needs no launcher.
"""

from __future__ import annotations

from typing import Protocol


class CampaignLauncher(Protocol):
    def launch(self, target_id: str, suite: str) -> str:
        """Run ``suite`` against ``target_id`` to completion; return the campaign_id."""
        ...
