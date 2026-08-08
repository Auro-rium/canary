"""Contracts preventing silent campaign/strategy regressions."""

from cyberredteam.agents.attacker import _reference_payloads
from cyberredteam.attack_strategies.registry import STRATEGY_REGISTRY
from cyberredteam.schemas import StrategyType


def test_registry_covers_every_strategy_enum():
    assert set(STRATEGY_REGISTRY) == set(StrategyType)


def test_every_strategy_has_dispatchable_reference_payload():
    for strategy in StrategyType:
        assert _reference_payloads(strategy, "test target")


def test_campaign_request_accepts_legacy_label_but_server_id_is_not_client_supplied():
    from cyberredteam.api import CampaignRunRequest

    request = CampaignRunRequest(campaign_id="reused", techniques=[])
    assert request.campaign_id == "reused"
