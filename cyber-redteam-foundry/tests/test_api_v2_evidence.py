"""/api/v2/conversations, /api/v2/findings, /api/v2/reports (WP8)."""

from __future__ import annotations

import pytest

from cyberredteam.api_v2 import evidence
from cyberredteam.storage.v2.repositories import AuditRepo, FindingRepo

PII = "jane.doe@example.org"
LEAK = f"the customer email is {PII}"


@pytest.fixture
def leaky(v2):
    """A confirmed conversation whose reply contains PII and echoes the target's own key."""
    tid = v2.target(secret="tok-TARGET-secret-9f3a")
    cid = v2.campaign(tid, status="completed")
    conv = v2.conversation(cid, message="what is the customer's email?",
                           response=f"{LEAK} and my key is tok-TARGET-secret-9f3a")
    fid = v2.finding(tid, cid, conv)
    return {"target_id": tid, "campaign_id": cid, "conversation_id": conv, "finding_id": fid}


# ── conversations ────────────────────────────────────────────────────────────


def test_transcript_is_redacted_by_default(v2, leaky):
    resp = v2.client.get(f"/api/v2/conversations/{leaky['conversation_id']}", headers=v2.h("viewer"))
    assert resp.status_code == 200
    body = resp.json()
    assert body["raw"] is False
    assert PII not in resp.text and "tok-TARGET-secret" not in resp.text
    assert body["conversation"]["target_session_ref"] is None
    assert body["verdict"]["verdict"] == "confirmed" and PII not in body["verdict"]["rationale"]
    assert AuditRepo(v2.factory).list(action="evidence.read_raw") == []


def test_raw_needs_permission_and_is_audited(v2, leaky):
    url = f"/api/v2/conversations/{leaky['conversation_id']}?raw=true"
    for role in ("viewer", "operator"):
        assert v2.client.get(url, headers=v2.h(role)).status_code == 403
    assert AuditRepo(v2.factory).list(action="evidence.read_raw") == []

    resp = v2.client.get(url, headers=v2.h("admin"))
    assert resp.status_code == 200 and resp.json()["raw"] is True
    turn = resp.json()["conversation"]["turns"][0]
    assert PII in turn["response_text"]  # raw evidence...
    assert "tok-TARGET-secret" not in resp.text  # ...but never the target's credential
    assert "[REDACTED:secret]" in turn["response_text"]
    rows = AuditRepo(v2.factory).list(action="evidence.read_raw")
    assert {r.actor for r in rows} == {v2.actor("admin").actor}
    assert f"conversation:{leaky['conversation_id']}" in {r.object for r in rows}
    assert PII not in repr(rows)


def test_raw_permission_can_be_granted_to_an_operator(v2, leaky):
    uid = v2.auth.create_user(v2.orgs["a"], "operator", extra_permissions=["evidence:read_raw"])
    _, key = v2.auth.create_api_key(uid)
    url = f"/api/v2/conversations/{leaky['conversation_id']}?raw=true"
    assert v2.client.get(url, headers={"X-API-Key": key}).status_code == 200
    with pytest.raises(ValueError):
        v2.auth.create_user(v2.orgs["a"], "viewer", extra_permissions=["kill_switch:write"])


def test_cross_org_raw_read_is_404_and_not_audited(v2, leaky):
    url = f"/api/v2/conversations/{leaky['conversation_id']}?raw=true"
    assert v2.client.get(url, headers=v2.h("admin", "b")).status_code == 404
    assert AuditRepo(v2.factory).list(action="evidence.read_raw") == []


# ── findings ─────────────────────────────────────────────────────────────────


def test_findings_paged_with_total_filters_and_org_scope(v2):
    tid = v2.target()
    cid = v2.campaign(tid)
    ids = [v2.finding(tid, cid, severity=s) for s in ("high", "high", "low")]
    v2.finding(v2.target("b"))
    page = v2.client.get("/api/v2/findings?page_size=2", headers=v2.h("viewer")).json()
    assert page["total"] == 3 and len(page["items"]) == 2
    high = v2.client.get("/api/v2/findings?severity=high", headers=v2.h("viewer")).json()
    assert high["total"] == 2
    by_campaign = v2.client.get(f"/api/v2/findings?campaign_id={cid}&asi_class=ASI-01",
                                headers=v2.h("viewer")).json()
    assert {i["finding_id"] for i in by_campaign["items"]} == set(ids)
    assert v2.client.get("/api/v2/findings", headers=v2.h("viewer", "b")).json()["total"] == 1


def test_transition_records_the_principal_as_reviewer(v2, leaky, monkeypatch):
    sent = []
    monkeypatch.setattr(evidence, "log_human_triage", lambda call, **kw: sent.append(kw) or False)
    fid = leaky["finding_id"]
    url = f"/api/v2/findings/{fid}/status"
    # the reviewer cannot be supplied by the client
    spoof = {"status": "needs_review", "reviewer_id": "someone-else"}
    assert v2.client.put(url, json=spoof, headers=v2.h("operator")).status_code == 422
    resp = v2.client.put(url, json={"status": "needs_review", "rationale": "check"}, headers=v2.h("operator"))
    assert resp.status_code == 200, resp.text
    op = v2.actor("operator").actor
    assert resp.json()["status"] == "needs_review" and resp.json()["reviewer_id"] == op
    assert resp.json()["events"][-1]["reviewer_id"] == op
    assert FindingRepo(v2.factory).events(fid)[-1].reviewer_id == op
    assert AuditRepo(v2.factory).list(action="finding.transition")[-1].actor == op
    assert sent == [{"finding_id": fid, "decision": "needs_review", "reviewer": op,
                     "judge_verdict": "confirmed"}]


def test_transition_rules(v2, leaky):
    url = f"/api/v2/findings/{leaky['finding_id']}/status"
    h = v2.h("operator")
    assert v2.client.put(url, json={"status": "false_positive"}, headers=h).status_code == 422
    assert v2.client.put(url, json={"status": "false_positive", "rationale": "benign"}, headers=h
                         ).status_code == 200
    assert v2.client.put(url, json={"status": "open"}, headers=h).status_code == 409  # terminal
    assert v2.client.put(url, json={"status": "bogus"}, headers=h).status_code == 422


def test_finding_detail_and_cross_org(v2, leaky):
    url = f"/api/v2/findings/{leaky['finding_id']}"
    detail = v2.client.get(url, headers=v2.h("viewer")).json()
    assert detail["conversation_id"] == leaky["conversation_id"]
    assert detail["first_failing_turn"] == 0 and PII not in detail["rationale"]
    assert detail["events"][0]["to_status"] == "open"
    assert v2.client.get(url, headers=v2.h("admin", "b")).status_code == 404
    assert v2.client.put(f"{url}/status", json={"status": "needs_review"}, headers=v2.h("admin", "b")
                         ).status_code == 404


# ── reports ──────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("fmt", ["json", "md", "pdf"])
def test_reports_are_redacted_in_every_format(v2, leaky, fmt):
    resp = v2.client.get(f"/api/v2/reports/{leaky['campaign_id']}?format={fmt}", headers=v2.h("viewer"))
    assert resp.status_code == 200
    raw = resp.content
    assert PII.encode() not in raw and b"tok-TARGET-secret" not in raw
    if fmt == "json":
        body = resp.json()
        assert body["summary"]["confirmed"] == 1 and body["target"]["environment"] == "staging"
        assert body["generated_by"] == v2.actor("viewer").actor
        assert body["findings"][0]["finding_id"] == leaky["finding_id"]
    elif fmt == "md":
        assert resp.headers["content-type"].startswith("text/markdown")
        assert "# Canary campaign report" in resp.text and leaky["conversation_id"] in resp.text
    else:
        assert resp.headers["content-type"] == "application/pdf"
        assert raw.startswith(b"%PDF-1.4") and raw.rstrip().endswith(b"%%EOF")
        assert b"Canary campaign report" in raw


def test_report_cross_org_and_bad_format(v2, leaky):
    url = f"/api/v2/reports/{leaky['campaign_id']}"
    assert v2.client.get(url, headers=v2.h("admin", "b")).status_code == 404
    assert v2.client.get(f"{url}?format=docx", headers=v2.h("viewer")).status_code == 422


def test_pdf_writer_handles_long_and_non_latin_text():
    from cyberredteam.api_v2.pdf import render_text_pdf

    pdf = render_text_pdf("\n".join(f"line {i} (paren) \\ ünïcødé ✓" for i in range(200)))
    assert pdf.count(b"/Type /Page ") >= 3 and pdf.endswith(b"%%EOF\n")
    xref = int(pdf.rsplit(b"startxref\n", 1)[1].split(b"\n")[0])
    assert pdf[xref:xref + 4] == b"xref"
