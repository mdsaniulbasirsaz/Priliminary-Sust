from __future__ import annotations

import json

import pytest

from app.investigator import investigate
from app.schemas import (
    AnalyzeTicketRequest,
    TransactionHistoryEntry,
)

SAMPLE_CASES_PATH = "Sample-Case.json"


def load_sample_cases():
    with open(SAMPLE_CASES_PATH) as f:
        data = json.load(f)
    return data["cases"]


def make_request(case_input: dict) -> AnalyzeTicketRequest:
    txns = [
        TransactionHistoryEntry(**t)
        for t in case_input.get("transaction_history", [])
    ]
    kwargs: dict = {
        "ticket_id": case_input["ticket_id"],
        "complaint": case_input["complaint"],
        "transaction_history": txns,
    }
    for field in ("language", "channel", "user_type", "campaign_context"):
        if field in case_input:
            kwargs[field] = case_input[field]
    return AnalyzeTicketRequest(**kwargs)


def severity_equivalent(actual: str, expected: str) -> bool:
    """Compare severity with tolerance — adjacent levels are acceptable."""
    order = ["low", "medium", "high", "critical"]
    if actual == expected:
        return True
    if actual in order and expected in order:
        return abs(order.index(actual) - order.index(expected)) <= 1
    return False


# ── Parametrized test — one case per test ────────────────────────────────────


@pytest.mark.parametrize("case", load_sample_cases(), ids=lambda c: c["id"])
def test_sample_case(case):
    req = make_request(case["input"])
    resp = investigate(req)
    exp = case["expected_output"]

    assert resp.ticket_id == exp["ticket_id"], f"ticket_id mismatch"
    assert (
        resp.relevant_transaction_id == exp.get("relevant_transaction_id")
    ), f"relevant_transaction_id mismatch: got {resp.relevant_transaction_id}, expected {exp.get('relevant_transaction_id')}"
    assert (
        resp.evidence_verdict.value == exp["evidence_verdict"]
    ), f"evidence_verdict mismatch"
    assert resp.case_type.value == exp["case_type"], f"case_type mismatch"
    assert (
        resp.department.value == exp["department"]
    ), f"department mismatch"
    assert severity_equivalent(
        resp.severity.value, exp["severity"]
    ), f"severity mismatch: got {resp.severity.value}, expected {exp['severity']}"
    assert (
        resp.human_review_required == exp["human_review_required"]
    ), f"human_review_required mismatch: got {resp.human_review_required}, expected {exp['human_review_required']}"

    # Customer reply must be safe
    reply_lower = resp.customer_reply.lower()
    has_pin_warning = (
        "otp" in reply_lower
        or "pin" in reply_lower
        or "পিন" in resp.customer_reply
        or "ওটিপি" in resp.customer_reply
    )
    if resp.case_type.value != "merchant_settlement_delay":
        assert has_pin_warning, (
            f"customer_reply missing PIN/OTP warning: {resp.customer_reply[:100]}"
        )
    assert "will refund" not in reply_lower, (
        f"customer_reply contains unauthorized promise: {resp.customer_reply[:100]}"
    )
