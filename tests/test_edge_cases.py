from __future__ import annotations

import pytest

from app.investigator import investigate
from app.schemas import (
    AnalyzeTicketRequest,
    TransactionHistoryEntry,
)


def _make_txn(
    txn_id: str = "TXN-001",
    timestamp: str = "2026-04-14T10:00:00Z",
    txn_type: str = "transfer",
    amount: float = 1000,
    counterparty: str = "+8801712345678",
    status: str = "completed",
) -> TransactionHistoryEntry:
    return TransactionHistoryEntry(
        transaction_id=txn_id,
        timestamp=timestamp,
        type=txn_type,
        amount=amount,
        counterparty=counterparty,
        status=status,
    )


def _req(
    complaint: str = "Test complaint",
    txns: list | None = None,
    **kwargs,
) -> AnalyzeTicketRequest:
    return AnalyzeTicketRequest(
        ticket_id=kwargs.get("ticket_id", "TKT-EDGE"),
        complaint=complaint,
        transaction_history=txns or [],
        language=kwargs.get("language", "en"),
    )


# ─── Edge Case: Empty complaint ──────────────────────────────────────────────


def test_empty_complaint():
    resp = investigate(_req(complaint=""))
    assert resp.relevant_transaction_id is None
    assert resp.evidence_verdict.value == "insufficient_data"
    assert resp.case_type.value == "other"
    assert resp.severity.value == "low"


# ─── Edge Case: Complaint with only whitespace ────────────────────────────────


def test_whitespace_complaint():
    resp = investigate(_req(complaint="   \n  \t  "))
    assert resp.relevant_transaction_id is None
    assert resp.evidence_verdict.value == "insufficient_data"
    assert resp.case_type.value == "other"


# ─── Edge Case: Complaints with all possible channels ─────────────────────────


def test_all_channels():
    for channel in ["in_app_chat", "call_center", "email", "merchant_portal", "field_agent"]:
        req = AnalyzeTicketRequest(
            ticket_id="TKT-CH",
            complaint="I sent 500 taka to wrong number.",
            language="en",
            channel=channel,
            transaction_history=[_make_txn()],
        )
        resp = investigate(req)
        assert resp.relevant_transaction_id is not None
        assert resp.evidence_verdict.value == "consistent"


# ─── Edge Case: Large amount (boundary testing) ───────────────────────────────


def test_large_amount():
    req = _req(
        complaint="I sent 100000 taka to wrong number.",
        txns=[_make_txn(amount=100000, counterparty="+8801712345678")],
    )
    resp = investigate(req)
    assert resp.relevant_transaction_id is not None
    assert resp.severity.value == "high"
    assert resp.human_review_required is True


def test_critical_amount():
    req = _req(
        complaint="I transferred 50000 taka to a stranger by mistake.",
        txns=[_make_txn(txn_id="TXN-LRG", amount=50000, counterparty="+8801712345678")],
    )
    resp = investigate(req)
    assert resp.relevant_transaction_id == "TXN-LRG"
    assert resp.severity.value == "high"  # 50K >= 10K → high


# ─── Edge Case: All transaction types ─────────────────────────────────────────


def test_all_transaction_types():
    for txn_type in ["transfer", "payment", "cash_in", "cash_out", "settlement", "refund"]:
        req = _req(
            complaint="I sent 1000 taka but something went wrong.",
            txns=[_make_txn(txn_type=txn_type)],
        )
        resp = investigate(req)
        assert resp.relevant_transaction_id is not None, f"no match for {txn_type}"


# ─── Edge Case: All transaction statuses ──────────────────────────────────────


def test_pending_transaction():
    req = _req(
        complaint="I deposited 1000 taka but balance not updated.",
        txns=[_make_txn(status="pending")],
    )
    resp = investigate(req)
    assert resp.relevant_transaction_id is not None
    assert resp.evidence_verdict.value in ("consistent", "insufficient_data")


def test_reversed_transaction():
    req = _req(
        complaint="My 1000 taka refund was processed but I don't see the money.",
        txns=[_make_txn(status="reversed", amount=1000)],
    )
    resp = investigate(req)
    assert resp.relevant_transaction_id is not None


# ─── Edge Case: Mixed language complaint ──────────────────────────────────────


def test_mixed_language():
    req = _req(
        complaint="আমার 500 taka ট্রান্সফার হয়েছে ভুল নম্বরে। please help.",
        txns=[_make_txn(amount=500)],
    )
    resp = investigate(req)
    assert resp.customer_reply is not None


# ─── Edge Case: Missing fields are optional ────────────────────────────────────


def test_minimal_request():
    """Only ticket_id and complaint are required."""
    req = AnalyzeTicketRequest(
        ticket_id="TKT-MIN",
        complaint="I have an issue.",
    )
    resp = investigate(req)
    assert resp.ticket_id == "TKT-MIN"
    assert resp.relevant_transaction_id is None


def test_malformed_amount_in_complaint():
    """Complaint mentions amount but with unusual formatting."""
    req = _req(
        complaint="Sent 5,000.50 taka to wrong number.",
        txns=[_make_txn(amount=5000.50)],
    )
    resp = investigate(req)
    assert resp.relevant_transaction_id is not None
    assert resp.evidence_verdict.value == "consistent"


# ─── Edge Case: Safety is always applied ──────────────────────────────────────


def test_customer_reply_always_safe():
    """Even with no transaction history, customer_reply must mention PIN/OTP safety."""
    req = _req(complaint="I lost money.", txns=[])
    resp = investigate(req)
    reply_lower = resp.customer_reply.lower()
    assert "otp" in reply_lower or "pin" in reply_lower


def test_no_unauthorized_promise():
    """customer_reply must never contain unauthorized promises."""
    req = _req(
        complaint="Please refund my 500 taka.",
        txns=[_make_txn(amount=500)],
    )
    resp = investigate(req)
    assert "will refund" not in resp.customer_reply.lower()
