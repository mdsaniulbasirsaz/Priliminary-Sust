from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import pytest

from app.llm_client import (
    build_prompt,
    call_llm_with_fallback,
    llm_investigate,
    parse_llm_response,
    validate_llm_output,
)
from app.schemas import (
    AnalyzeTicketRequest,
    AnalyzeTicketResponse,
    CaseType,
    Department,
    EvidenceVerdict,
    Severity,
    TransactionHistoryEntry,
    TransactionStatus,
    TransactionType,
)


def make_request(complaint: str, history: list | None = None) -> AnalyzeTicketRequest:
    return AnalyzeTicketRequest(
        ticket_id="TKT-LLM",
        complaint=complaint,
        transaction_history=history or [],
    )


def test_build_prompt_includes_input():
    request = make_request("I sent 5000 taka to wrong number.")
    prompt = build_prompt(request)
    assert "I sent 5000 taka to wrong number" in prompt
    assert "TKT-LLM" in prompt


def test_build_prompt_includes_system_instructions():
    request = make_request("test")
    prompt = build_prompt(request)
    assert "investigator" in prompt.lower()
    assert "evidence_verdict" in prompt
    assert "case_type" in prompt


def test_parse_llm_response_valid_json():
    data = {
        "ticket_id": "TKT-001",
        "relevant_transaction_id": "TXN-001",
        "evidence_verdict": "consistent",
        "case_type": "wrong_transfer",
        "severity": "high",
        "department": "dispute_resolution",
        "agent_summary": "Test summary.",
        "recommended_next_action": "Investigate.",
        "customer_reply": "We will review.",
        "human_review_required": True,
        "confidence": 0.9,
        "reason_codes": ["wrong_transfer"],
    }
    result = parse_llm_response(json.dumps(data))
    assert result is not None
    assert result["ticket_id"] == "TKT-001"
    assert result["evidence_verdict"] == "consistent"


def test_parse_llm_response_json_in_text():
    text = "Here is the result:\n\n{\"ticket_id\": \"TKT-001\", \"evidence_verdict\": \"consistent\", \"case_type\": \"wrong_transfer\", \"severity\": \"high\", \"department\": \"dispute_resolution\", \"agent_summary\": \"test\", \"recommended_next_action\": \"test\", \"customer_reply\": \"test\", \"human_review_required\": false, \"confidence\": 0.85, \"reason_codes\": []}\n\nEnd."
    result = parse_llm_response(text)
    assert result is not None
    assert result["evidence_verdict"] == "consistent"


def test_parse_llm_response_invalid():
    result = parse_llm_response("not json at all")
    assert result is None


def test_parse_llm_response_empty():
    result = parse_llm_response("")
    assert result is None


def test_parse_llm_response_single_quotes():
    text = "{'ticket_id': 'TKT-001', 'evidence_verdict': 'consistent', 'case_type': 'wrong_transfer', 'severity': 'high', 'department': 'dispute_resolution', 'agent_summary': 'test', 'recommended_next_action': 'test', 'customer_reply': 'test', 'human_review_required': false, 'confidence': 0.85, 'reason_codes': []}"
    result = parse_llm_response(text)
    assert result is not None
    assert result["evidence_verdict"] == "consistent"


def test_validate_llm_output_valid():
    data = {
        "ticket_id": "TKT-001",
        "relevant_transaction_id": "TXN-001",
        "evidence_verdict": "consistent",
        "case_type": "wrong_transfer",
        "severity": "high",
        "department": "dispute_resolution",
        "agent_summary": "Summary here.",
        "recommended_next_action": "Action here.",
        "customer_reply": "Customer reply.",
        "human_review_required": True,
        "confidence": 0.9,
        "reason_codes": ["wrong_transfer"],
    }
    result = validate_llm_output(data)
    assert result is not None
    assert isinstance(result, AnalyzeTicketResponse)
    assert result.ticket_id == "TKT-001"
    assert result.evidence_verdict == EvidenceVerdict.consistent
    assert result.case_type == CaseType.wrong_transfer
    assert result.severity == Severity.high
    assert result.department == Department.dispute_resolution
    assert result.confidence == 0.9


def test_validate_llm_output_invalid_verdict():
    data = {
        "ticket_id": "TKT-001",
        "evidence_verdict": "not_a_real_verdict",
        "case_type": "wrong_transfer",
        "severity": "high",
        "department": "dispute_resolution",
        "agent_summary": "",
        "recommended_next_action": "",
        "customer_reply": "",
        "human_review_required": True,
        "confidence": 0.9,
        "reason_codes": [],
    }
    result = validate_llm_output(data)
    assert result is None


def test_validate_llm_output_minimal():
    data = {
        "ticket_id": "TKT-001",
        "relevant_transaction_id": None,
        "evidence_verdict": "insufficient_data",
        "case_type": "other",
        "severity": "low",
        "department": "customer_support",
        "agent_summary": "",
        "recommended_next_action": "",
        "customer_reply": "",
        "human_review_required": False,
        "confidence": 0.5,
        "reason_codes": [],
    }
    result = validate_llm_output(data)
    assert result is not None
    assert result.evidence_verdict == EvidenceVerdict.insufficient_data


@pytest.mark.asyncio
async def test_llm_investigate_no_api_key():
    request = make_request("Test complaint")
    with patch("app.llm_client.OPENROUTER_API_KEY", ""):
        result = await llm_investigate(request)
    assert result is None


@pytest.mark.asyncio
async def test_llm_investigate_api_error():
    request = make_request("Test complaint")
    with patch("app.llm_client.OPENROUTER_API_KEY", "sk-test"):
        with patch("app.llm_client.call_llm_with_fallback", return_value=None):
            result = await llm_investigate(request)
    assert result is None


@pytest.mark.asyncio
async def test_llm_investigate_parse_failure():
    request = make_request("Test complaint")
    with patch("app.llm_client.OPENROUTER_API_KEY", "sk-test"):
        with patch("app.llm_client.call_llm_with_fallback", return_value="not json"):
            result = await llm_investigate(request)
    assert result is None


@pytest.mark.asyncio
async def test_llm_investigate_success():
    valid_json = json.dumps({
        "ticket_id": "TKT-LLM",
        "relevant_transaction_id": "TXN-001",
        "evidence_verdict": "consistent",
        "case_type": "wrong_transfer",
        "severity": "high",
        "department": "dispute_resolution",
        "agent_summary": "LLM summary.",
        "recommended_next_action": "LLM action.",
        "customer_reply": "LLM reply.",
        "human_review_required": True,
        "confidence": 0.9,
        "reason_codes": ["wrong_transfer"],
    })

    request = make_request("I sent 5000 to wrong number.")
    with patch("app.llm_client.OPENROUTER_API_KEY", "sk-test"):
        with patch("app.llm_client.call_llm_with_fallback", return_value=valid_json):
            result = await llm_investigate(request)
    assert result is not None
    assert result.ticket_id == "TKT-LLM"
    assert result.evidence_verdict == EvidenceVerdict.consistent
    assert result.case_type == CaseType.wrong_transfer
    assert result.confidence == 0.9
    assert result.agent_summary == "LLM summary."


@pytest.mark.asyncio
async def test_call_llm_with_fallback_success_first():
    mock_response = "valid response"
    primary_model = "openai/gpt-4o-mini"

    with patch("app.llm_client.OPENROUTER_API_KEY", "sk-test"):
        with patch("app.llm_client.OPENROUTER_MODEL", primary_model):
            with patch("app.llm_client.call_llm") as mock_call:
                mock_call.return_value = mock_response
                result = await call_llm_with_fallback("test prompt")
    assert result == "valid response"


@pytest.mark.asyncio
async def test_call_llm_with_fallback_all_fail():
    with patch("app.llm_client.OPENROUTER_API_KEY", "sk-test"):
        with patch("app.llm_client.call_llm", return_value=None):
            result = await call_llm_with_fallback("test prompt")
    assert result is None


def test_merge_llm_into_rule():
    from app.investigator import merge_llm_into_rule

    rule_resp = AnalyzeTicketResponse(
        ticket_id="TKT-001",
        relevant_transaction_id="TXN-001",
        evidence_verdict=EvidenceVerdict.consistent,
        case_type=CaseType.wrong_transfer,
        severity=Severity.high,
        department=Department.dispute_resolution,
        agent_summary="Rule summary.",
        recommended_next_action="Rule action.",
        customer_reply="Rule reply.",
        human_review_required=True,
        confidence=0.75,
        reason_codes=["wrong_transfer", "transaction_match"],
    )

    llm_resp = AnalyzeTicketResponse(
        ticket_id="TKT-001",
        relevant_transaction_id="TXN-001",
        evidence_verdict=EvidenceVerdict.consistent,
        case_type=CaseType.wrong_transfer,
        severity=Severity.high,
        department=Department.dispute_resolution,
        agent_summary="LLM summary.",
        recommended_next_action="LLM action.",
        customer_reply="LLM reply.",
        human_review_required=False,
        confidence=0.92,
        reason_codes=["wrong_transfer"],
    )

    merged = merge_llm_into_rule(rule_resp, llm_resp)
    assert merged.agent_summary == "LLM summary."
    assert merged.recommended_next_action == "LLM action."
    assert merged.customer_reply == "LLM reply."
    assert merged.confidence == 0.92
    assert merged.human_review_required is True
    assert "wrong_transfer" in merged.reason_codes
    assert "transaction_match" in merged.reason_codes


def test_merge_llm_into_rule_fallback():
    from app.investigator import merge_llm_into_rule

    rule_resp = AnalyzeTicketResponse(
        ticket_id="TKT-001",
        relevant_transaction_id="TXN-001",
        evidence_verdict=EvidenceVerdict.consistent,
        case_type=CaseType.wrong_transfer,
        severity=Severity.high,
        department=Department.dispute_resolution,
        agent_summary="Rule summary.",
        recommended_next_action="Rule action.",
        customer_reply="Rule reply.",
        human_review_required=True,
        confidence=0.75,
        reason_codes=["wrong_transfer"],
    )

    llm_resp = AnalyzeTicketResponse(
        ticket_id="TKT-001",
        relevant_transaction_id=None,
        evidence_verdict=EvidenceVerdict.insufficient_data,
        case_type=CaseType.other,
        severity=Severity.low,
        department=Department.customer_support,
        agent_summary="",
        recommended_next_action="",
        customer_reply="",
        human_review_required=False,
        confidence=None,
        reason_codes=[],
    )

    merged = merge_llm_into_rule(rule_resp, llm_resp)
    assert merged.evidence_verdict == EvidenceVerdict.consistent
    assert merged.relevant_transaction_id == "TXN-001"
    assert merged.case_type == CaseType.wrong_transfer
    assert merged.agent_summary == "Rule summary."
    assert merged.confidence == 0.75
