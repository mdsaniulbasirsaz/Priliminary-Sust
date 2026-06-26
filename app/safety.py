from __future__ import annotations

import re

from app.schemas import (
    AnalyzeTicketRequest,
    AnalyzeTicketResponse,
    CaseType,
)

# ═══════════════════════════════════════════════════════════════════════════════
# Phase 2 — Triple-Layer Safety Guardrails
# ═══════════════════════════════════════════════════════════════════════════════

# ── Layer 1: Input Scanner — Detect adversarial/prompt injection in complaint ─


PROMPT_INJECTION_PATTERNS = re.compile(
    r"\b(?:"
    r"ignore\s+(?:previous|all|above|instructions|your\s+protocol)|"
    r"override|disregard|forget\s+(?:everything|all|previous)|"
    r"new\s+instructions|you\s+are\s+now|act\s+as|"
    r"pretend|roleplay|do\s+not\s+follow|"
    r"system\s+prompt|you're\s+now|you are now|"
    r"you\s+must\s+ignore|never\s+mind|stop\s+following|"
    r"forget\s+your\s+(?:previous|old)\s+instructions"
    r")\b",
    re.IGNORECASE,
)


def layer1_scan_input(complaint: str) -> bool:
    return bool(PROMPT_INJECTION_PATTERNS.search(complaint))


# ── Layer 2: Decision Guard — Check authorization before building response ────

# Case types where the system CANNOT autonomously approve the action
REQUIRES_AUTHORIZATION: set[CaseType] = {
    CaseType.refund_request,
    CaseType.wrong_transfer,
    CaseType.duplicate_payment,
    CaseType.agent_cash_in_issue,
}

# Case types that must ALWAYS escalate
MUST_ESCALATE: set[CaseType] = {
    CaseType.phishing_or_social_engineering,
}

# Phrases that constitute unauthorized promises (must NOT appear)
UNAUTHORIZED_PROMISE_PATTERNS = re.compile(
    r"\b(?:"
    r"will\s+refund|we\s+will\s+reverse|we\s+will\s+cancel|"
    r"we\s+will\s+reset|we\s+guarantee|we\s+promise|"
    r"we'll\s+refund|we'll\s+reverse|we'll\s+cancel|"
    r"definitely\s+refund|absolutely\s+refund|"
    r"will\s+return\s+(?:your\s+)?money|will\s+give\s+back"
    r")\b",
    re.IGNORECASE,
)


def layer2_check_authorization(
    response: AnalyzeTicketResponse,
) -> list[str]:
    violations: list[str] = []

    case_type = response.case_type

    if case_type in MUST_ESCALATE:
        if not response.human_review_required:
            violations.append("escalation_required_but_not_set")

    if case_type in REQUIRES_AUTHORIZATION:
        if scan_for_unauthorized_promise(response.customer_reply):
            violations.append("unauthorized_promise_in_customer_reply")
        if scan_for_unauthorized_promise(response.recommended_next_action):
            violations.append("unauthorized_promise_in_recommended_action")

    if case_type in (CaseType.phishing_or_social_engineering,):
        if scan_for_credential_request(response.customer_reply):
            violations.append("credential_request_phishing_reply")

    return violations


# ── Layer 3: Output Filter — Post-process generated text ─────────────────────

CREDENTIAL_REQUEST_PATTERNS = re.compile(
    r"(?:"
    r"(?:please|kindly|pls)\s+(?:share|provide|send|give|enter|submit)\s+(?:your|the|ur)\s+(?:"
    r"otp|pin|password|credit\s*card|account\s*(?:number|no|pin)|"
    r"cvv|ssn|passport\s*(?:number|no)"
    r")|"
    r"(?:share|provide|send|give|enter|submit)\s+(?:your|the|ur)\s+(?:"
    r"otp|pin|password|credit\s*card"
    r")|"
    r"(?:share|provide|send|give|enter|submit)\s+(?:me|us)\s+(?:your|the|ur)\s+(?:"
    r"otp|pin|password|credit\s*card"
    r")|"
    r"(?:what'?s?\s+(?:your|the|ur)\s+(?:otp|pin|password))|"
    r"(?:tell\s+(?:us|me)\s+(?:your|the|ur)\s+(?:otp|pin|password))"
    r")",
    re.IGNORECASE,
)

THIRD_PARTY_REDIRECT_PATTERNS = re.compile(
    r"(?:"
    r"contact\s+(?:this\s+)?number|call\s+(?:this\s+)?number|"
    r"reach\s+out\s+to\s+(?!official|our|the\s+official)|"
    r"get\s+in\s+touch\s+with\s+(?!official|our|the\s+official)|"
    r"contact\s+.*?(?:outside|third.?party|unofficial|private)"
    r")",
    re.IGNORECASE,
)

BANGLA_CREDENTIAL_REQUEST = re.compile(
    r"(?:"
    r"(?:আমাকে|আমার)\s*(?:দিন|দাও|বল|পাঠান|শেয়ার)\s+(?:আপনার|তোমার)\s+(?:পিন|ওটিপি|পাসওয়ার্ড)|"
    r"(?:পিন|ওটিপি|পাসওয়ার্ড)\s*(?:দিন|দাও|বলুন|পাঠান|শেয়ার\s+করুন)"
    r")",
    re.IGNORECASE,
)


def scan_for_credential_request(text: str) -> bool:
    for match in CREDENTIAL_REQUEST_PATTERNS.finditer(text):
        before = text[max(0, match.start() - 20): match.start()]
        if re.search(
            r"(?:do\s+not|don't|never|should\s+not|shouldn't|must\s+not|"
            r"never\s+share|do\s+not\s+share|should\s+not\s+share)",
            before,
            re.IGNORECASE,
        ):
            continue
        return True
    if BANGLA_CREDENTIAL_REQUEST.search(text):
        before_neg = text[:50]
        if any(
            neg in before_neg.lower()
            for neg in ["শেয়ার করবেন না", "বলবেন না", "দিন না"]
        ):
            return False
        return True
    return False


def scan_for_unauthorized_promise(text: str) -> bool:
    return bool(UNAUTHORIZED_PROMISE_PATTERNS.search(text))


def scan_for_third_party_redirect(text: str) -> bool:
    return bool(THIRD_PARTY_REDIRECT_PATTERNS.search(text))


SAFE_CUSTOMER_REPLY_FALLBACK = (
    "Thank you for reaching out. Our team will review your case "
    "and any eligible amount will be returned through official channels. "
    "Please do not share your PIN or OTP with anyone."
)

SAFE_CUSTOMER_REPLY_BANGLA = (
    "আমাদের সাথে যোগাযোগ করার জন্য ধন্যবাদ। আমাদের টিম আপনার কেস"
    "পর্যালোচনা করবে এবং ফেরত দেওয়া হবে। "
    "অনুগ্রহ করে কারো সাথে আপনার পিন বা ওটিপি শেয়ার করবেন না।"
)


_BANGLA_PATTERN = re.compile(r"[\u0980-\u09FF]")


def _get_fallback_for_language(request: AnalyzeTicketRequest) -> str:
    lang = "en"
    if request.language:
        lang = request.language.value
    if lang == "bn":
        return SAFE_CUSTOMER_REPLY_BANGLA
    if _BANGLA_PATTERN.search(request.complaint):
        return SAFE_CUSTOMER_REPLY_BANGLA
    return SAFE_CUSTOMER_REPLY_FALLBACK


def layer3_filter_output(
    response: AnalyzeTicketResponse,
    request: AnalyzeTicketRequest,
) -> AnalyzeTicketResponse:
    resp = response.model_copy(deep=True)
    fallback = _get_fallback_for_language(request)

    if scan_for_credential_request(resp.customer_reply):
        resp.customer_reply = fallback

    if scan_for_unauthorized_promise(resp.customer_reply):
        resp.customer_reply = fallback

    if scan_for_third_party_redirect(resp.customer_reply):
        resp.customer_reply = fallback

    if scan_for_unauthorized_promise(resp.recommended_next_action):
        resp.recommended_next_action = (
            "Review the case details and take appropriate action through official channels."
        )

    return resp


# ═══════════════════════════════════════════════════════════════════════════════
# Combined Safety Pipeline
# ═══════════════════════════════════════════════════════════════════════════════


def apply_safety(
    request: AnalyzeTicketRequest,
    response: AnalyzeTicketResponse,
) -> AnalyzeTicketResponse:
    resp = response.model_copy(deep=True)

    # ── Layer 1: Input Scan ──
    if layer1_scan_input(request.complaint):
        resp.human_review_required = True
        current = resp.reason_codes or []
        if "prompt_injection_detected" not in current:
            resp.reason_codes = current + ["prompt_injection_detected"]

    # ── Layer 2: Decision Guard ──
    fallback = _get_fallback_for_language(request)
    violations = layer2_check_authorization(resp)
    for violation in violations:
        if violation == "unauthorized_promise_in_customer_reply":
            resp.customer_reply = fallback
        if violation == "unauthorized_promise_in_recommended_action":
            resp.recommended_next_action = (
                "Review the case details and take appropriate action through official channels."
            )
        if violation == "escalation_required_but_not_set":
            resp.human_review_required = True
        if "credential_request" in violation:
            resp.customer_reply = fallback
        current = resp.reason_codes or []
        if violation not in current:
            resp.reason_codes = current + [violation]

    # ── Layer 3: Output Filter ──
    resp = layer3_filter_output(resp, request)

    return resp
