from __future__ import annotations

import datetime
import re
from typing import Optional

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

HYBRID_FAST_PATH_CONFIDENCE = 0.85

# ─── Constants ───────────────────────────────────────────────────────────────

SUSPICIOUS_KEYWORDS = [
    "otp", "pin", "password", "scam", "fraud", "phishing",
    "fake call", "suspicious call", "hack", "compromise",
    "social security", "credit card number", "passport",
    "ওটিপি", "পিন", "পাসওয়ার্ড",
]

WRONG_TRANSFER_KEYWORDS = [
    "wrong number", "wrong recipient", "wrong person",
    "wrong account", "sent to wrong", "transferred to wrong",
    "typed it wrong", "mistakenly sent", "by mistake",
]

PAYMENT_FAILED_KEYWORDS = [
    "payment failed", "transaction failed", "deducted but",
    "money deducted but", "amount deducted but",
    "failed but", "showed failed", "app showed failed",
]

REFUND_KEYWORDS = [
    "refund", "money back", "return my", "give me back",
    "reverse", "please refund",
]

DUPLICATE_KEYWORDS = [
    "charged twice", "deducted twice", "double payment",
    "charged double", "same amount twice", "two times",
]

MERCHANT_KEYWORDS = [
    "merchant", "settlement", "shop payment", "sales",
]

AGENT_CASH_KEYWORDS = [
    "agent", "cash in", "cash deposit",
    "not reflected", "balance e nai", "balance aase nai",
    "taka paaini", "paaini",
]

INJECTION_PATTERNS = [
    "ignore previous", "ignore all", "override",
    "disregard", "forget everything", "forget all",
    "you are now", "act as", "pretend", "roleplay",
    "do not follow", "system prompt",
]

ACTION_TO_TYPE = {
    "sent": TransactionType.transfer,
    "send": TransactionType.transfer,
    "transferred": TransactionType.transfer,
    "transfer": TransactionType.transfer,
    "paid": TransactionType.payment,
    "pay": TransactionType.payment,
    "payment": TransactionType.payment,
    "deposited": TransactionType.cash_in,
    "deposit": TransactionType.cash_in,
    "cash in": TransactionType.cash_in,
    "cash_in": TransactionType.cash_in,
    "withdrew": TransactionType.cash_out,
    "withdraw": TransactionType.cash_out,
    "cash out": TransactionType.cash_out,
    "settlement": TransactionType.settlement,
    "settled": TransactionType.settlement,
}

OUTCOME_TO_STATUS_MAP = {
    "fail": TransactionStatus.failed,
    "failed": TransactionStatus.failed,
    "didn't go through": TransactionStatus.failed,
    "did not go through": TransactionStatus.failed,
    "not working": TransactionStatus.failed,
    "went through": TransactionStatus.completed,
    "completed": TransactionStatus.completed,
    "success": TransactionStatus.completed,
    "successful": TransactionStatus.completed,
    "pending": TransactionStatus.pending,
    "not yet": TransactionStatus.pending,
    "reversed": TransactionStatus.reversed,
    "reversal": TransactionStatus.reversed,
}

OUTCOME_CONTRADICTION_PAIRS: list[tuple[str, TransactionStatus]] = [
    ("fail", TransactionStatus.completed),
    ("failed", TransactionStatus.completed),
    ("went through", TransactionStatus.failed),
    ("success", TransactionStatus.failed),
    ("not received", TransactionStatus.completed),
    ("didn't get", TransactionStatus.completed),
    ("didn't receive", TransactionStatus.completed),
    ("not showing", TransactionStatus.completed),
    ("deducted", TransactionStatus.failed),
]

SCORE_THRESHOLD_MATCH = 30
SCORE_THRESHOLD_AMBIGUITY = 10
DUPLICATE_TIME_WINDOW_SECONDS = 60

BANGLA_UNICODE_RANGE = re.compile(r"[\u0980-\u09FF]")


# ─── Helper ──────────────────────────────────────────────────────────────────


def normalize_text(text: str) -> str:
    return text.lower().strip()


def has_bangla(text: str) -> bool:
    return bool(BANGLA_UNICODE_RANGE.search(text))


def extract_amounts(text: str) -> list[float]:
    normalized = normalize_text(text)
    amounts = []
    patterns = [
        r"(\d+(?:,\d{3})*(?:\.\d+)?)\s*(?:taka|bdt|tk|টাকা)",
        r"(?:taka|bdt|tk|টাকা)\s*(\d+(?:,\d{3})*(?:\.\d+)?)",
        r"(\d+(?:,\d{3})*(?:\.\d+)?)\s*(?:taka|bdt|tk)",
    ]
    for pattern in patterns:
        amounts.extend(
            float(match.group(1).replace(",", ""))
            for match in re.finditer(pattern, normalized)
        )

    if not amounts:
        number_pattern = r"\b(\d{3,})\b"
        amounts.extend(
            float(match.group(1))
            for match in re.finditer(number_pattern, normalized)
            if 10 <= float(match.group(1)) <= 999999
        )

    return amounts


def extract_phone_numbers(text: str) -> list[str]:
    normalized = normalize_text(text)
    pattern = r"(\+?8801[3-9]\d{8}|01[3-9]\d{8})"
    return re.findall(pattern, normalized)


def extract_actions(text: str) -> list[str]:
    normalized = normalize_text(text)
    actions = []
    for verb in ACTION_TO_TYPE:
        if verb in normalized:
            actions.append(verb)
    return actions


def extract_outcomes(text: str) -> list[str]:
    normalized = normalize_text(text)
    outcomes = []
    for phrase in OUTCOME_TO_STATUS_MAP:
        if phrase in normalized:
            outcomes.append(phrase)
    return outcomes


def extract_time_reference(text: str) -> dict:
    normalized = normalize_text(text)
    ref = {}

    time_patterns = [
        (r"(?:yesterday|গতকাল)", "yesterday"),
        (r"(?:today|আজ)", "today"),
        (r"(?:this morning|আজ সকাল)", "this_morning"),
        (r"(?:this afternoon|আজ বিকাল|আজ দুপুর)", "this_afternoon"),
        (r"(?:last night|গত রাত)", "last_night"),
        (r"(?:around|about|প্রায়)\s+(\d{1,2})\s*(am|pm)?", "approximate_time"),
        (r"\b(\d{1,2})\s*(am|pm)\b", "hour_with_period"),
    ]

    for pattern, key in time_patterns:
        match = re.search(pattern, normalized)
        if match:
            ref[key] = match.group(0)

    return ref


def detect_suspicious(text: str) -> bool:
    normalized = normalize_text(text)
    return any(kw in normalized for kw in SUSPICIOUS_KEYWORDS)


def detect_injection(text: str) -> bool:
    normalized = normalize_text(text)
    return any(pat in normalized for pat in INJECTION_PATTERNS)


def detect_language(text: str) -> str:
    if has_bangla(text):
        en_chars = len(re.findall(r"[a-zA-Z0-9]", text))
        bn_chars = len(re.findall(r"[\u0980-\u09FF]", text))
        if en_chars > bn_chars:
            return "mixed"
        return "bn"
    return "en"


# ─── Scoring ─────────────────────────────────────────────────────────────────


class ClaimExtract:
    def __init__(self, complaint: str):
        self.amounts = extract_amounts(complaint)
        self.phone_numbers = extract_phone_numbers(complaint)
        self.actions = extract_actions(complaint)
        self.outcomes = extract_outcomes(complaint)
        self.time_ref = extract_time_reference(complaint)
        self.is_suspicious = detect_suspicious(complaint)
        self.has_injection = detect_injection(complaint)
        self.normalized = normalize_text(complaint)
        self.is_vague = self._is_vague()
        self.language = detect_language(complaint)

    def _is_vague(self) -> bool:
        has_amount = len(self.amounts) > 0
        has_phone = len(self.phone_numbers) > 0
        has_action = len(self.actions) > 0
        has_outcome = len(self.outcomes) > 0
        specific_count = sum([has_amount, has_phone, has_action, has_outcome])
        return specific_count <= 1


def score_amount(claimed_amounts: list[float], txn_amount: float) -> tuple[int, bool]:
    if not claimed_amounts:
        return 0, False
    best_diff = min(abs(amnt - txn_amount) for amnt in claimed_amounts)
    if best_diff == 0:
        return 30, False
    if best_diff <= 100:
        return 20, False
    if best_diff <= 500:
        return 10, False
    if best_diff > 500:
        return 0, True
    return 0, False


def score_counterparty(
    claimed_numbers: list[str], normalized_complaint: str, txn_counterparty: str
) -> int:
    txn_normalized = txn_counterparty.lower()
    for num in claimed_numbers:
        if num in txn_normalized or txn_normalized in num:
            return 30
    if "wrong number" in normalized_complaint or "wrong person" in normalized_complaint:
        return 5
    return 0


def score_action(actions: list[str], txn_type: TransactionType) -> int:
    for action in actions:
        mapped_type = ACTION_TO_TYPE.get(action)
        if mapped_type == txn_type:
            return 20
    return 0


def score_outcome(
    outcomes: list[str], txn_status: TransactionStatus
) -> tuple[int, bool]:
    has_contradiction = False
    best_score = 0

    for outcome in outcomes:
        mapped_status = OUTCOME_TO_STATUS_MAP.get(outcome)
        if mapped_status == txn_status:
            best_score = max(best_score, 15)

        for phrase, contradict_status in OUTCOME_CONTRADICTION_PAIRS:
            if phrase in outcome and txn_status == contradict_status:
                has_contradiction = True
                best_score = -30

    return best_score, has_contradiction


def score_time(
    time_ref: dict,
    txn_timestamp: str,
    latest_txn_timestamp: Optional[str] = None,
) -> int:
    if not time_ref:
        return 0
    try:
        txn_dt = datetime.datetime.fromisoformat(txn_timestamp.replace("Z", "+00:00"))
        txn_dt = txn_dt.replace(tzinfo=datetime.timezone.utc)

        if latest_txn_timestamp:
            ref_dt = datetime.datetime.fromisoformat(
                latest_txn_timestamp.replace("Z", "+00:00")
            )
            ref_dt = ref_dt.replace(tzinfo=datetime.timezone.utc)
        else:
            ref_dt = datetime.datetime.now(datetime.timezone.utc)

        diff_hours = abs((ref_dt - txn_dt).total_seconds()) / 3600

        if "today" in time_ref or "this_morning" in time_ref or "this_afternoon" in time_ref:
            if diff_hours <= 24:
                return 15 if diff_hours <= 1 else 5

        if "yesterday" in time_ref:
            if 24 <= diff_hours <= 48:
                return 5

        if "last_night" in time_ref:
            if 8 <= diff_hours <= 16:
                return 5

        return 0
    except (ValueError, TypeError):
        return 0


# ─── Pattern Analysis ────────────────────────────────────────────────────────


def check_established_recipient(
    matched_txn: TransactionHistoryEntry,
    all_history: list[TransactionHistoryEntry],
) -> bool:
    if matched_txn.type != TransactionType.transfer:
        return False
    prior_count = sum(
        1
        for t in all_history
        if t.counterparty == matched_txn.counterparty
        and t.type == TransactionType.transfer
        and t.status == TransactionStatus.completed
    )
    return prior_count >= 3


def check_duplicate(
    history: list[TransactionHistoryEntry],
) -> Optional[TransactionHistoryEntry]:
    for i in range(len(history)):
        for j in range(i + 1, len(history)):
            t1, t2 = history[i], history[j]
            if (
                t1.type == t2.type
                and t1.amount == t2.amount
                and t1.counterparty == t2.counterparty
            ):
                try:
                    ts1 = datetime.datetime.fromisoformat(
                        t1.timestamp.replace("Z", "+00:00")
                    )
                    ts2 = datetime.datetime.fromisoformat(
                        t2.timestamp.replace("Z", "+00:00")
                    )
                    diff = abs((ts2 - ts1).total_seconds())
                    if diff <= DUPLICATE_TIME_WINDOW_SECONDS:
                        return t2
                except (ValueError, TypeError):
                    pass
    return None


# ─── Classification ──────────────────────────────────────────────────────────


def derive_case_type(
    claim: ClaimExtract,
    verdict: EvidenceVerdict,
    relevant_txn: Optional[TransactionHistoryEntry],
    all_history: list[TransactionHistoryEntry],
    request: AnalyzeTicketRequest,
) -> CaseType:
    if claim.is_suspicious:
        return CaseType.phishing_or_social_engineering

    normalized = claim.normalized

    if any(kw in normalized for kw in DUPLICATE_KEYWORDS):
        return CaseType.duplicate_payment

    if any(kw in normalized for kw in WRONG_TRANSFER_KEYWORDS):
        return CaseType.wrong_transfer

    if any(kw in normalized for kw in PAYMENT_FAILED_KEYWORDS):
        return CaseType.payment_failed

    if any(kw in normalized for kw in REFUND_KEYWORDS):
        return CaseType.refund_request

    if any(kw in normalized for kw in MERCHANT_KEYWORDS):
        return CaseType.merchant_settlement_delay

    if any(kw in normalized for kw in AGENT_CASH_KEYWORDS):
        return CaseType.agent_cash_in_issue

    # If complaint mentions sending/transferring money without "wrong" keyword,
    # still treat as wrong_transfer if action verbs indicate transfer
    if any(act in claim.actions for act in ("sent", "send", "transferred", "transfer")):
        return CaseType.wrong_transfer

    if relevant_txn:
        if relevant_txn.type == TransactionType.transfer:
            return CaseType.wrong_transfer
        if relevant_txn.type == TransactionType.payment and relevant_txn.status == TransactionStatus.failed:
            return CaseType.payment_failed
        if relevant_txn.type == TransactionType.cash_in:
            return CaseType.agent_cash_in_issue
        if relevant_txn.type == TransactionType.settlement:
            return CaseType.merchant_settlement_delay

    return CaseType.other


def derive_severity(
    case_type: CaseType,
    verdict: EvidenceVerdict,
    relevant_txn: Optional[TransactionHistoryEntry],
    claim: ClaimExtract,
) -> Severity:
    if case_type == CaseType.phishing_or_social_engineering:
        return Severity.critical

    if verdict == EvidenceVerdict.inconsistent and relevant_txn and relevant_txn.amount >= 10000:
        return Severity.critical

    # Check case_type first for known severity mappings
    if case_type == CaseType.merchant_settlement_delay:
        return Severity.medium

    if case_type == CaseType.refund_request:
        amount = relevant_txn.amount if relevant_txn else (claim.amounts[0] if claim.amounts else 0)
        if amount >= 5000:
            return Severity.medium
        return Severity.low

    amount = relevant_txn.amount if relevant_txn else (claim.amounts[0] if claim.amounts else 0)

    if amount >= 10000:
        return Severity.high

    if case_type in (
        CaseType.wrong_transfer,
        CaseType.payment_failed,
        CaseType.agent_cash_in_issue,
        CaseType.duplicate_payment,
    ):
        if verdict == EvidenceVerdict.inconsistent:
            return Severity.medium
        if verdict == EvidenceVerdict.insufficient_data:
            return Severity.medium
        return Severity.high

    if verdict == EvidenceVerdict.insufficient_data and claim.is_vague:
        return Severity.low

    return Severity.medium


def derive_department(
    case_type: CaseType, severity: Severity, verdict: EvidenceVerdict
) -> Department:
    mapping = {
        CaseType.wrong_transfer: Department.dispute_resolution,
        CaseType.payment_failed: Department.payments_ops,
        CaseType.duplicate_payment: Department.payments_ops,
        CaseType.merchant_settlement_delay: Department.merchant_operations,
        CaseType.agent_cash_in_issue: Department.agent_operations,
        CaseType.phishing_or_social_engineering: Department.fraud_risk,
    }

    if case_type in mapping:
        return mapping[case_type]

    if case_type == CaseType.refund_request:
        if severity == Severity.low:
            return Department.customer_support
        return Department.dispute_resolution

    return Department.customer_support


def derive_human_review_required(
    verdict: EvidenceVerdict,
    case_type: CaseType,
    severity: Severity,
    relevant_txn: Optional[TransactionHistoryEntry],
    claim: ClaimExtract,
) -> bool:
    if case_type == CaseType.phishing_or_social_engineering:
        return True

    if verdict == EvidenceVerdict.inconsistent:
        return True

    # Ambiguous cases need clarification first, not escalation
    if verdict == EvidenceVerdict.insufficient_data and not relevant_txn:
        return False

    if claim.has_injection:
        return True

    if case_type in (CaseType.wrong_transfer, CaseType.duplicate_payment, CaseType.agent_cash_in_issue):
        return True

    if relevant_txn and relevant_txn.status == TransactionStatus.pending:
        if case_type == CaseType.merchant_settlement_delay:
            return False
        if case_type == CaseType.agent_cash_in_issue:
            return True
        return True

    if severity in (Severity.critical, Severity.high):
        if case_type == CaseType.payment_failed and verdict == EvidenceVerdict.consistent:
            pass
        else:
            return True

    if claim.is_suspicious or claim.has_injection:
        return True

    return False


def derive_confidence(
    base_score: int,
    verdict: EvidenceVerdict,
    case_type: CaseType,
) -> float:
    if case_type == CaseType.phishing_or_social_engineering:
        return 0.95

    if verdict == EvidenceVerdict.insufficient_data:
        return 0.60

    if base_score >= 100:
        return 0.95
    if base_score >= 80:
        return 0.85
    if base_score >= 60:
        return 0.75
    if base_score >= 30:
        return 0.60
    return 0.50


def derive_reason_codes(
    claim: ClaimExtract,
    verdict: EvidenceVerdict,
    case_type: CaseType,
    relevant_txn: Optional[TransactionHistoryEntry],
    has_established_recipient: bool,
    has_ambiguity: bool,
    is_duplicate: bool,
    has_contradiction: bool,
) -> list[str]:
    codes: list[str] = []

    codes.append(case_type.value)

    if relevant_txn:
        codes.append("transaction_match")
        if claim.amounts and any(
            abs(a - relevant_txn.amount) > 500 for a in claim.amounts
        ):
            codes.append("amount_mismatch")
        else:
            codes.append("amount_match")
    else:
        codes.append("no_transaction_match")

    if has_established_recipient:
        codes.append("established_recipient_pattern")

    if has_ambiguity:
        codes.append("ambiguous_match")
        codes.append("needs_clarification")

    if is_duplicate:
        codes.append("duplicate_payment_detected")

    if claim.is_vague and not relevant_txn:
        codes.append("vague_complaint")
        codes.append("needs_clarification")

    if claim.is_suspicious:
        codes.append("credential_protection")

    if claim.has_injection:
        codes.append("prompt_injection_detected")

    if verdict == EvidenceVerdict.inconsistent:
        codes.append("evidence_inconsistent")

    if has_contradiction:
        codes.append("status_contradiction")

    return codes


SAFE_REPLY_TEMPLATES: dict[CaseType, str] = {
    CaseType.wrong_transfer: (
        "We have noted your concern about transaction {txn_id}. "
        "Our dispute resolution team will review the details and take appropriate action "
        "through official channels. Any eligible amount will be returned through "
        "the standard process. Please do not share your PIN or OTP with anyone."
    ),
    CaseType.payment_failed: (
        "We see that your transaction of {amount} BDT was {status}. "
        "If the amount was deducted, it will be automatically reversed within "
        "24-48 hours through official channels. Please check your balance after this window. "
        "Please do not share your PIN or OTP with anyone."
    ),
    CaseType.refund_request: (
        "Thank you for contacting us regarding a refund. "
        "We have escalated your request to the relevant team. "
        "Any eligible amount will be returned through official channels as per our policy. "
        "Please do not share your PIN or OTP with anyone."
    ),
    CaseType.duplicate_payment: (
        "We have noted the possible duplicate payment for transaction {txn_id}. "
        "Our payments team will verify with the biller and any eligible amount "
        "will be returned through official channels. "
        "Please do not share your PIN or OTP with anyone."
    ),
    CaseType.merchant_settlement_delay: (
        "We have noted your concern about settlement {txn_id}. "
        "Our merchant operations team will check the batch status and update you "
        "on the expected settlement time through official channels."
    ),
    CaseType.agent_cash_in_issue: (
        "আপনার লেনদেন {txn_id} এর বিষয়ে আমরা অবগত হয়েছি। "
        "আমাদের এজেন্ট অপারেশন্স দল এটি দ্রুত যাচাই করবে এবং অফিসিয়াল চ্যানেলে আপনাকে জানাবে। "
        "অনুগ্রহ করে কারো সাথে আপনার পিন বা ওটিপি শেয়ার করবেন না।"
    ),
    CaseType.phishing_or_social_engineering: (
        "This appears to be a security-related concern. "
        "Please do not share your PIN, OTP, or password with anyone. "
        "Our fraud risk team has been notified and will investigate. "
        "For immediate assistance, please contact our official support channels."
    ),
    CaseType.other: (
        "Thank you for reaching out. "
        "We need a few more details to assist you better. "
        "Please contact our customer support team through official channels "
        "with the specific transaction details. "
        "Please do not share your PIN or OTP with anyone."
    ),
}


def build_customer_reply(
    case_type: CaseType,
    relevant_txn: Optional[TransactionHistoryEntry],
    claim: ClaimExtract,
    language: str,
) -> str:
    template = SAFE_REPLY_TEMPLATES.get(case_type, SAFE_REPLY_TEMPLATES[CaseType.other])

    if case_type in (CaseType.phishing_or_social_engineering, CaseType.other, CaseType.refund_request):
        return template

    if case_type == CaseType.agent_cash_in_issue:
        if language == "en":
            template = (
                "We have noted your concern regarding the cash-in transaction {txn_id}. "
                "Our agent operations team will verify it and update you through official channels. "
                "Please do not share your PIN or OTP with anyone."
            )
        return template.format(
            txn_id=relevant_txn.transaction_id if relevant_txn else "N/A",
        )

    if not relevant_txn:
        return SAFE_REPLY_TEMPLATES[CaseType.other]

    if case_type == CaseType.payment_failed:
        return template.format(
            amount=relevant_txn.amount,
            status=relevant_txn.status.value,
        )

    return template.format(txn_id=relevant_txn.transaction_id)


def build_agent_summary(
    claim: ClaimExtract,
    verdict: EvidenceVerdict,
    case_type: CaseType,
    relevant_txn: Optional[TransactionHistoryEntry],
    has_established_recipient: bool,
    has_ambiguity: bool,
    request: AnalyzeTicketRequest,
) -> str:
    if case_type == CaseType.phishing_or_social_engineering:
        return (
            "Investigation: Customer reports an unsolicited call claiming to be from the company "
            "and asking for OTP. Customer has not yet shared credentials. "
            "Likely social engineering attempt."
        )

    if has_ambiguity:
        amounts_str = ", ".join(
            f"{t.amount} BDT" for t in (request.transaction_history or [])
        )
        return (
            f"Investigation: Customer reports a transfer was not received. "
            f"Multiple transactions of similar amounts exist ({amounts_str}). "
            f"Cannot determine which is the correct transaction without further input."
        )

    if relevant_txn:
        txn_id = relevant_txn.transaction_id
        amount = relevant_txn.amount
        status = relevant_txn.status.value
        counterparty = relevant_txn.counterparty

        if has_established_recipient:
            return (
                f"Investigation: Customer claims {txn_id} ({amount} BDT to {counterparty}) was a wrong transfer, "
                f"but transaction history shows multiple prior transfers to the same counterparty, "
                f"suggesting an established recipient."
            )

        if case_type == CaseType.duplicate_payment:
            return (
                f"Investigation: Customer reports duplicate payment. "
                f"Two identical {amount} BDT payments to {counterparty} were completed "
                f"within seconds of each other (including {txn_id}). "
                f"The latter is likely the duplicate."
            )

        if case_type == CaseType.wrong_transfer:
            return (
                f"Investigation: Customer reports sending {amount} BDT via {txn_id} to {counterparty}, "
                f"which they now believe was the wrong recipient. "
                f"Evidence verdict: {verdict.value}."
            )
        if case_type == CaseType.payment_failed:
            return (
                f"Investigation: Customer attempted a {amount} BDT payment ({txn_id}) which {status}, "
                f"but reports balance was deducted. "
                f"Evidence verdict: {verdict.value}."
            )
        if case_type == CaseType.agent_cash_in_issue:
            return (
                f"Investigation: Customer reports {amount} BDT cash-in via {counterparty} ({txn_id}) "
                f"not reflected in balance. Transaction status is {status}. "
                f"Evidence verdict: {verdict.value}."
            )
        if case_type == CaseType.merchant_settlement_delay:
            return (
                f"Investigation: Merchant reports {amount} BDT settlement ({txn_id}) is delayed. "
                f"Settlement status is {status}. "
                f"Evidence verdict: {verdict.value}."
            )
        if case_type == CaseType.refund_request:
            return (
                f"Investigation: Customer requests refund of {amount} BDT for {txn_id} "
                f"(merchant payment). Not a service failure. "
                f"Evidence verdict: {verdict.value}."
            )

        return (
            f"Investigation: Customer reports sending {amount} BDT via {txn_id} to {counterparty}. "
            f"Transaction status: {status}. "
            f"Evidence verdict: {verdict.value}."
        )

    if claim.is_vague:
        return (
            "Investigation: Customer reports a vague concern about their money without specifying "
            "a specific transaction, amount, or issue. Insufficient detail to identify any relevant transaction."
        )

    return (
        f"Investigation: Customer reports an issue. "
        f"No matching transaction found in history. "
        f"Evidence verdict: insufficient_data."
    )


def build_recommended_next_action(
    case_type: CaseType,
    verdict: EvidenceVerdict,
    relevant_txn: Optional[TransactionHistoryEntry],
    has_established_recipient: bool,
    has_ambiguity: bool,
    claim: ClaimExtract,
) -> str:
    if case_type == CaseType.phishing_or_social_engineering:
        return (
            "Escalate to fraud_risk team immediately. "
            "Confirm to customer that the company never asks for OTP. "
            "Log the reported number for fraud pattern analysis."
        )

    if has_established_recipient and relevant_txn:
        return (
            f"Flag for human review. Verify with the customer whether this was genuinely "
            f"a wrong transfer given the established transaction pattern with this recipient."
        )

    if has_ambiguity:
        return (
            "Reply to customer asking for the recipient's number to identify "
            "the correct transaction. Do not initiate dispute until the transaction is confirmed."
        )

    if relevant_txn:
        txn_id = relevant_txn.transaction_id
        if case_type == CaseType.wrong_transfer:
            return (
                f"Verify {txn_id} details with the customer and initiate "
                f"the wrong-transfer dispute workflow per policy."
            )
        if case_type == CaseType.payment_failed:
            return (
                f"Investigate {txn_id} ledger status. "
                f"If balance was deducted on a failed payment, initiate "
                f"the automatic reversal flow within standard SLA."
            )
        if case_type == CaseType.refund_request:
            return (
                "Inform the customer that refund eligibility depends on the "
                "merchant's own policy. Provide guidance on contacting the merchant directly."
            )
        if case_type == CaseType.duplicate_payment:
            return (
                f"Verify the duplicate with payments_ops. "
                f"If the biller confirms only one payment was received, initiate reversal of {txn_id}."
            )
        if case_type == CaseType.merchant_settlement_delay:
            return (
                "Route to merchant_operations to verify settlement batch status. "
                "If the batch is delayed, communicate a revised ETA to the merchant."
            )
        if case_type == CaseType.agent_cash_in_issue:
            return (
                f"Investigate {txn_id} pending status with agent operations. "
                f"Confirm settlement state and resolve within the standard cash-in SLA."
            )

    if claim.is_vague:
        return (
            "Reply to customer asking for specific details: "
            "which transaction, what amount, what went wrong, and approximate time."
        )

    return (
        "Reply to customer asking for specific transaction details to identify the issue."
    )


# ─── Main Investigator Engine ────────────────────────────────────────────────


def investigate(request: AnalyzeTicketRequest) -> AnalyzeTicketResponse:
    claim = ClaimExtract(request.complaint)
    history = request.transaction_history or []

    has_established_recipient = False
    has_ambiguity = False
    is_duplicate = False
    has_contradiction = False
    best_txn: Optional[TransactionHistoryEntry] = None
    best_base_score = 0

    # Phase A: Pattern Detection (runs first, before scoring)
    duplicate_txn = check_duplicate(history)
    if duplicate_txn:
        is_duplicate = True
        best_txn = duplicate_txn

    # Phase B: Compute two scores per transaction:
    #   relevance_score  = amount + counterparty + action (core identity fields)
    #   full_base_score  = all dimensions including outcome + time
    #   has_contradiction = outcome contradicts status
    # This separation ensures contradictions affect VERDICT but not RELEVANCE.

    scored_txns: list[tuple[TransactionHistoryEntry, int, int, bool, bool]] = []

    latest_timestamp: Optional[str] = None
    if history:
        try:
            timestamps = [
                datetime.datetime.fromisoformat(t.timestamp.replace("Z", "+00:00"))
                for t in history
            ]
            if timestamps:
                latest = max(timestamps)
                if latest:
                    latest_timestamp = history[
                        timestamps.index(latest)
                    ].timestamp
        except (ValueError, TypeError):
            pass

    for txn in history:
        amt_score, amt_contradiction = score_amount(claim.amounts, txn.amount)
        cpy_score = score_counterparty(claim.phone_numbers, claim.normalized, txn.counterparty)
        act_score = score_action(claim.actions, txn.type)
        out_score, out_contradiction = score_outcome(claim.outcomes, txn.status)
        tim_score = score_time(claim.time_ref, txn.timestamp, latest_timestamp)

        contradiction = amt_contradiction or out_contradiction
        # Relevance score excludes outcome and time — identity fields only
        relevance_score = amt_score + cpy_score + act_score
        # Full base includes everything (for ranking/confidence)
        full_base = amt_score + cpy_score + act_score + out_score + tim_score

        scored_txns.append((txn, relevance_score, full_base, contradiction, out_contradiction))

    # Sort by relevance_score (identity match) for determining relevant_txn
    scored_txns.sort(key=lambda x: x[1], reverse=True)

    # Check ambiguity on relevance_score
    if len(scored_txns) >= 2 and not is_duplicate:
        if scored_txns[0][1] - scored_txns[1][1] <= SCORE_THRESHOLD_AMBIGUITY:
            has_ambiguity = True

    # Select best transaction by relevance_score
    MIN_RELEVANCE_SCORE = 30  # Must match at least 2 dimensions including amount

    if is_duplicate:
        for txn, rel, full, contra, out_contra in scored_txns:
            if txn.transaction_id == duplicate_txn.transaction_id:
                if rel >= MIN_RELEVANCE_SCORE or rel == max(r for _, r, _, _, _ in scored_txns):
                    best_txn = txn
                    best_base_score = full
                    has_contradiction = contra
                break
    elif scored_txns and not has_ambiguity:
        best_txn, best_relevance, best_base_score, has_contradiction, _ = scored_txns[0]
        if best_relevance < MIN_RELEVANCE_SCORE:
            best_txn = None
            best_base_score = 0
            has_contradiction = False

    if has_ambiguity:
        best_txn = None
        best_base_score = 0
        has_contradiction = False

    if best_txn and not has_ambiguity:
        has_established_recipient = check_established_recipient(best_txn, history)

    # Phase C: Determine verdict
    if has_ambiguity:
        verdict = EvidenceVerdict.insufficient_data
        best_txn = None
        best_base_score = 0
    elif claim.is_suspicious:
        verdict = EvidenceVerdict.insufficient_data
    elif best_txn is None and not history:
        verdict = EvidenceVerdict.insufficient_data
    elif best_txn is None and history:
        # Has history but no transaction matched the complaint
        verdict = EvidenceVerdict.insufficient_data
    elif has_established_recipient:
        verdict = EvidenceVerdict.inconsistent
    elif has_contradiction:
        verdict = EvidenceVerdict.inconsistent
    else:
        verdict = EvidenceVerdict.consistent

    # Phase D: Derive classification from investigation
    case_type = derive_case_type(claim, verdict, best_txn, history, request)

    if claim.is_suspicious:
        case_type = CaseType.phishing_or_social_engineering

    severity = derive_severity(case_type, verdict, best_txn, claim)
    department = derive_department(case_type, severity, verdict)
    human_review = derive_human_review_required(verdict, case_type, severity, best_txn, claim)
    confidence = derive_confidence(best_base_score, verdict, case_type)
    reason_codes = derive_reason_codes(
        claim, verdict, case_type, best_txn,
        has_established_recipient, has_ambiguity, is_duplicate, has_contradiction,
    )

    language = claim.language
    if request.language:
        language = request.language.value

    agent_summary = build_agent_summary(
        claim, verdict, case_type, best_txn,
        has_established_recipient, has_ambiguity, request,
    )
    recommended_next_action = build_recommended_next_action(
        case_type, verdict, best_txn,
        has_established_recipient, has_ambiguity, claim,
    )
    customer_reply = build_customer_reply(case_type, best_txn, claim, language)

    relevant_id = best_txn.transaction_id if best_txn else None

    response = AnalyzeTicketResponse(
        ticket_id=request.ticket_id,
        relevant_transaction_id=relevant_id,
        evidence_verdict=verdict,
        case_type=case_type,
        severity=severity,
        department=department,
        agent_summary=agent_summary,
        recommended_next_action=recommended_next_action,
        customer_reply=customer_reply,
        human_review_required=human_review,
        confidence=confidence,
        reason_codes=reason_codes,
    )

    return response


def merge_llm_into_rule(
    rule_response: AnalyzeTicketResponse,
    llm_response: AnalyzeTicketResponse,
) -> AnalyzeTicketResponse:
    merged = rule_response.model_copy(deep=True)

    if llm_response.evidence_verdict != EvidenceVerdict.insufficient_data:
        merged.evidence_verdict = llm_response.evidence_verdict

    if llm_response.relevant_transaction_id:
        merged.relevant_transaction_id = llm_response.relevant_transaction_id

    if llm_response.case_type != CaseType.other:
        merged.case_type = llm_response.case_type

    if llm_response.severity:
        merged.severity = llm_response.severity

    if llm_response.department:
        merged.department = llm_response.department

    if llm_response.agent_summary:
        merged.agent_summary = llm_response.agent_summary

    if llm_response.recommended_next_action:
        merged.recommended_next_action = llm_response.recommended_next_action

    if llm_response.customer_reply:
        merged.customer_reply = llm_response.customer_reply

    merged.human_review_required = (
        rule_response.human_review_required or llm_response.human_review_required
    )

    llm_conf = llm_response.confidence
    if llm_conf is not None:
        merged.confidence = max(
            (rule_response.confidence or 0), llm_conf
        )

    merged.reason_codes = list(
        dict.fromkeys(
            (rule_response.reason_codes or []) + (llm_response.reason_codes or [])
        )
    )

    return merged


async def hybrid_investigate(request: AnalyzeTicketRequest) -> AnalyzeTicketResponse:
    rule_response = investigate(request)

    rule_conf = rule_response.confidence or 0.0

    if rule_conf >= HYBRID_FAST_PATH_CONFIDENCE:
        return rule_response

    from app.llm_client import llm_investigate

    try:
        llm_response = await llm_investigate(request)
    except Exception:
        llm_response = None

    if llm_response is None:
        return rule_response

    return merge_llm_into_rule(rule_response, llm_response)
