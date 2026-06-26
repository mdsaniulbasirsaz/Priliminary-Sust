#!/usr/bin/env python3
"""Validation script: run all 10 sample cases and report structural equivalence.

Usage:
    python3 validate_cases.py [--json]
"""

from __future__ import annotations

import json
import sys

from app.investigator import investigate
from app.schemas import (
    AnalyzeTicketRequest,
    TransactionHistoryEntry,
)

SAMPLE_CASES_PATH = "Sample-Case.json"

SEVERITY_ORDER = ["low", "medium", "high", "critical"]

PASS = "PASS"
FAIL = "FAIL"


def severity_equivalent(actual: str, expected: str) -> bool:
    if actual == expected:
        return True
    if actual in SEVERITY_ORDER and expected in SEVERITY_ORDER:
        return abs(SEVERITY_ORDER.index(actual) - SEVERITY_ORDER.index(expected)) <= 1
    return False


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


def validate_case(case: dict) -> dict:
    cid = case["id"]
    label = case["label"]
    input_data = case["input"]
    exp = case["expected_output"]

    req = make_request(input_data)
    resp = investigate(req)

    checks = {
        "ticket_id": (resp.ticket_id == exp["ticket_id"]),
        "relevant_transaction_id": (
            resp.relevant_transaction_id == exp.get("relevant_transaction_id")
        ),
        "evidence_verdict": (resp.evidence_verdict.value == exp["evidence_verdict"]),
        "case_type": (resp.case_type.value == exp["case_type"]),
        "department": (resp.department.value == exp["department"]),
        "severity": severity_equivalent(resp.severity.value, exp["severity"]),
        "human_review_required": (
            resp.human_review_required == exp["human_review_required"]
        ),
    }

    all_pass = all(checks.values())

    details = {
        "id": cid,
        "label": label,
        "pass": all_pass,
        "fields": {},
    }

    for field, ok in checks.items():
        got = getattr(resp, field, None)
        if field == "evidence_verdict":
            got = resp.evidence_verdict.value
        elif field == "case_type":
            got = resp.case_type.value
        elif field == "department":
            got = resp.department.value
        elif field == "severity":
            got = resp.severity.value

        expected = exp.get(field)
        status = PASS if ok else FAIL
        details["fields"][field] = {
            "status": status,
            "got": got,
            "expected": expected,
        }

    details["confidence"] = {
        "got": resp.confidence,
        "expected": exp.get("confidence"),
    }
    details["reason_codes"] = {
        "got": resp.reason_codes,
        "expected": exp.get("reason_codes"),
    }

    # Safety check on customer_reply
    reply_lower = resp.customer_reply.lower()
    details["safety_checks"] = {
        "has_pin_otp_warning": "otp" in reply_lower or "pin" in reply_lower,
        "no_unauthorized_promise": "will refund" not in reply_lower,
    }

    return details


def main():
    with open(SAMPLE_CASES_PATH) as f:
        data = json.load(f)

    results = [validate_case(case) for case in data["cases"]]

    use_json = "--json" in sys.argv

    if use_json:
        print(json.dumps(results, indent=2, ensure_ascii=False))
        return

    passed = sum(1 for r in results if r["pass"])
    total = len(results)

    print(f"{'='*70}")
    print(f"  Sample Case Validation — {passed}/{total} structural passes")
    print(f"{'='*70}\n")

    for r in results:
        icon = "✓" if r["pass"] else "✗"
        print(f"  {icon} {r['id']}: {r['label']}")
        for field, fd in r["fields"].items():
            status_str = fd["status"]
            if fd["status"] == FAIL:
                print(
                    f"      {field}: {status_str}  got={fd['got']!r}  exp={fd['expected']!r}"
                )
        print(f"      confidence: got={r['confidence']['got']}  exp={r['confidence']['expected']}")
        print(f"      reason_codes: got={r['reason_codes']['got']}")
        print(
            f"      safety: PIN/OTP={'✓' if r['safety_checks']['has_pin_otp_warning'] else '✗'}  no-promise={'✓' if r['safety_checks']['no_unauthorized_promise'] else '✗'}"
        )
        print()

    print(f"{'='*70}")
    if passed == total:
        print("  ALL SAMPLE CASES PASS — structural equivalence confirmed.")
    else:
        print(f"  {total - passed} case(s) have structural failures.")
    print(f"{'='*70}")

    # Exit code
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
