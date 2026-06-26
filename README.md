# QueueStorm Investigator — AI/API SupportOps Challenge

Live API Docs: https://priliminary-sust.onrender.com/docs

A **complaint investigation** service for the SUST CSE Carnival 2026 Codex Community Hackathon. It is a **complaint investigator** that cross-references customer claims against transaction history to determine what is true.

---


## Architecture

```
Request (POST /analyze-ticket)
  │
  ├── Pydantic Validation
  │
  ├── Rule-Based Investigator Engine (always runs first)
  │     ├── Extract Claims (amount, counterparty, action, outcome, time)
  │     ├── Score Transactions (deterministic matching)
  │     ├── Cross-Transaction Pattern Analysis
  │     │     ├── Established Recipient Detection
  │     │     ├── Ambiguity Detection
  │     │     └── Duplicate Detection
  │     ├── Determine Evidence Verdict (PRIMARY)
  │     ├── Derive Classification (DERIVED)
  │     └── Build Response (agent_summary, customer_reply, etc.)
  │
  ├── Fast Path? (confidence >= 0.85) ──► Return response
  │
  └── LLM Enhancement (low-confidence/complex cases)
        ├── qwen/qwen3-next-80b-a3b-instruct:free (primary)
        ├── qwen/qwen3-next-80b-a3b-instruct:free (fallback)
        └── Rule-based fallback (if LLM unavailable)
              │
              └── Triple-Layer Safety Guardrails
                    ├── Layer 1: Input Scanner (prompt injection)
                    ├── Layer 2: Decision Guard (authorization)
                    └── Layer 3: Output Filter (credential/promise safety)
                          │
                          └── JSON Response
```

---

## Setup & Run

### Prerequisites
- Python 3.11+ or Docker
- OpenRouter API key (for LLM enhancement)

### Local Development

```bash
# Clone and install
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env and add your OPENROUTER_API_KEY

# Run server
uvicorn app.main:app --host 0.0.0.0 --port 8000

# Health check
curl http://localhost:8000/health
# → {"status":"ok"}
```

### Docker

```bash
# Build image
docker build -t supportops-investigator .

# Run container
docker run -p 8000:8000 --env-file .env supportops-investigator

# Or use docker-compose
docker compose up --build
```

---

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `OPENROUTER_API_KEY` | No* | `""` | OpenRouter API key for LLM enhancement |
| `OPENROUTER_MODEL` | No | `openai/gpt-4o-mini` | Primary LLM model |
| `PORT` | No | `8000` | Server port |
| `LLM_TIMEOUT` | No | `25` | LLM request timeout in seconds |
| `LLM_MAX_TOKENS` | No | `500` | LLM max response tokens |
| `LLM_TEMPERATURE` | No | `0.1` | LLM temperature setting |

*The service runs entirely on rule-based logic without an API key; LLM enhancement is optional.

---

## API

### `GET /health`

Returns `{"status": "ok"}` within 60s of startup.

### `POST /analyze-ticket`

**Request body:**
```json
{
  "ticket_id": "TKT-001",
  "complaint": "I sent 5000 taka to a wrong number around 2pm today.",
  "language": "en",
  "channel": "in_app_chat",
  "user_type": "customer",
  "campaign_context": "boishakh_bonanza_day_1",
  "transaction_history": [
    {
      "transaction_id": "TXN-9101",
      "timestamp": "2026-04-14T14:08:22Z",
      "type": "transfer",
      "amount": 5000.0,
      "counterparty": "+8801719876543",
      "status": "completed"
    }
  ]
}
```

**Response:**
```json
{
  "ticket_id": "TKT-001",
  "relevant_transaction_id": "TXN-9101",
  "evidence_verdict": "consistent",
  "case_type": "wrong_transfer",
  "severity": "high",
  "department": "dispute_resolution",
  "agent_summary": "Investigation: Customer reports sending 5000 BDT via TXN-9101 to +8801719876543, which they now believe was the wrong recipient. Evidence verdict: consistent.",
  "recommended_next_action": "Verify TXN-9101 details with the customer and initiate the wrong-transfer dispute workflow per policy.",
  "customer_reply": "We have noted your concern about transaction TXN-9101. Our dispute resolution team will review the details and take appropriate action through official channels. Any eligible amount will be returned through the standard process. Please do not share your PIN or OTP with anyone.",
  "human_review_required": true,
  "confidence": 0.95,
  "reason_codes": ["wrong_transfer", "transaction_match", "amount_match"]
}
```

**Sample curl:**
```bash
curl -X POST http://localhost:8000/analyze-ticket \
  -H "Content-Type: application/json" \
  -d '{
    "ticket_id": "TKT-001",
    "complaint": "I sent 5000 taka to a wrong number around 2pm today.",
    "transaction_history": [
      {"transaction_id":"TXN-9101","timestamp":"2026-04-14T14:08:22Z","type":"transfer","amount":5000,"counterparty":"+8801719876543","status":"completed"}
    ]
  }'
```

---

## AI/Model Usage

### OpenRouter LLM Integration

| Component | Model | Purpose |
|-----------|-------|---------|
| Primary | `qwen/qwen3-next-80b-a3b-instruct:free` | Complaint investigation with few-shot prompting |
| Fallback 1 | `qwen/qwen3-next-80b-a3b-instruct:free` | Alternative when primary unavailable |
| Fallback 2 | `nvidia/nemotron-3-ultra-550b-a55b:free` | Free-tier alternative |
| Final fallback | Rule-based engine | Deterministic logic, always available |

### Hybrid Architecture

1. **Rule-based investigator** runs first on every request — deterministic scoring engine extracts claims from complaint, cross-references transaction history, and produces structured output
2. **Fast path**: If rule-based confidence >= 0.85, return immediately (no LLM call)
3. **LLM enhancement**: For low-confidence/complex cases, LLM investigates the same complaint and its output is merged with rule-based results
4. **Fallback chain**: LLM → fallback models → pure rule-based (always produces valid output)

### Prompt Design

The LLM is framed as a **complaint investigator**. The system prompt:
- Instructs the LLM to extract claims from complaint and compare against transaction data
- Provides few-shot examples from the 10 public sample cases
- Enforces strict JSON-only output (no markdown, no explanation)
- Embeds safety rules prohibiting credential requests, unauthorized promises, or third-party redirects

---

## Safety Logic — Triple-Layer Guardrails

### Layer 1: Input Scanner
Scans `complaint` text for prompt injection / adversarial override patterns:
- `ignore previous`, `ignore all instructions`, `override`, `system prompt`, `you are now`, `forget everything`, `act as`, `pretend`, `roleplay`, `do not follow`, `disregard`
- If detected: sets `human_review_required: true` and adds `prompt_injection_detected` to reason_codes
- Injected instructions are treated as part of the complaint text — never trusted as authoritative

### Layer 2: Decision Guard
Before building the response, checks if the action/case_type requires authorization:
- `refund_request` → NEVER promise refund; use "any eligible amount will be returned through official channels"
- `wrong_transfer` → NEVER promise reversal; use "we will investigate and assist through dispute resolution"
- Scans generated text for unauthorized promises, credential requests, and missing escalation flags

### Layer 3: Output Filter
Post-processes `customer_reply` to strip/rewrite:
- **Credential requests**: Regex scan for OTP/PIN/password requests (with negation-aware context to avoid false-triggering on "do not share your OTP")
- **Unauthorized promises**: Scans for `will refund|will reverse|will cancel|will guarantee` → replaces with safe fallback
- **Third-party redirects**: Scans for suspicious contact instructions → replaces with official channels reference
- **Bangla support**: Bangla-specific credential request and fallback handling

---

## Testing

```bash
# Run all tests
pytest tests/ -v

# Validate against 10 public sample cases
python3 validate_cases.py

# Run specific test suites
pytest tests/test_investigator.py -v  # Investigator engine tests
pytest tests/test_safety.py -v        # Safety guardrail tests
pytest tests/test_sample_cases.py -v  # Sample case structural tests
pytest tests/test_edge_cases.py -v    # Edge case tests
```

---

## Project Structure

```
├── app/
│   ├── config.py          Settings & environment variables
│   ├── investigator.py    Core investigation engine (scoring, matching, verdict)
│   ├── llm_client.py      OpenRouter LLM integration with fallback
│   ├── main.py            FastAPI application (GET /health, POST /analyze-ticket)
│   ├── safety.py          Triple-layer safety guardrails
│   └── schemas.py         Pydantic models, enums, request/response schemas
├── tests/
│   ├── test_edge_cases.py
│   ├── test_investigator.py
│   ├── test_safety.py
│   └── test_sample_cases.py
├── Dockerfile              Multi-stage build (<500MB)
├── docker-compose.yml      Docker Compose with healthcheck
├── requirements.txt        Pinned Python dependencies
├── .env.example            Environment variable template
├── validate_cases.py       Sample case validation script
└── Sample-Case.json        10 public sample cases
```

## License

Internal use — SUST CSE Carnival 2026 Codex Community Hackathon
@Md. Saniul Basir Saz
