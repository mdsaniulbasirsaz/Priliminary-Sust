from __future__ import annotations

from json import JSONDecodeError

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.investigator import hybrid_investigate
from app.safety import apply_safety
from app.schemas import AnalyzeTicketRequest, AnalyzeTicketResponse

app = FastAPI(title="QueueStorm Investigator", version="1.0.0")


@app.exception_handler(JSONDecodeError)
async def json_decode_handler(request: Request, exc: JSONDecodeError):
    return JSONResponse(
        status_code=400,
        content={"error": "Malformed JSON input"},
    )


@app.exception_handler(RequestValidationError)
async def validation_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=422,
        content={"error": f"Invalid input: {exc.errors()}"},
    )


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post(
    "/analyze-ticket",
    response_model=AnalyzeTicketResponse,
    response_model_exclude_none=True,
)
async def analyze_ticket(body: AnalyzeTicketRequest):
    try:
        response = await hybrid_investigate(body)
        response = apply_safety(body, response)
        return response
    except Exception:
        return JSONResponse(
            status_code=500,
            content={"error": "Internal processing error"},
        )
