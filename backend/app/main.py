from .remediation import generate_remediation
import asyncio
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .data import FIXTURES, findings_with_validation
from .validation import run_validation, with_metadata

app = FastAPI(title="RowdyHacks CTEM Prototype", version="0.1.0")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
                   allow_methods=["GET", "POST"], allow_headers=["Content-Type"])
REPO_ROOT = Path(__file__).resolve().parents[2]
validation_results: dict[str, dict] = {}
validation_lock = asyncio.Lock()


@app.exception_handler(HTTPException)
async def api_error(_request, exc: HTTPException):
    return JSONResponse(status_code=exc.status_code, content={"error": {
        "code": {404: "NOT_FOUND", 400: "UNSUPPORTED_FINDING"}.get(exc.status_code, "REQUEST_ERROR"),
        "message": exc.detail, "retryable": False}})


@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.get("/api/findings")
def findings():
    return {"findings": findings_with_validation(validation_results),
            "generated_at": datetime.now(timezone.utc).isoformat()}


@app.post("/api/findings/{finding_id}/validate")
async def validate(finding_id: str):
    selected = next((f for f in FIXTURES if f["id"] == finding_id), None)
    if selected is None:
        raise HTTPException(404, detail="Finding not found")
    if not selected["validation_supported"]:
        raise HTTPException(400, detail="No approved validator for this finding")
    if validation_lock.locked():
        return JSONResponse(status_code=409, content={"error": {
            "code": "VALIDATION_RUNNING", "message": "Validation already running", "retryable": True}})
    async with validation_lock:
        try:
            result = with_metadata(await run_validation(REPO_ROOT))
        except (OSError, RuntimeError) as exc:
            result = with_metadata({"status": "error", "summary": str(exc), "evidence": []})
        validation_results[finding_id] = result
        return result

@app.post("/api/findings/{finding_id}/remediation")
def remediation(finding_id: str):
    selected = next(
        (f for f in findings_with_validation(validation_results)
         if f["id"] == finding_id),
        None,
    )
    if selected is None:
        raise HTTPException(404, detail="Finding not found")
    return generate_remediation(selected)
