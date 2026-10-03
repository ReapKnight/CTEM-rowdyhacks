"""The only executable check is the reviewed template against the local lab."""

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path

TEMPLATE_ID = "ctem-cve-2021-41773-readonly"
MARKER = "CTEM-LAB-PROOF-41773"
NETWORK = "ctem-rowdyhacks_lab"
CONTAINER = "ctem-rowdyhacks-vulnerable-web-1"
IMAGE = "projectdiscovery/nuclei:latest"  # Pin a digest after final demo verification.


def interpret(output: str, returncode: int) -> dict:
    """Do not interpret silence/scan failures as a clean target."""
    records = []
    for line in output.splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict) and item.get("template-id") == TEMPLATE_ID:
            records.append(item)
    match = next((record for record in records
                  if record.get("matcher-status") is not False
                  and MARKER in record.get("response", "")
                  and "200 OK" in record.get("response", "")), None)
    if match:
        return {"status": "matched", "summary": "Approved check read the controlled marker file outside the web root.",
                "evidence": [{"label": "HTTP response", "detail": "200 OK"},
                             {"label": "Controlled marker", "detail": MARKER}]}
    return {"status": "error", "summary": "No confirmed match. Review scanner output; this is not proof of mitigation.",
            "evidence": [{"label": "Scanner exit code", "detail": str(returncode)}]}


async def run_validation(repo_root: Path) -> dict:
    template_dir = repo_root / "lab" / "templates"
    if not (template_dir / "CVE-2021-41773-readonly.yaml").is_file():
        raise RuntimeError("Approved template missing from lab/templates")
    inspect = await asyncio.create_subprocess_exec(
        "docker", "inspect", "-f",
        "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
        CONTAINER,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE)
    ip_bytes, _ = await asyncio.wait_for(inspect.communicate(), timeout=10)
    ip = ip_bytes.decode(errors="replace").strip()
    if inspect.returncode != 0 or not ip:
        raise RuntimeError("Lab container unavailable. Run docker compose up -d.")
    target = f"http://{ip}"
    command = ["docker", "run", "--rm", "--network", NETWORK,
               "-v", f"{template_dir.resolve()}:/templates:ro", IMAGE,
               "-u", target, "-t", "/templates/CVE-2021-41773-readonly.yaml",
               "-timeout", "5", "-retries", "0", "-duc", "-jsonl"]
    proc = await asyncio.create_subprocess_exec(*command, stdout=asyncio.subprocess.PIPE,
                                                stderr=asyncio.subprocess.PIPE)
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.communicate()
        return {"status": "error", "summary": "Validation timed out; result inconclusive.", "evidence": []}
    result = interpret(stdout.decode(errors="replace"), proc.returncode)
    if result["status"] == "error":
        result["evidence"].append({"label": "Diagnostic", "detail": stderr.decode(errors="replace")[-500:]})
    return result


def with_metadata(result: dict) -> dict:
    return {**result, "provenance": "live", "observed_at": datetime.now(timezone.utc).isoformat(),
            "template_id": TEMPLATE_ID, "viewpoint": "local Docker lab",
            "limitations": ["This check establishes controlled file read only; it does not prove RCE or internet exposure."]}


