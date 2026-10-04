"""Run one approved Nuclei check against its fixed Compose lab service."""

import asyncio
import ipaddress
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from .lab_checks import LAB_CHECKS

IMAGE = "projectdiscovery/nuclei:v3.11.1"


def interpret(output: str, returncode: int, finding_id: str) -> dict:
    """Require the selected template's response proof, never a generic scan match."""
    check = LAB_CHECKS[finding_id]
    if returncode == 0:
        for line in output.splitlines():
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if (not isinstance(record, dict) or record.get("template-id") != check.template_id
                    or record.get("matcher-status") is False):
                continue
            response = record.get("response", "")
            if not isinstance(response, str):
                continue
            response = response.replace("\r\n", "\n")
            headers, separator, body = response.partition("\n\n")
            status = re.match(r"HTTP/\S+\s+(\d{3})(?:\s+([^\n]*))?", headers)
            if not separator or not status:
                continue
            if check.kind == "file_read":
                matched = status.group(1) == "200" and check.proof in body.splitlines()
            else:
                matched = bool(re.search(
                    r"^X-CTEM-Lab-Proof:\s*" + re.escape(check.proof) + r"\s*$",
                    headers, flags=re.IGNORECASE | re.MULTILINE,
                ))
            if matched:
                status_line = "200 OK" if status.group(1) == "200" else (
                    status.group(1) + " " + (status.group(2) or "")).strip()
                return {"status": "matched", "summary": check.summary, "evidence": [
                    {"label": "HTTP response", "detail": status_line},
                    {"label": check.proof_label, "detail": check.proof},
                ]}
    return {"status": "error",
            "summary": "No confirmed match. Review scanner output; this is not proof of mitigation.",
            "evidence": [{"label": "Scanner exit code", "detail": str(returncode)}]}


async def _command(*args: str, cwd: Path | None = None, timeout: int = 10) -> tuple[str, str, int]:
    proc = await asyncio.create_subprocess_exec(
        *args, cwd=cwd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except BaseException:
        if proc.returncode is None:
            proc.kill()
        await proc.communicate()
        raise
    return stdout.decode(errors="replace"), stderr.decode(errors="replace"), proc.returncode


async def run_validation(repo_root: Path, finding_id: str) -> dict:
    check = LAB_CHECKS[finding_id]
    template_dir = repo_root / "lab" / "templates"
    if not (template_dir / check.template_file).is_file():
        raise RuntimeError("Approved template missing from lab/templates")
    try:
        container, _, code = await _command(
            "docker", "compose", "ps", "-q", check.service, cwd=repo_root,
        )
        container = container.strip()
        if code != 0 or not container or len(container.splitlines()) != 1:
            raise RuntimeError(f"Lab service {check.service} unavailable. Run docker compose up -d.")
        details, _, code = await _command("docker", "inspect", container)
        if code != 0:
            raise RuntimeError("Could not inspect the selected lab container.")
        try:
            info = json.loads(details)[0]
            labels = info["Config"]["Labels"]
            network = labels["com.docker.compose.project"] + "_lab"
            if labels["com.docker.compose.service"] != check.service or not info["State"]["Running"]:
                raise ValueError("Unexpected service or stopped container")
            ip = str(ipaddress.IPv4Address(info["NetworkSettings"]["Networks"][network]["IPAddress"]))
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise RuntimeError("Selected lab service is not running on its Compose lab network.") from exc
    except asyncio.TimeoutError as exc:
        raise RuntimeError("Docker inspection timed out; result inconclusive.") from exc

    # Stop the named scanner container even if the Docker CLI itself times out.
    scanner = "ctem-validator-" + uuid4().hex
    command = [
        "docker", "run", "--rm", "--pull=never", "--name", scanner, "--network", network,
        "-v", f"{template_dir.resolve()}:/templates:ro", IMAGE,
        "-u", f"http://{ip}:{check.port}", "-t", "/templates/" + check.template_file,
        "-timeout", "5", "-retries", "0", "-duc", "-ni", "-dr", "-jsonl", "-ot",
    ]
    try:
        stdout, stderr, code = await _command(*command, timeout=30)
        result = interpret(stdout, code, finding_id)
        if result["status"] == "error":
            result["evidence"].append({"label": "Diagnostic", "detail": stderr[-500:]})
        return result
    except asyncio.TimeoutError:
        return {"status": "error", "summary": "Validation timed out; result inconclusive.", "evidence": []}
    finally:
        try:
            await _command("docker", "rm", "-f", scanner, timeout=5)
        except (OSError, asyncio.TimeoutError):
            pass


def with_metadata(result: dict, finding_id: str) -> dict:
    check = LAB_CHECKS[finding_id]
    return {**result, "provenance": "live", "observed_at": datetime.now(timezone.utc).isoformat(),
            "template_id": check.template_id, "viewpoint": "local Docker lab", "kind": check.kind,
            "limitations": [check.limitation]}
