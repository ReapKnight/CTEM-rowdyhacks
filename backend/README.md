# RowdyHacks CTEM backend

The demo contains three prepared lab findings. The asset names, production/development labels, criticality, data sensitivity, and internet-facing flags are **declared scenario inputs**; the local containers do not establish real internet exposure. Apache 2.4.50 and Struts have no published host ports in Compose.

| Finding | Lab service | CVE | Approved validation evidence |
| --- | --- | --- | --- |
| Apache HTTP Server 2.4.49 | `vulnerable-web` | CVE-2021-41773 | Exact marker returned from `/tmp/ctem-proof.txt` |
| Apache HTTP Server 2.4.50 | `httpd-250-internal` | CVE-2021-42013 | Exact marker returned from `/tmp/ctem-proof-42013.txt` |
| Apache Struts 2.3.30 | `struts-internal` | CVE-2017-5638 | Response header with the computed result of fixed arithmetic |

From a free PowerShell window at the repository root:

```powershell
.\backend\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt
.\backend\.venv\Scripts\python.exe -m backend.refresh_intel

docker compose up -d --build
docker pull projectdiscovery/nuclei:v3.11.1

docker compose ps
.\backend\.venv\Scripts\python.exe -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
```

Refresh the dashboard at `http://localhost:3000`. The `GET /api/findings` response should contain three CVEs with dated EPSS/KEV data. Refreshing intelligence requires access to FIRST EPSS and the full CISA KEV catalog. If either request fails, the refresh script leaves the previous snapshot untouched; missing data remains unknown and the score is withheld. The included cache is a dated fallback, not live intelligence on every page load.

The validation endpoint accepts only a finding ID. It resolves the approved service and template from `backend/app/lab_checks.py`, checks the container's Compose labels and lab network, and runs only that template in Nuclei. It does not accept a target URL or arbitrary template. A scanner error, timeout, or missing proof is inconclusive. The Struts check does **not** execute an operating-system command. Validation state is in memory and clears when the backend restarts.

Gemini remediation uses curated actions and Apache advisories, then validates Gemini's selected action IDs before displaying them. Set `GEMINI_API_KEY` in the backend process environment as already configured. The Struts historical fix versions are not current deployment recommendations; use a currently supported Struts release. Recommendations do not execute changes.

The scanner has no internet-facing target in the two new Compose services, but a Docker bridge alone is not an egress firewall. Run this deliberately vulnerable lab only on a controlled development machine. The API has no authentication and should remain bound to `127.0.0.1`.

Checks in this repository:

```powershell
.\backend\.venv\Scripts\python.exe -m unittest discover -s backend\tests -v
```

The Nuclei YAML templates and local API/renderer were checked during development. The new live Docker checks still need to be exercised on the target Windows machine. Confirm each details panel reports its expected proof, without a MOCK label, before treating live validation as complete.
