# Backend checkpoint

Place this `backend/` directory beside `lab/` and `compose.yaml` at the repository root.

From PowerShell in the repository root:

```powershell
py -m venv backend\.venv
backend\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt
backend\.venv\Scripts\python.exe -m uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
```

Visit http://127.0.0.1:8000/docs or request `/api/findings`.

The fixture contains two **synthetic** comparison findings and one `prepared_lab` finding.
Real EPSS/KEV are unknown until enrichment is implemented. Scores for the synthetic
findings are display examples; they must not be presented as actual threat intelligence.

Validation runs a fixed Nuclei template for `lab-httpd-41773` against the local
Docker lab. It requires Docker Desktop, the lab service running, and the reviewed
template in `lab/templates/`. The current runner expects the network alias
`vulnerable-web.ctem.local` and network `ctem-rowdyhacks_lab` from the latest
Compose configuration. Remediation currently returns manual-review-required.

This is a development checkpoint, not the completed MVP. Do not deploy this API
publicly; there is no authentication. The recorded validation state is in-memory
and resets on restart.
