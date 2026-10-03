"""Small explicit fixture; replace with reviewed Trivy/EPSS/KEV inputs in the next phase."""

import json
from pathlib import Path

from copy import deepcopy

from .scoring import priority_for


def _asset(id_: str, name: str, environment: str, criticality: str,
           internet_facing: bool, sensitivity: str) -> dict:
    return {"id": id_, "name": name, "environment": environment,
            "business_service": "Demonstration service", "criticality": criticality,
            "internet_facing": internet_facing, "data_sensitivity": sensitivity,
            "context_source": "predefined_demo"}


FIXTURES = [
    {"id": "lab-httpd-41773", "cve_id": "CVE-2021-41773",
     "title": "Apache HTTP Server 2.4.49 path traversal (controlled lab)",
     "discovery_source": "prepared_lab",
     "asset": _asset("lab-web", "VULHUB-WEB-01", "production", "critical", True, "high"),
     "cvss": {"score": 7.5, "version": "3.1", "source": "CVE reference; verify before demo"},
     "threat": {"epss_probability": None, "epss_percentile": None, "kev": None,
                "epss_date": None, "kev_retrieved_at": None, "provenance": "synthetic_demo"},
     "validation_supported": True},
    {"id": "demo-dev-a", "cve_id": None, "title": "Synthetic comparison finding A",
     "discovery_source": "synthetic_demo",
     "asset": _asset("demo-dev", "DEV-ISOLATED-01", "development", "low", False, "low"),
     "cvss": {"score": 9.8, "version": "demo", "source": "synthetic_demo"},
     "threat": {"epss_probability": .01, "epss_percentile": None, "kev": False,
                "epss_date": None, "kev_retrieved_at": None, "provenance": "synthetic_demo"},
     "validation_supported": False},
    {"id": "demo-prod-b", "cve_id": None, "title": "Synthetic comparison finding B",
     "discovery_source": "synthetic_demo",
     "asset": _asset("demo-prod", "WEB-PROD-01", "production", "critical", True, "high"),
     "cvss": {"score": 8.1, "version": "demo", "source": "synthetic_demo"},
     "threat": {"epss_probability": .80, "epss_percentile": None, "kev": True,
                "epss_date": None, "kev_retrieved_at": None, "provenance": "synthetic_demo"},
     "validation_supported": False},
]


def findings_with_validation(results: dict[str, dict]) -> list[dict]:
    findings = deepcopy(FIXTURES)
    for finding in findings:
        if finding["id"] == "lab-httpd-41773":
            snapshot_path = Path(__file__).with_name("intel_snapshot.json")
            if snapshot_path.is_file():
                intel = json.loads(snapshot_path.read_text(encoding="utf-8-sig"))
                if intel.get("cve_id") != finding["cve_id"]:
                    raise RuntimeError("Intelligence snapshot CVE mismatch")
                keys = ("epss_probability", "epss_percentile", "epss_date",
                        "kev", "kev_retrieved_at", "provenance",
                        "epss_source", "kev_source", "kev_date_added")
                finding["threat"].update({key: intel[key] for key in keys})
        finding["priority"] = priority_for(finding)
        finding["validation"] = deepcopy(results.get(finding["id"], {
            "status": "not_run", "provenance": "mock", "observed_at": None,
            "template_id": None, "viewpoint": None, "summary": "Validation has not run.",
            "evidence": [], "limitations": []}))
    return findings

