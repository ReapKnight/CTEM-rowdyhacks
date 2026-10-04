"""Three prepared lab findings with declared business context and dated intelligence."""

import json
from copy import deepcopy
from pathlib import Path

from .scoring import priority_for


def _asset(id_: str, name: str, environment: str, criticality: str,
           internet_facing: bool, sensitivity: str) -> dict:
    return {"id": id_, "name": name, "environment": environment,
            "business_service": "Demonstration service", "criticality": criticality,
            "internet_facing": internet_facing, "data_sensitivity": sensitivity,
            "context_source": "predefined_demo"}


def _threat() -> dict:
    return {"epss_probability": None, "epss_percentile": None, "kev": None,
            "epss_date": None, "kev_retrieved_at": None, "provenance": "not_retrieved"}


FIXTURES = [
    {"id": "lab-httpd-41773", "cve_id": "CVE-2021-41773",
     "title": "Apache HTTP Server 2.4.49 path traversal (controlled lab)",
     "discovery_source": "prepared_lab",
     "asset": _asset("lab-web", "VULHUB-WEB-01", "production", "critical", True, "high"),
     "cvss": {"score": 7.5, "version": "3.1", "source": "CISA-ADP CVE record"},
     "threat": _threat(), "validation_supported": True},
    {"id": "lab-httpd-42013", "cve_id": "CVE-2021-42013",
     "title": "Apache HTTP Server 2.4.50 path traversal (controlled lab)",
     "discovery_source": "prepared_lab",
     "asset": _asset("lab-dev", "HTTPD-DEV-01", "development", "low", False, "low"),
     "cvss": {"score": 9.8, "version": "3.1", "source": "NVD CVE-2021-42013"},
     "threat": _threat(), "validation_supported": True},
    {"id": "lab-struts-5638", "cve_id": "CVE-2017-5638",
     "title": "Apache Struts 2.3.30 Jakarta Multipart parser (controlled lab)",
     "discovery_source": "prepared_lab",
     "asset": _asset("lab-struts", "STRUTS-PROD-01", "production", "critical", False, "high"),
     "cvss": {"score": 9.8, "version": "3.1", "source": "NVD CVE-2017-5638"},
     "threat": _threat(), "validation_supported": True},
]


def _cached_intel() -> dict:
    path = Path(__file__).with_name("intel_snapshot.json")
    if not path.is_file():
        return {}
    try:
        snapshot = json.loads(path.read_text(encoding="utf-8-sig"))
        if snapshot.get("schema_version") == 2 and isinstance(snapshot.get("cves"), dict):
            return snapshot["cves"]
        # Read the original single-CVE cache during upgrades; new CVEs remain unknown.
        if snapshot.get("cve_id") == "CVE-2021-41773":
            return {snapshot["cve_id"]: snapshot}
    except (OSError, ValueError, AttributeError):
        pass
    return {}


def findings_with_validation(results: dict[str, dict]) -> list[dict]:
    findings = deepcopy(FIXTURES)
    intel_by_cve = _cached_intel()
    keys = ("epss_probability", "epss_percentile", "epss_date", "kev",
            "kev_retrieved_at", "provenance", "epss_source", "kev_source", "kev_date_added")
    for finding in findings:
        intel = intel_by_cve.get(finding["cve_id"], {})
        if all(key in intel for key in keys):
            finding["threat"].update({key: intel[key] for key in keys})
        finding["priority"] = priority_for(finding)
        finding["validation"] = deepcopy(results.get(finding["id"], {
            "status": "not_run", "provenance": "mock", "observed_at": None,
            "template_id": None, "viewpoint": None, "summary": "Validation has not run.",
            "evidence": [], "limitations": []}))
    return findings
