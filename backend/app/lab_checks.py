"""Approved checks are mapped to fixed Compose services by finding ID."""

from dataclasses import dataclass


@dataclass(frozen=True)
class LabCheck:
    service: str
    port: int
    template_file: str
    template_id: str
    kind: str
    proof_label: str
    proof: str
    summary: str
    limitation: str


LAB_CHECKS = {
    "lab-httpd-41773": LabCheck(
        "vulnerable-web", 80, "CVE-2021-41773-readonly.yaml",
        "ctem-cve-2021-41773-readonly", "file_read",
        "Controlled marker", "CTEM-LAB-PROOF-41773",
        "Approved check read the controlled marker file outside the web root.",
        "This check establishes controlled file read only; it does not prove RCE or internet exposure.",
    ),
    "lab-httpd-42013": LabCheck(
        "httpd-250-internal", 80, "CVE-2021-42013-readonly.yaml",
        "ctem-cve-2021-42013-readonly", "file_read",
        "Controlled marker", "CTEM-LAB-PROOF-42013",
        "Approved check read the Apache 2.4.50 controlled marker file.",
        "This check establishes controlled file read only; it does not prove RCE or internet exposure.",
    ),
    "lab-struts-5638": LabCheck(
        "struts-internal", 8080, "CVE-2017-5638-expression.yaml",
        "ctem-cve-2017-5638-expression", "expression_evaluation",
        "Computed response header", "5421",
        "Approved check evaluated fixed arithmetic and returned its result in a response header.",
        "This checks OGNL expression evaluation in the local lab; it runs no operating-system commands and does not prove internet exposure.",
    ),
}


def validation_confirmed(finding_id: str, validation: dict) -> bool:
    check = LAB_CHECKS.get(finding_id)
    if not check or validation.get("status") != "matched" or validation.get("provenance") != "live":
        return False
    if validation.get("template_id") != check.template_id:
        return False
    evidence = validation.get("evidence", [])
    proof = any(e.get("label") == check.proof_label and e.get("detail") == check.proof
                for e in evidence if isinstance(e, dict))
    if check.kind == "file_read":
        return proof and any(e.get("label") == "HTTP response" and e.get("detail") == "200 OK"
                             for e in evidence if isinstance(e, dict))
    return proof
