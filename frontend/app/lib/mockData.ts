// MOCK MODE ONLY. Generated from the backend fixture and snapshot.
// Values are a labeled offline replay; no live retrieval or validation occurs.
import type { ApiFindingsResponse, ApiRemediation, ApiValidation } from "./types";

export const mockFindings: ApiFindingsResponse = {
  "findings": [
    {
      "id": "lab-httpd-41773",
      "cve_id": "CVE-2021-41773",
      "title": "Apache HTTP Server 2.4.49 path traversal (controlled lab)",
      "discovery_source": "prepared_lab",
      "asset": {
        "id": "lab-web",
        "name": "VULHUB-WEB-01",
        "environment": "production",
        "business_service": "Demonstration service",
        "criticality": "critical",
        "internet_facing": true,
        "data_sensitivity": "high",
        "context_source": "predefined_demo"
      },
      "cvss": {
        "score": 7.5,
        "version": "3.1",
        "source": "CISA-ADP CVE record"
      },
      "threat": {
        "epss_probability": 0.99992,
        "epss_percentile": 0.99986,
        "kev": true,
        "epss_date": null,
        "kev_retrieved_at": null,
        "provenance": "mock"
      },
      "validation_supported": true,
      "priority": {
        "score": 95.0,
        "model_version": "ctem-demo-v0.1",
        "categories": [
          {
            "key": "threat",
            "max_points": 30,
            "points": 30.0,
            "factors": [
              {
                "label": "EPSS probability",
                "points": 20.0,
                "explanation": "20 × EPSS probability; EPSS is not asset compromise probability."
              },
              {
                "label": "CISA KEV",
                "points": 10.0,
                "explanation": "10 points if listed in the retrieved KEV catalog."
              }
            ]
          },
          {
            "key": "exposure",
            "max_points": 25,
            "points": 25.0,
            "factors": [
              {
                "label": "Predefined internet exposure",
                "points": 25.0,
                "explanation": "Asset context supplied for the demo; the lab check does not establish internet exposure."
              }
            ]
          },
          {
            "key": "business_impact",
            "max_points": 25,
            "points": 25.0,
            "factors": [
              {
                "label": "Criticality",
                "points": 15.0,
                "explanation": "Predefined business criticality."
              },
              {
                "label": "Production environment",
                "points": 5.0,
                "explanation": "Production adds 5 points."
              },
              {
                "label": "Data sensitivity",
                "points": 5.0,
                "explanation": "Predefined data sensitivity."
              }
            ]
          },
          {
            "key": "technical_severity",
            "max_points": 20,
            "points": 15.0,
            "factors": [
              {
                "label": "CVSS base score",
                "points": 15.0,
                "explanation": "2 × supplied CVSS base score."
              }
            ]
          }
        ],
        "missing_inputs": []
      },
      "validation": {
        "status": "not_run",
        "provenance": "mock",
        "observed_at": null,
        "template_id": null,
        "viewpoint": null,
        "summary": "Validation has not run.",
        "evidence": [],
        "limitations": []
      }
    },
    {
      "id": "lab-httpd-42013",
      "cve_id": "CVE-2021-42013",
      "title": "Apache HTTP Server 2.4.50 path traversal (controlled lab)",
      "discovery_source": "prepared_lab",
      "asset": {
        "id": "lab-dev",
        "name": "HTTPD-DEV-01",
        "environment": "development",
        "business_service": "Demonstration service",
        "criticality": "low",
        "internet_facing": false,
        "data_sensitivity": "low",
        "context_source": "predefined_demo"
      },
      "cvss": {
        "score": 9.8,
        "version": "3.1",
        "source": "NVD CVE-2021-42013"
      },
      "threat": {
        "epss_probability": 0.99964,
        "epss_percentile": 0.99976,
        "kev": true,
        "epss_date": null,
        "kev_retrieved_at": null,
        "provenance": "mock"
      },
      "validation_supported": true,
      "priority": {
        "score": 58.6,
        "model_version": "ctem-demo-v0.1",
        "categories": [
          {
            "key": "threat",
            "max_points": 30,
            "points": 30.0,
            "factors": [
              {
                "label": "EPSS probability",
                "points": 20.0,
                "explanation": "20 × EPSS probability; EPSS is not asset compromise probability."
              },
              {
                "label": "CISA KEV",
                "points": 10.0,
                "explanation": "10 points if listed in the retrieved KEV catalog."
              }
            ]
          },
          {
            "key": "exposure",
            "max_points": 25,
            "points": 5.0,
            "factors": [
              {
                "label": "Predefined internet exposure",
                "points": 5.0,
                "explanation": "Asset context supplied for the demo; the lab check does not establish internet exposure."
              }
            ]
          },
          {
            "key": "business_impact",
            "max_points": 25,
            "points": 4.0,
            "factors": [
              {
                "label": "Criticality",
                "points": 3.0,
                "explanation": "Predefined business criticality."
              },
              {
                "label": "Production environment",
                "points": 0.0,
                "explanation": "Production adds 5 points."
              },
              {
                "label": "Data sensitivity",
                "points": 1.0,
                "explanation": "Predefined data sensitivity."
              }
            ]
          },
          {
            "key": "technical_severity",
            "max_points": 20,
            "points": 19.6,
            "factors": [
              {
                "label": "CVSS base score",
                "points": 19.6,
                "explanation": "2 × supplied CVSS base score."
              }
            ]
          }
        ],
        "missing_inputs": []
      },
      "validation": {
        "status": "not_run",
        "provenance": "mock",
        "observed_at": null,
        "template_id": null,
        "viewpoint": null,
        "summary": "Validation has not run.",
        "evidence": [],
        "limitations": []
      }
    },
    {
      "id": "lab-struts-5638",
      "cve_id": "CVE-2017-5638",
      "title": "Apache Struts 2.3.30 Jakarta Multipart parser (controlled lab)",
      "discovery_source": "prepared_lab",
      "asset": {
        "id": "lab-struts",
        "name": "STRUTS-PROD-01",
        "environment": "production",
        "business_service": "Demonstration service",
        "criticality": "critical",
        "internet_facing": false,
        "data_sensitivity": "high",
        "context_source": "predefined_demo"
      },
      "cvss": {
        "score": 9.8,
        "version": "3.1",
        "source": "NVD CVE-2017-5638"
      },
      "threat": {
        "epss_probability": 0.99999,
        "epss_percentile": 0.99994,
        "kev": true,
        "epss_date": null,
        "kev_retrieved_at": null,
        "provenance": "mock"
      },
      "validation_supported": true,
      "priority": {
        "score": 79.6,
        "model_version": "ctem-demo-v0.1",
        "categories": [
          {
            "key": "threat",
            "max_points": 30,
            "points": 30.0,
            "factors": [
              {
                "label": "EPSS probability",
                "points": 20.0,
                "explanation": "20 × EPSS probability; EPSS is not asset compromise probability."
              },
              {
                "label": "CISA KEV",
                "points": 10.0,
                "explanation": "10 points if listed in the retrieved KEV catalog."
              }
            ]
          },
          {
            "key": "exposure",
            "max_points": 25,
            "points": 5.0,
            "factors": [
              {
                "label": "Predefined internet exposure",
                "points": 5.0,
                "explanation": "Asset context supplied for the demo; the lab check does not establish internet exposure."
              }
            ]
          },
          {
            "key": "business_impact",
            "max_points": 25,
            "points": 25.0,
            "factors": [
              {
                "label": "Criticality",
                "points": 15.0,
                "explanation": "Predefined business criticality."
              },
              {
                "label": "Production environment",
                "points": 5.0,
                "explanation": "Production adds 5 points."
              },
              {
                "label": "Data sensitivity",
                "points": 5.0,
                "explanation": "Predefined data sensitivity."
              }
            ]
          },
          {
            "key": "technical_severity",
            "max_points": 20,
            "points": 19.6,
            "factors": [
              {
                "label": "CVSS base score",
                "points": 19.6,
                "explanation": "2 × supplied CVSS base score."
              }
            ]
          }
        ],
        "missing_inputs": []
      },
      "validation": {
        "status": "not_run",
        "provenance": "mock",
        "observed_at": null,
        "template_id": null,
        "viewpoint": null,
        "summary": "Validation has not run.",
        "evidence": [],
        "limitations": []
      }
    }
  ],
  "generated_at": "mock"
};


export function mockValidation(findingId: string): ApiValidation {
  const checks: Record<string, { template: string; kind: "file_read" | "expression_evaluation"; label: string; proof: string }> = {
    "lab-httpd-41773": { template: "ctem-cve-2021-41773-readonly", kind: "file_read", label: "Controlled marker", proof: "CTEM-LAB-PROOF-41773" },
    "lab-httpd-42013": { template: "ctem-cve-2021-42013-readonly", kind: "file_read", label: "Controlled marker", proof: "CTEM-LAB-PROOF-42013" },
    "lab-struts-5638": { template: "ctem-cve-2017-5638-expression", kind: "expression_evaluation", label: "Computed response header", proof: "5421" },
  };
  const check = checks[findingId];
  if (!check) throw new Error("No mock check for this finding");
  return {
    status: "matched",
    summary: "MOCK: Offline replay of an approved lab result.",
    evidence: [{ label: "HTTP response", detail: "200 OK" }, { label: check.label, detail: check.proof }],
    provenance: "mock",
    observed_at: new Date().toISOString(),
    template_id: check.template,
    kind: check.kind,
    viewpoint: "mock local Docker lab",
    limitations: ["Offline replay only; no check was executed."],
  };
}

export function mockRemediation(findingId: string): ApiRemediation {
  return {
    finding_id: findingId,
    status: "manual_review_required",
    provenance: "mock",
    generated_at: null,
    sections: { remediation: [], mitigation: [], implementation: [], verification: [], rollback: [], reasoning: [] },
    sources: [],
    limitations: ["AI grounding is not configured. No recommendation was generated."],
  };
}
