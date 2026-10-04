// ─────────────────────────────────────────────────────────────
// MOCK MODE ONLY. A copy of what the backend returns, so the same
// adapter runs in mock and live mode. Generated from the backend's own
// fixture (backend/app/data.py + scoring.py) — do not hand-edit scores.
// Everything here is labeled MOCK in the UI.
// ─────────────────────────────────────────────────────────────
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
        "source": "CVE reference; verify before demo"
      },
      "threat": {
        "epss_probability": 0.99992,
        "epss_percentile": 0.99986,
        "kev": true,
        "epss_date": "2026-10-03",
        "kev_retrieved_at": "2026-10-03T23:51:40.3966192Z",
        "provenance": "verified_cached",
        "epss_source": "https://api.first.org/data/v1/epss?cve=CVE-2021-41773",
        "kev_source": "https://github.com/cisagov/kev-data",
        "kev_date_added": "2021-11-03"
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
                "explanation": "20 \u00d7 EPSS probability; EPSS is not asset compromise probability."
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
                "explanation": "2 \u00d7 supplied CVSS base score."
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
      "id": "demo-dev-a",
      "cve_id": null,
      "title": "Synthetic comparison finding A",
      "discovery_source": "synthetic_demo",
      "asset": {
        "id": "demo-dev",
        "name": "DEV-ISOLATED-01",
        "environment": "development",
        "business_service": "Demonstration service",
        "criticality": "low",
        "internet_facing": false,
        "data_sensitivity": "low",
        "context_source": "predefined_demo"
      },
      "cvss": {
        "score": 9.8,
        "version": "demo",
        "source": "synthetic_demo"
      },
      "threat": {
        "epss_probability": 0.01,
        "epss_percentile": null,
        "kev": false,
        "epss_date": null,
        "kev_retrieved_at": null,
        "provenance": "synthetic_demo"
      },
      "validation_supported": false,
      "priority": {
        "score": 28.8,
        "model_version": "ctem-demo-v0.1",
        "categories": [
          {
            "key": "threat",
            "max_points": 30,
            "points": 0.2,
            "factors": [
              {
                "label": "EPSS probability",
                "points": 0.2,
                "explanation": "20 \u00d7 EPSS probability; EPSS is not asset compromise probability."
              },
              {
                "label": "CISA KEV",
                "points": 0.0,
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
                "explanation": "2 \u00d7 supplied CVSS base score."
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
      "id": "demo-prod-b",
      "cve_id": null,
      "title": "Synthetic comparison finding B",
      "discovery_source": "synthetic_demo",
      "asset": {
        "id": "demo-prod",
        "name": "WEB-PROD-01",
        "environment": "production",
        "business_service": "Demonstration service",
        "criticality": "critical",
        "internet_facing": true,
        "data_sensitivity": "high",
        "context_source": "predefined_demo"
      },
      "cvss": {
        "score": 8.1,
        "version": "demo",
        "source": "synthetic_demo"
      },
      "threat": {
        "epss_probability": 0.8,
        "epss_percentile": null,
        "kev": true,
        "epss_date": null,
        "kev_retrieved_at": null,
        "provenance": "synthetic_demo"
      },
      "validation_supported": false,
      "priority": {
        "score": 92.2,
        "model_version": "ctem-demo-v0.1",
        "categories": [
          {
            "key": "threat",
            "max_points": 30,
            "points": 26.0,
            "factors": [
              {
                "label": "EPSS probability",
                "points": 16.0,
                "explanation": "20 \u00d7 EPSS probability; EPSS is not asset compromise probability."
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
            "points": 16.2,
            "factors": [
              {
                "label": "CVSS base score",
                "points": 16.2,
                "explanation": "2 \u00d7 supplied CVSS base score."
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
  "generated_at": "2026-10-04T00:00:00+00:00"
};

export function mockValidation(): ApiValidation {
  return {
    status: "matched",
    summary: "MOCK: Approved check read the controlled marker file outside the web root.",
    evidence: [
      { label: "HTTP response", detail: "200 OK" },
      { label: "Controlled marker", detail: "CTEM-LAB-PROOF-41773" },
    ],
    provenance: "mock",
    observed_at: new Date().toISOString(),
    template_id: "ctem-cve-2021-41773-readonly",
    viewpoint: "local Docker lab",
    limitations: ["This check establishes controlled file read only; it does not prove RCE or internet exposure."],
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
