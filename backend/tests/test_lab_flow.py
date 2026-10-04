"""Meaningful regression checks for the three fixed lab finding workflows."""

import json
import unittest
from pathlib import Path
from unittest.mock import patch

from backend.app.data import findings_with_validation
from backend.app.lab_checks import LAB_CHECKS, validation_confirmed
from backend.app.remediation import generate_remediation
from backend.app.validation import interpret, run_validation, with_metadata
from backend.refresh_intel import build_snapshot

ROOT = Path(__file__).resolve().parents[2]


class LabFlowTests(unittest.TestCase):
    def test_real_findings_and_dated_intel(self):
        findings = findings_with_validation({})
        self.assertEqual({f["cve_id"] for f in findings},
                         {"CVE-2021-41773", "CVE-2021-42013", "CVE-2017-5638"})
        self.assertTrue(all(f["discovery_source"] == "prepared_lab" for f in findings))
        self.assertEqual([f["priority"]["score"] for f in findings], [95, 58.6, 79.6])
        self.assertTrue(all(f["threat"]["kev"] is True and f["threat"]["epss_date"]
                            for f in findings))
        self.assertFalse(findings[1]["asset"]["internet_facing"])
        self.assertFalse(findings[2]["asset"]["internet_facing"])

    def test_each_match_requires_its_own_proof_and_template(self):
        examples = {
            "lab-httpd-41773": "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nCTEM-LAB-PROOF-41773\n",
            "lab-httpd-42013": "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nCTEM-LAB-PROOF-42013\n",
            "lab-struts-5638": "HTTP/1.1 500 Error\r\nX-CTEM-Lab-Proof: 5421\r\n\r\n",
        }
        for finding_id, response in examples.items():
            check = LAB_CHECKS[finding_id]
            record = json.dumps({"template-id": check.template_id, "response": response})
            matched = with_metadata(interpret(record, 0, finding_id), finding_id)
            self.assertTrue(validation_confirmed(finding_id, matched))
            self.assertEqual(interpret(record, 1, finding_id)["status"], "error")
            self.assertEqual(interpret(json.dumps({"template-id": "wrong", "response": response}),
                                       0, finding_id)["status"], "error")
            self.assertFalse(validation_confirmed(finding_id, {**matched, "template_id": "wrong"}))
        # Reflected proof in a request/body is insufficient for Struts.
        reflected = {"template-id": LAB_CHECKS["lab-struts-5638"].template_id,
                     "response": "HTTP/1.1 500 Error\r\n\r\n5421"}
        self.assertEqual(interpret(json.dumps(reflected), 0, "lab-struts-5638")["status"], "error")

    def test_incomplete_kev_catalog_never_becomes_false(self):
        epss = {"status": "OK", "data": [{"cve": "CVE-2021-42013", "epss": "0.4",
                                          "percentile": "0.7", "date": "2026-10-03"}]}
        incomplete = {"count": 2, "vulnerabilities": [{"cveID": "CVE-2021-41773"}]}
        with self.assertRaises(ValueError):
            build_snapshot(epss, incomplete, ["CVE-2021-42013"], "2026-10-04T00:00:00Z")

    def test_struts_guidance_uses_reviewed_actions_and_its_advisory(self):
        finding = next(f for f in findings_with_validation({}) if f["id"] == "lab-struts-5638")

        class Response:
            def __init__(self, value):
                self.value = value

            def __enter__(self):
                return self

            def __exit__(self, *_):
                pass

            def read(self):
                return json.dumps(self.value).encode()

        def fake_urlopen(request, timeout):
            payload = json.loads(request.data)
            context = json.loads(payload["contents"][0]["parts"][0]["text"])
            chosen = {section: list(options) for section, options in context["approved_actions"].items()}
            plan = {"manual_review_required": False, "sections": chosen}
            return Response({"candidates": [{"finishReason": "STOP", "content": {
                "parts": [{"text": json.dumps(plan)}]}}]})

        with patch.dict("backend.app.remediation.os.environ", {"GEMINI_API_KEY": "test-key"}), \
                patch("backend.app.remediation.urlopen", fake_urlopen):
            guidance = generate_remediation(finding)
        self.assertEqual(guidance["status"], "generated")
        self.assertIn("S2-045", guidance["sources"][0]["title"])
        self.assertTrue(any("currently supported" in item for item in guidance["sections"]["remediation"]))
        self.assertTrue(any("No successful" in item for item in guidance["sections"]["reasoning"]))


class RunnerTests(unittest.IsolatedAsyncioTestCase):
    async def test_struts_is_bound_to_its_compose_service_and_template(self):
        calls = []

        async def fake_command(*args, **kwargs):
            calls.append(args)
            if args[:3] == ("docker", "compose", "ps"):
                return ("abc123\n", "", 0)
            if args[:2] == ("docker", "inspect"):
                return (json.dumps([{ "Config": {"Labels": {
                    "com.docker.compose.project": "ctem-rowdyhacks",
                    "com.docker.compose.service": "struts-internal"}},
                    "State": {"Running": True}, "NetworkSettings": {"Networks": {
                        "ctem-rowdyhacks_lab": {"IPAddress": "172.21.0.3"}}}}]), "", 0)
            if args[:2] == ("docker", "run"):
                response = "HTTP/1.1 500 Error\r\nX-CTEM-Lab-Proof: 5421\r\n\r\n"
                return (json.dumps({"template-id": LAB_CHECKS["lab-struts-5638"].template_id,
                                    "response": response}), "", 0)
            return ("", "", 0)

        with patch("backend.app.validation._command", fake_command):
            result = await run_validation(ROOT, "lab-struts-5638")
        self.assertEqual(result["status"], "matched")
        self.assertEqual(calls[0][-1], "struts-internal")
        self.assertIn("http://172.21.0.3:8080", calls[2])
        self.assertIn("/templates/CVE-2017-5638-expression.yaml", calls[2])
        self.assertEqual(calls[-1][:3], ("docker", "rm", "-f"))

    async def test_wrong_compose_service_fails_closed(self):
        async def fake_command(*args, **kwargs):
            if args[:3] == ("docker", "compose", "ps"):
                return ("abc123\n", "", 0)
            return (json.dumps([{"Config": {"Labels": {
                "com.docker.compose.project": "ctem-rowdyhacks",
                "com.docker.compose.service": "vulnerable-web"}},
                "State": {"Running": True}, "NetworkSettings": {"Networks": {
                    "ctem-rowdyhacks_lab": {"IPAddress": "172.21.0.3"}}}}]), "", 0)
        with patch("backend.app.validation._command", fake_command):
            with self.assertRaisesRegex(RuntimeError, "not running on its Compose lab network"):
                await run_validation(ROOT, "lab-struts-5638")


if __name__ == "__main__":
    unittest.main()
