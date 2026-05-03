import json
from unittest.mock import patch

from django.test import TestCase

from api.guardrail_parser import normalize_guardrail_text
from api.mcp_agent import _compose_system_prompt, _guardrail_decision, _guardrail_violation
from api import tool_bridge
from api.models import ScanRun
from api.verifier import AttackExecutor


class GuardrailParserTests(TestCase):
    def test_normalize_guardrail_text_extracts_constraints(self):
        raw = """
        <div>Program Rules</div>
        <ul>
          <li>In scope: app.example.com and api.example.com</li>
          <li>Do not perform denial of service attacks.</li>
          <li>Out of scope: third-party services and employee devices.</li>
          <li>Rate limit your requests and avoid noisy automation.</li>
        </ul>
        """

        normalized = normalize_guardrail_text(raw)

        self.assertIn("In scope: app.example.com and api.example.com", normalized["cleaned_text"])
        self.assertIn("Do not perform denial of service attacks.", normalized["constraints"])
        self.assertIn("Out of scope: third-party services and employee devices.", normalized["constraints"])
        self.assertIn("## Forbidden", normalized["markdown"])
        self.assertIn("app.example.com", normalized["enforcement"]["allowed_hosts"])
        self.assertIn("api.example.com", normalized["enforcement"]["allowed_hosts"])
        self.assertEqual(normalized["enforcement"]["recommended_max_parallel_probes"], 3)

    def test_korean_guardrail_extracts_enforcement(self):
        normalized = normalize_guardrail_text(
            "허용 범위: https://app.example.com/api\n"
            "제외 대상: https://app.example.com/admin\n"
            "자동화 스캐너 사용 금지\n"
            "과도한 요청은 피하고 속도 제한을 준수하세요."
        )

        self.assertIn("app.example.com", normalized["enforcement"]["allowed_hosts"])
        self.assertIn("https://app.example.com/api", normalized["enforcement"]["allowed_url_prefixes"])
        self.assertIn("https://app.example.com/admin", normalized["enforcement"]["out_of_scope_url_prefixes"])
        self.assertIn("nuclei_scan", normalized["enforcement"]["blocked_tools"])
        self.assertEqual(normalized["enforcement"]["recommended_max_parallel_probes"], 3)

    def test_extracts_wildcard_host_scope(self):
        normalized = normalize_guardrail_text("Allowed: *.example.com")

        self.assertIn("example.com", normalized["enforcement"]["allowed_wildcard_hosts"])


class GuardrailApiTests(TestCase):
    def test_normalize_endpoint_returns_summary(self):
        response = self.client.post(
            "/api/guardrails/normalize/",
            data=json.dumps({"raw_text": "Allowed: test app.example.com\nDo not brute force accounts."}),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertIn("summary", payload)
        self.assertIn("Do not brute force accounts.", payload["constraints"])

    def test_scan_run_creation_stores_normalized_guardrail(self):
        response = self.client.post(
            "/api/scan-runs/",
            data=json.dumps({
                "target_url": "https://example.com",
                "guardrail_raw": "In scope: example.com\nDo not access customer data.",
                "config": {"mode": "mcp"},
            }),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 201)
        scan = ScanRun.objects.get(run_id=response.json()["run_id"])
        self.assertIn("guardrail", scan.config)
        self.assertEqual(scan.config["guardrail"]["raw"], "In scope: example.com\nDo not access customer data.")
        self.assertIn("Do not access customer data.", scan.config["guardrail"]["constraints"])


class GuardrailPromptTests(TestCase):
    def test_compose_system_prompt_includes_guardrail_summary(self):
        scan = ScanRun.objects.create(
            target_url="https://example.com",
            config={
                "guardrail": {
                    "summary": "Only test example.com. Avoid destructive traffic.",
                    "constraints": ["Do not brute force.", "Out of scope: support.example.com"],
                    "markdown": "## Forbidden\n- Do not brute force.",
                }
            },
        )

        prompt = _compose_system_prompt(scan, "BASE PROMPT")

        self.assertIn("Bug Bounty Guardrails", prompt)
        self.assertIn("Only test example.com. Avoid destructive traffic.", prompt)
        self.assertIn("Do not brute force.", prompt)
        self.assertTrue(prompt.endswith("BASE PROMPT"))


class GuardrailEnforcementTests(TestCase):
    def test_blocks_out_of_scope_host(self):
        scan = ScanRun.objects.create(
            target_url="https://app.example.com",
            config={
                "guardrail": normalize_guardrail_text(
                    "In scope: app.example.com\nOut of scope: admin.example.com"
                )
            },
        )

        violation = _guardrail_violation(
            scan,
            "http_request",
            {"url": "https://admin.example.com/private", "method": "GET"},
        )

        self.assertIn("out of scope", violation.lower())

    def test_blocks_scanner_when_policy_forbids_automation(self):
        scan = ScanRun.objects.create(
            target_url="https://app.example.com",
            config={
                "guardrail": normalize_guardrail_text(
                    "In scope: app.example.com\nDo not use automated scanners or noisy automation."
                )
            },
        )

        violation = _guardrail_violation(
            scan,
            "nuclei_scan",
            {"target_url": "https://app.example.com"},
        )

        self.assertIn("blocked tool", violation.lower())
        self.assertIn("nuclei_scan", violation)

    def test_warns_parallel_probe_above_recommended_rate_limit_in_balanced_mode(self):
        scan = ScanRun.objects.create(
            target_url="https://app.example.com",
            config={
                "guardrail": normalize_guardrail_text(
                    "In scope: app.example.com\nRate limit your requests and avoid noisy automation."
                )
            },
        )

        decision = _guardrail_decision(
            scan,
            "multi_http_probe",
            {
                "requests_json": '[{"url":"https://app.example.com/a","method":"GET"}]',
                "max_concurrent": 8,
            },
        )

        self.assertEqual(decision["action"], "warn")
        self.assertIn("max_concurrent", decision["messages"][0])

    def test_blocks_parallel_probe_above_explicit_limit(self):
        scan = ScanRun.objects.create(
            target_url="https://app.example.com",
            config={
                "guardrail": normalize_guardrail_text(
                    "In scope: app.example.com\nDo not send noisy automation or burst traffic. Rate limit your requests."
                )
            },
        )

        violation = _guardrail_violation(
            scan,
            "multi_http_probe",
            {
                "requests_json": '[{"url":"https://app.example.com/a","method":"GET"}]',
                "max_concurrent": 8,
            },
        )

        self.assertIn("max_concurrent", violation)

    def test_blocks_out_of_scope_url_prefix(self):
        scan = ScanRun.objects.create(
            target_url="https://app.example.com",
            config={
                "guardrail": normalize_guardrail_text(
                    "Allowed: https://app.example.com/api\nOut of scope: https://app.example.com/admin"
                )
            },
        )

        violation = _guardrail_violation(
            scan,
            "browser_navigate",
            {"url": "https://app.example.com/admin/settings"},
        )

        self.assertIn("out-of-scope", violation)

    def test_blocks_prefix_boundary_bypass(self):
        scan = ScanRun.objects.create(
            target_url="https://app.example.com",
            config={
                "guardrail": normalize_guardrail_text(
                    "Allowed: https://app.example.com/api"
                )
            },
        )

        violation = _guardrail_violation(
            scan,
            "http_request",
            {"url": "https://app.example.com/api-admin/users", "method": "GET"},
        )

        self.assertIn("outside the declared in-scope url prefixes", violation.lower())

    def test_exact_host_scope_does_not_allow_subdomain(self):
        scan = ScanRun.objects.create(
            target_url="https://app.example.com",
            config={
                "guardrail": normalize_guardrail_text("Allowed: app.example.com")
            },
        )

        violation = _guardrail_violation(
            scan,
            "http_request",
            {"url": "https://foo.app.example.com", "method": "GET"},
        )

        self.assertIn("outside the declared in-scope hosts", violation.lower())

    def test_wildcard_host_scope_allows_subdomain(self):
        scan = ScanRun.objects.create(
            target_url="https://app.example.com",
            config={
                "guardrail": normalize_guardrail_text("Allowed: *.example.com")
            },
        )

        decision = _guardrail_decision(
            scan,
            "http_request",
            {"url": "https://foo.example.com", "method": "GET"},
        )

        self.assertEqual(decision["action"], "allow")

    @patch("api.tool_bridge._run_cmd")
    @patch("api.tool_bridge._tool_available", return_value=True)
    def test_tool_bridge_blocks_direct_scanner_execution(self, _tool_available, run_cmd):
        scan = ScanRun.objects.create(
            target_url="https://app.example.com",
            config={
                "guardrail": normalize_guardrail_text(
                    "Allowed: app.example.com\nDo not use automated scanners."
                )
            },
        )

        result = tool_bridge.nuclei_scan("https://app.example.com", scan_run=scan)

        self.assertIn("Guardrail blocked tool", result["error"])
        run_cmd.assert_not_called()

    @patch("requests.sessions.Session.get")
    def test_verifier_http_executor_blocks_out_of_scope_request(self, session_get):
        scan = ScanRun.objects.create(
            target_url="https://app.example.com",
            config={
                "guardrail": normalize_guardrail_text(
                    "Allowed: https://app.example.com/api\nOut of scope: https://app.example.com/admin"
                )
            },
        )

        executor = AttackExecutor(scan.target_url, scan_run=scan)
        result = executor.execute("/admin/panel", "GET", "q", "1")

        self.assertIn("Guardrail blocked URL", result["error"])
        session_get.assert_not_called()
