import unittest

from api.strategy_core import (
    PrimitiveFact,
    infer_chain_family,
    primitive_category_for,
    score_chain_family,
)


class StrategyCoreTests(unittest.TestCase):
    def test_idor_maps_to_object_reference(self):
        self.assertEqual(
            primitive_category_for("idor", "/api/groups/123"),
            "object_reference",
        )

    def test_password_reset_route_forms_takeover_family(self):
        primitive = PrimitiveFact(
            category="workflow_bypass",
            endpoint="/api/v1/user/password/send-code",
            vuln_type="logic_flaw",
        )

        self.assertEqual(infer_chain_family(primitive), "password_reset_takeover")

    def test_unverified_chain_requests_deterministic_evidence(self):
        score = score_chain_family("group_access_chain", [
            PrimitiveFact(
                category="object_reference",
                vuln_type="idor",
                endpoint="/lms/admin/group/123",
                confidence=0.72,
            ),
        ])

        self.assertEqual(score.provider_hint, "claude")
        self.assertIn("deterministic verification", score.missing_evidence)
        self.assertIn("fresh authenticated persona/state", score.prerequisite_gaps)
        self.assertGreater(score.total_score, 0)

    def test_verified_code_heavy_chain_routes_to_codex(self):
        score = score_chain_family("file_path_chain", [
            PrimitiveFact(
                category="file",
                vuln_type="file_upload",
                endpoint="/api/assignment/image",
                confidence=0.91,
                status="verified",
            ),
        ])

        self.assertEqual(score.provider_hint, "codex")
        self.assertNotIn("deterministic verification", score.missing_evidence)
        self.assertIn(score.status, {"needs_recheck", "verified"})


if __name__ == "__main__":
    unittest.main()
