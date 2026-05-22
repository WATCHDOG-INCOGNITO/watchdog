import unittest

from api.discovery_queue import build_queue_metadata, build_work_item_metadata


class DiscoveryQueueTests(unittest.TestCase):
    def test_exploit_step_scores_above_plain_endpoint(self):
        endpoint = build_queue_metadata(node_type="endpoint", depth=1)
        exploit_step = build_queue_metadata(
            node_type="exploit_step",
            vuln_type="sqli",
            depth=3,
            parent_status="confirmed",
        )

        self.assertGreater(exploit_step["priority_score"], endpoint["priority_score"])
        self.assertEqual(exploit_step["queue_lane"], "chain")

    def test_blocked_prerequisite_lowers_score(self):
        ready = build_queue_metadata(node_type="vuln", vuln_type="rce", context={"confidence": 1.0})
        blocked = build_queue_metadata(
            node_type="vuln",
            vuln_type="rce",
            context={"confidence": 1.0, "blocked_by": ["auth_session"]},
        )

        self.assertLess(blocked["priority_score"], ready["priority_score"])
        self.assertEqual(blocked["blocked_by"], ["auth_session"])

    def test_explicit_lane_and_provider_hint_are_respected(self):
        meta = build_queue_metadata(
            node_type="clue",
            context={"queue_lane": "recheck", "provider_hint": "codex"},
        )

        self.assertEqual(meta["queue_lane"], "recheck")
        self.assertEqual(meta["provider_hint"], "codex")
        self.assertEqual(meta["mission"]["lane"], "recheck")

    def test_work_item_metadata_derives_type_and_diversity(self):
        meta = build_work_item_metadata(
            node_type="vuln",
            vuln_type="idor",
            endpoint="/api/users/{id}",
            context={"technique": "persona_swap", "oracle": "idor_diff"},
            depth=2,
        )

        self.assertEqual(meta["work_type"], "hypothesis_test")
        self.assertEqual(meta["queue_lane"], "hypothesis")
        self.assertEqual(meta["oracle"], "idor_diff")
        self.assertIn("persona_swap", meta["diversity_key"])

    def test_blocked_work_item_gets_preconditions(self):
        meta = build_work_item_metadata(
            node_type="exploit_step",
            vuln_type="access_control",
            context={"preconditions": ["auth:admin"]},
        )

        self.assertEqual(meta["work_type"], "chain")
        self.assertEqual(meta["preconditions"], ["auth:admin"])
        self.assertLess(meta["priority_score"], 1.0)


if __name__ == "__main__":
    unittest.main()
