from unittest import TestCase

from api.llm_provider import (
    ModelSpec,
    _to_openai_input,
    estimate_cost_usd,
    missing_provider_message,
    resolve_model_spec,
)


class LLMProviderConfigTests(TestCase):
    def test_legacy_claude_model_defaults_to_anthropic(self):
        spec = resolve_model_spec("claude-sonnet-4-20250514")

        self.assertEqual(spec.provider, "anthropic")
        self.assertEqual(spec.model, "claude-sonnet-4-20250514")

    def test_provider_qualified_string(self):
        spec = resolve_model_spec("openai:gpt-example")

        self.assertEqual(spec.provider, "openai")
        self.assertEqual(spec.model, "gpt-example")

    def test_dict_config_aliases_codex_to_openai(self):
        spec = resolve_model_spec({"provider": "codex", "model": "gpt-example"})

        self.assertEqual(spec.provider, "openai")
        self.assertEqual(spec.model, "gpt-example")

    def test_missing_provider_message_names_expected_env_key(self):
        msg = missing_provider_message(ModelSpec(provider="openai", model="gpt-example"))

        self.assertIn("OPENAI_API_KEY", msg)
        self.assertIn("openai", msg)

    def test_cost_estimate_preserves_nonzero_default(self):
        cost = estimate_cost_usd(
            ModelSpec(provider="anthropic", model="claude-sonnet-4-20250514"),
            input_tokens=1000,
            output_tokens=1000,
        )

        self.assertGreater(cost, 0)


class OpenAIMessageConversionTests(TestCase):
    def test_tool_use_and_tool_result_convert_to_responses_items(self):
        converted = _to_openai_input([
            {
                "role": "assistant",
                "content": [
                    {
                        "type": "tool_use",
                        "id": "call_1",
                        "name": "search_knowledge",
                        "input": {"vuln_type": "sqli"},
                    }
                ],
            },
            {
                "role": "user",
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": "call_1",
                        "content": '{"patterns":[]}',
                    }
                ],
            },
        ])

        self.assertEqual(converted[0]["type"], "function_call")
        self.assertEqual(converted[0]["call_id"], "call_1")
        self.assertEqual(converted[0]["name"], "search_knowledge")
        self.assertEqual(converted[1]["type"], "function_call_output")
        self.assertEqual(converted[1]["call_id"], "call_1")
