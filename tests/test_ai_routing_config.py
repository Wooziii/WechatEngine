import unittest

import monitor_web as mw


class AiRoutingConfigTests(unittest.TestCase):
    def test_normalize_ai_provider_config_adds_default_surface_routes(self):
        cfg = mw._normalize_ai_provider_config({})
        self.assertIn("surface_routes", cfg)
        self.assertEqual(cfg["surface_routes"]["live_alert"], "shared_api")
        self.assertEqual(cfg["surface_routes"]["sidebar"], "claude_cli")
        self.assertEqual(cfg["surface_routes"]["insight"], "shared_api")

    def test_legacy_claude_cli_provider_migrates_to_surface_routes(self):
        cfg = mw._normalize_ai_provider_config({"provider": "claude_cli"})
        self.assertEqual(cfg["surface_routes"]["sidebar"], "claude_cli")
        self.assertEqual(cfg["surface_routes"]["insight"], "claude_cli")
        self.assertEqual(cfg["surface_routes"]["live_alert"], "shared_api")

    def test_resolve_surface_provider_uses_claude_for_sidebar_route(self):
        cfg = mw._resolve_ai_provider_config_for_surface(
            "sidebar",
            override={
                "provider": "openai_compat",
                "base_url": "https://example.com/v1",
                "api_key": "sk-test",
                "model": "qwen-test",
                "surface_routes": {
                    "sidebar": "claude_cli",
                    "insight": "shared_api",
                    "live_alert": "shared_api",
                },
            },
        )
        self.assertEqual(cfg["provider"], "claude_cli")
        self.assertEqual(cfg["model"], "claude_cli")
        self.assertEqual(cfg["base_url"], "")
        self.assertEqual(cfg["api_key"], "")

    def test_resolve_surface_provider_keeps_shared_api_for_insight(self):
        cfg = mw._resolve_ai_provider_config_for_surface(
            "insight",
            override={
                "provider": "anthropic_compat",
                "base_url": "https://anthropic.example.com/v1",
                "api_key": "sk-ant-test",
                "model": "claude-sonnet-test",
                "surface_routes": {
                    "sidebar": "claude_cli",
                    "insight": "shared_api",
                    "live_alert": "shared_api",
                },
            },
        )
        self.assertEqual(cfg["provider"], "anthropic_compat")
        self.assertEqual(cfg["model"], "claude-sonnet-test")
        self.assertEqual(cfg["base_url"], "https://anthropic.example.com/v1")


if __name__ == "__main__":
    unittest.main()
