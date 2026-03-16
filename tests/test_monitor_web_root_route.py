import unittest
from pathlib import Path


PY = Path(__file__).resolve().parents[1] / "monitor_web.py"
TEXT = PY.read_text(encoding="utf-8")


class MonitorWebRootRouteTests(unittest.TestCase):
    def test_root_route_uses_parsed_path_for_cache_busted_urls(self):
        self.assertIn("parsed_path = urllib.parse.urlparse(self.path)", TEXT)
        self.assertIn("request_path = parsed_path.path or '/'", TEXT)
        self.assertIn("if request_path in ('/', '/index.html'):", TEXT)

    def test_desktop_shell_mode_skips_browser_autolaunch(self):
        self.assertIn('def _has_cli_flag(flag):', TEXT)
        self.assertIn('return flag in sys.argv[1:]', TEXT)
        self.assertIn('if _has_cli_flag("--desktop-shell"):', TEXT)
        self.assertIn('if _should_open_browser():', TEXT)


if __name__ == "__main__":
    unittest.main()
