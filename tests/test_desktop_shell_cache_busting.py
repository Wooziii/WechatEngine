import unittest
import re
from pathlib import Path


PY = Path(__file__).resolve().parents[1] / "desktop_shell.py"
TEXT = PY.read_text(encoding="utf-8")
MONITOR_PY = Path(__file__).resolve().parents[1] / "monitor_web.py"
MONITOR_TEXT = MONITOR_PY.read_text(encoding="utf-8")


class DesktopShellCacheBustingTests(unittest.TestCase):
    def test_desktop_shell_disables_web_cache(self):
      self.assertIn("QWebEngineProfile.HttpCacheType.NoCache", TEXT)

    def test_desktop_shell_appends_timestamp_when_loading_backend(self):
      self.assertIn("_ts=", TEXT)
      self.assertIn("time.time()", TEXT)

    def test_desktop_shell_forces_loopback_and_disables_browser_mode(self):
      self.assertIn("--desktop-shell", TEXT)
      self.assertIn('replace("localhost", "127.0.0.1")', TEXT)

    def test_desktop_shell_defers_tray_hide_until_after_initial_show(self):
      self.assertIn("self._tray_hide_ready = False", TEXT)
      self.assertIn("QTimer.singleShot(0, self._show_main_window)", TEXT)
      self.assertIn("if not self._tray_hide_ready:", TEXT)

    def test_desktop_shell_has_webview_reveal_watchdog_for_stuck_loads(self):
      self.assertIn("self._reveal_timer = QTimer(self)", TEXT)
      self.assertIn("self._reveal_timer.timeout.connect(self._fallback_reveal_web_view)", TEXT)
      self.assertIn("urllib.request.urlopen", TEXT)
      self.assertIn("def _fallback_reveal_web_view(self) -> None:", TEXT)

    def test_desktop_shell_reveals_webview_before_loading_backend_page(self):
      self.assertIn("self.stack.setCurrentIndex(1)", TEXT)
      self.assertIn("self.web_view.show()", TEXT)

    def test_desktop_shell_defaults_webview_zoom_to_ninety_percent(self):
      self.assertIn("self.web_view.setZoomFactor(0.9)", TEXT)

    def test_desktop_shell_bootstraps_html_via_python_fetch_before_webview_network_load(self):
      self.assertIn("self.web_view.setHtml(", TEXT)
      self.assertIn('html bootstrap fetch failed', TEXT)

    def test_desktop_shell_loading_page_has_visual_progress_bar_and_stage_updates(self):
      self.assertIn("QProgressBar", TEXT)
      self.assertRegex(TEXT, re.compile(r"self\.loading_stage_label = QLabel\(\"正在准备启动阶段", re.S))
      self.assertRegex(TEXT, re.compile(r"self\.loading_progress = QProgressBar\(loading_page\)", re.S))
      self.assertRegex(TEXT, re.compile(r"def _set_boot_phase\(self,\s*percent:\s*int,\s*stage:\s*str,\s*detail:\s*str = [\"']{2}\)\s*->\s*None:", re.S))
      self.assertRegex(TEXT, re.compile(r"_set_boot_phase\(12,\s*\"启动本地服务\"", re.S))
      self.assertRegex(TEXT, re.compile(r"_set_boot_phase\(58,\s*\"服务已启动\"", re.S))
      self.assertRegex(TEXT, re.compile(r"_set_boot_phase\(100,\s*\"主界面已就绪\"", re.S))

    def test_desktop_shell_opens_external_links_via_system_browser(self):
      self.assertIn("QDesktopServices", TEXT)
      self.assertIn("def acceptNavigationRequest", TEXT)
      self.assertIn("def createWindow", TEXT)
      self.assertIn("QDesktopServices.openUrl", TEXT)

    def test_desktop_shell_uses_dedicated_backend_port_and_backend_honors_override(self):
      self.assertIn("TOPICENGINE_WEB_PORT", TEXT)
      self.assertIn("socket.socket", TEXT)
      self.assertRegex(TEXT, re.compile(r"env\.insert\(\"TOPICENGINE_WEB_PORT\",\s*str\(self\._requested_backend_port\)\)", re.S))
      self.assertRegex(TEXT, re.compile(r"env\.insert\(\"TOPICENGINE_PARENT_PID\",\s*str\(os\.getpid\(\)\)\)", re.S))
      self.assertIn("TOPICENGINE_WEB_PORT", MONITOR_TEXT)
      self.assertRegex(MONITOR_TEXT, re.compile(r"os\.environ\.get\(\"TOPICENGINE_WEB_PORT\"\)", re.S))
      self.assertIn("TOPICENGINE_PARENT_PID", MONITOR_TEXT)
      self.assertIn("def _start_parent_watchdog():", MONITOR_TEXT)
      self.assertIn("os._exit(0)", MONITOR_TEXT)

    def test_desktop_shell_branding_uses_wechatengine_names(self):
      self.assertIn('APP_NAME = "WechatEngine"', TEXT)
      self.assertIn('APP_ID = "WechatEngine.DesktopShell"', TEXT)
      self.assertIn('BACKEND_EXE = "WechatEngineCore.exe"', TEXT)
      self.assertIn('self.setWindowTitle("WechatEngine 桌面版")', TEXT)
      self.assertIn('self.tray_icon.setToolTip("WechatEngine")', TEXT)
      self.assertIn('print("  WechatEngine WeChat Monitor (WAL + SSE)"', MONITOR_TEXT)


if __name__ == "__main__":
    unittest.main()
