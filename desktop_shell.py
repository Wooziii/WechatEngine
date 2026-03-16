import json
import os
import re
import socket
import sys
import time
import urllib.request
from pathlib import Path

try:
    import winreg
except ImportError:  # pragma: no cover - non-Windows fallback
    winreg = None

from PySide6.QtCore import QEvent, QProcess, QProcessEnvironment, QSize, Qt, QTimer, QUrl
from PySide6.QtGui import QAction, QCloseEvent, QDesktopServices, QIcon
from PySide6.QtWebEngineCore import QWebEnginePage, QWebEngineProfile
from PySide6.QtWebEngineWidgets import QWebEngineView
from PySide6.QtWidgets import (
    QApplication,
    QFrame,
    QLabel,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QStackedWidget,
    QSystemTrayIcon,
    QVBoxLayout,
    QWidget,
)


APP_NAME = "WechatEngine"
APP_VERSION = "v2026.03.15"
APP_ID = "WechatEngine.DesktopShell"
RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
BACKEND_EXE = "WechatEngineCore.exe"
BACKEND_SCRIPT = "monitor_web.py"
ICON_FILE = "WechatEngine.ico"
SETTINGS_FILE = "desktop_settings.json"
READY_URL_RE = re.compile(r"=>\s+(http://(?:127\.0\.0\.1|localhost):\d+)")
MAX_LOG_LINES = 400
DEFAULT_WEB_ZOOM = 1.0
ANALYSIS_WEB_ZOOM = 0.9


class LoggingWebEnginePage(QWebEnginePage):
    def __init__(self, owner):
        super().__init__(owner)
        self._owner = owner

    def javaScriptConsoleMessage(self, level, message, line_number, source_id):
        if self._owner:
            self._owner._append_log(f"[web][console] {message} ({source_id}:{line_number})")
        super().javaScriptConsoleMessage(level, message, line_number, source_id)

    def acceptNavigationRequest(self, url, navigation_type, is_main_frame):
        if self._owner and self._owner._should_open_external_url(url):
            link_clicked = navigation_type == QWebEnginePage.NavigationType.NavigationTypeLinkClicked
            if link_clicked or not is_main_frame:
                self._owner._open_external_url(url)
                return False
        return super().acceptNavigationRequest(url, navigation_type, is_main_frame)

    def createWindow(self, _window_type):
        return ExternalLinkPage(self._owner, self.profile())


class ExternalLinkPage(QWebEnginePage):
    def __init__(self, owner, profile):
        super().__init__(profile, owner)
        self._owner = owner

    def acceptNavigationRequest(self, url, navigation_type, is_main_frame):
        if self._owner:
            self._owner._open_external_url(url)
        return False


def _set_windows_app_id():
    if os.name != "nt":
        return
    try:
        import ctypes

        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(APP_ID)
    except Exception:
        pass


def _resource_base_dir():
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS)
    return Path(__file__).resolve().parent


def _runtime_base_dir():
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


RESOURCE_BASE_DIR = _resource_base_dir()
RUNTIME_BASE_DIR = _runtime_base_dir()


def _icon_path() -> Path | None:
    candidates = [
        RUNTIME_BASE_DIR / ICON_FILE,
        RESOURCE_BASE_DIR / ICON_FILE,
    ]
    for path in candidates:
        if path.exists():
            return path
    return None


def _settings_path() -> Path:
    return RUNTIME_BASE_DIR / SETTINGS_FILE


def _load_settings() -> dict:
    default = {
        "width": 1380,
        "height": 880,
        "hide_notice_shown": False,
    }
    path = _settings_path()
    if not path.exists():
        return default
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default
    if not isinstance(data, dict):
        return default
    default.update(data)
    return default


def _save_settings(data: dict) -> None:
    try:
        _settings_path().write_text(
            json.dumps(data, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
    except Exception:
        pass


def _launch_command(start_minimized: bool) -> str:
    if getattr(sys, "frozen", False):
        parts = [str(Path(sys.executable).resolve())]
    else:
        pythonw = Path(sys.executable)
        pythonw_candidate = pythonw.with_name("pythonw.exe")
        if pythonw_candidate.exists():
            pythonw = pythonw_candidate
        parts = [str(pythonw), str(Path(__file__).resolve())]
    if start_minimized:
        parts.append("--minimized")
    return " ".join(f'"{part}"' for part in parts)


def _read_autostart_value() -> str | None:
    if winreg is None:
        return None
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_READ) as key:
            value, _ = winreg.QueryValueEx(key, APP_NAME)
            return str(value or "").strip() or None
    except FileNotFoundError:
        return None
    except OSError:
        return None


def is_autostart_enabled() -> bool:
    return bool(_read_autostart_value())


def set_autostart_enabled(enabled: bool) -> None:
    if winreg is None:
        raise RuntimeError("当前平台不支持注册表开机启动设置。")
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
        if enabled:
            winreg.SetValueEx(key, APP_NAME, 0, winreg.REG_SZ, _launch_command(start_minimized=True))
        else:
            try:
                winreg.DeleteValue(key, APP_NAME)
            except FileNotFoundError:
                pass


class WechatEngineDesktop(QMainWindow):
    def __init__(self, start_minimized: bool = False):
        super().__init__()
        self.settings_data = _load_settings()
        self.start_minimized = start_minimized
        self.backend_process: QProcess | None = None
        self.backend_url = ""
        self._requested_backend_port = 0
        self._backend_buffer = ""
        self._log_lines: list[str] = []
        self._quitting = False
        self._backend_shutdown_expected = False
        self._tray_hide_ready = False
        self._debug_log_path = RUNTIME_BASE_DIR / "desktop_shell.log"
        try:
            self._debug_log_path.write_text("", encoding="utf-8")
        except Exception:
            pass

        self.setWindowTitle(f"WechatEngine 桌面版 · {APP_VERSION}")
        self.resize(
            int(self.settings_data.get("width", 1380)),
            int(self.settings_data.get("height", 880)),
        )

        icon_path = _icon_path()
        self.app_icon = QIcon(str(icon_path)) if icon_path else self.style().standardIcon(self.style().StandardPixmap.SP_ComputerIcon)
        self.setWindowIcon(self.app_icon)

        self._init_ui()
        self._init_tray()
        self._start_backend()

        if self.start_minimized and self.tray_icon and self.tray_icon.isVisible():
            self._tray_hide_ready = True
            QTimer.singleShot(0, self.hide)
        else:
            QTimer.singleShot(0, self._show_main_window)

    def _init_ui(self) -> None:
        self.stack = QStackedWidget(self)
        self.setCentralWidget(self.stack)

        loading_page = QWidget(self)
        loading_page.setObjectName("loadingPage")
        loading_layout = QVBoxLayout(loading_page)
        loading_layout.setContentsMargins(28, 28, 28, 28)
        loading_layout.setSpacing(16)

        loading_card = QFrame(loading_page)
        loading_card.setObjectName("loadingCard")
        card_layout = QVBoxLayout(loading_card)
        card_layout.setContentsMargins(24, 24, 24, 24)
        card_layout.setSpacing(12)

        self.loading_stage_label = QLabel("正在准备启动阶段", loading_card)
        self.loading_stage_label.setObjectName("loadingStage")
        self.loading_stage_label.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        self.loading_stage_label.setWordWrap(True)

        self.loading_label = QLabel("正在启动本地服务...", loading_card)
        self.loading_label.setObjectName("loadingTitle")
        self.loading_label.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        self.loading_label.setWordWrap(True)

        self.loading_detail_label = QLabel("首次启动会读取本地服务、缓存和主界面资源。", loading_card)
        self.loading_detail_label.setObjectName("loadingDetail")
        self.loading_detail_label.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        self.loading_detail_label.setWordWrap(True)

        self.loading_progress = QProgressBar(loading_page)
        self.loading_progress.setRange(0, 100)
        self.loading_progress.setValue(8)
        self.loading_progress.setFormat("%p%")
        self.loading_progress.setTextVisible(True)

        self.log_view = QPlainTextEdit(loading_card)
        self.log_view.setReadOnly(True)
        self.log_view.setPlaceholderText("启动日志会显示在这里。")
        self.log_view.setMinimumHeight(220)

        card_layout.addWidget(self.loading_stage_label)
        card_layout.addWidget(self.loading_label)
        card_layout.addWidget(self.loading_detail_label)
        card_layout.addWidget(self.loading_progress)
        card_layout.addWidget(self.log_view, 1)

        loading_layout.addStretch(1)
        loading_layout.addWidget(loading_card, 1)
        loading_layout.addStretch(1)
        loading_page.setStyleSheet(
            """
            QWidget#loadingPage {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #f5f7fb, stop:1 #edf3ff);
            }
            QFrame#loadingCard {
                background: rgba(255, 255, 255, 0.96);
                border: 1px solid rgba(217, 226, 238, 0.96);
                border-radius: 24px;
            }
            QLabel#loadingStage {
                color: #4f46e5;
                font-size: 13px;
                font-weight: 700;
            }
            QLabel#loadingTitle {
                color: #0f172a;
                font-size: 24px;
                font-weight: 800;
            }
            QLabel#loadingDetail {
                color: #64748b;
                font-size: 13px;
                line-height: 1.5;
            }
            QProgressBar {
                min-height: 14px;
                border: 1px solid rgba(217, 226, 238, 0.96);
                border-radius: 999px;
                background: #e8eef7;
                text-align: right;
                color: #4338ca;
                font-size: 11px;
                font-weight: 700;
                padding-right: 8px;
            }
            QProgressBar::chunk {
                border-radius: 999px;
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #4f46e5, stop:0.55 #7c3aed, stop:1 #22c55e);
            }
            QPlainTextEdit {
                border-radius: 16px;
                border: 1px solid rgba(226, 232, 240, 0.96);
                background: #f8fafc;
                color: #334155;
                padding: 10px 12px;
                font-size: 12px;
            }
            """
        )

        self.web_view = QWebEngineView(self)
        self.web_view.setZoomFactor(DEFAULT_WEB_ZOOM)
        self.web_page = LoggingWebEnginePage(self)
        self.web_view.setPage(self.web_page)
        profile = self.web_page.profile()
        try:
            profile.setHttpCacheType(QWebEngineProfile.HttpCacheType.NoCache)
        except Exception:
            pass
        try:
            profile.clearHttpCache()
        except Exception:
            pass
        self._reveal_timer = QTimer(self)
        self._reveal_timer.setSingleShot(True)
        self._reveal_timer.timeout.connect(self._fallback_reveal_web_view)
        self.web_view.loadStarted.connect(self._on_page_load_started)
        self.web_view.loadFinished.connect(self._on_page_loaded)
        self.web_view.urlChanged.connect(self._on_url_changed)
        self.web_view.titleChanged.connect(self._on_title_changed)
        self.web_page.renderProcessTerminated.connect(self._on_render_process_terminated)

        self.stack.addWidget(loading_page)
        self.stack.addWidget(self.web_view)
        self.stack.setCurrentIndex(0)

        self.statusBar().showMessage("等待服务启动")
        self._set_boot_phase(8, "正在准备启动阶段", "首次启动会读取本地服务、缓存和主界面资源。")

    def _set_boot_phase(self, percent: int, stage: str, detail: str = "") -> None:
        pct = max(0, min(100, int(percent or 0)))
        stage_text = str(stage or "").strip() or "正在准备启动阶段"
        detail_text = str(detail or "").strip() or stage_text
        if hasattr(self, "loading_stage_label") and self.loading_stage_label:
            self.loading_stage_label.setText(stage_text)
        if hasattr(self, "loading_label") and self.loading_label:
            self.loading_label.setText(detail_text)
        if hasattr(self, "loading_detail_label") and self.loading_detail_label:
            self.loading_detail_label.setText(f"启动进度 {pct}% · 请稍候，主界面正在完成首屏准备。")
        if hasattr(self, "loading_progress") and self.loading_progress:
            self.loading_progress.setValue(pct)

    def _load_backend_page(self) -> None:
        if not self.backend_url:
            return
        self._set_boot_phase(68, "加载主界面", "本地服务已就绪，正在注入首屏页面资源。")
        self._apply_zoom_for_url(QUrl(self.backend_url))
        try:
            self.web_view.page().profile().clearHttpCache()
        except Exception:
            pass
        sep = "&" if "?" in self.backend_url else "?"
        fresh_url = f"{self.backend_url}{sep}_ts={int(time.time() * 1000)}"
        try:
            with urllib.request.urlopen(fresh_url, timeout=5) as response:
                html_text = response.read().decode("utf-8", errors="replace")
            self.web_view.setHtml(html_text, QUrl(self.backend_url.rstrip("/") + "/"))
            return
        except Exception as exc:
            self._append_log(f"[web] html bootstrap fetch failed: {exc}")
        self.web_view.load(QUrl(fresh_url))

    def _effective_url_port(self, url: QUrl) -> int:
        if not isinstance(url, QUrl):
            return -1
        port = int(url.port())
        if port > 0:
            return port
        if url.scheme() == "https":
            return 443
        if url.scheme() == "http":
            return 80
        return -1

    def _should_open_external_url(self, url: QUrl) -> bool:
        if not isinstance(url, QUrl) or not url.isValid():
            return False
        if url.scheme() not in {"http", "https"}:
            return False
        if not self.backend_url:
            return True
        backend = QUrl(self.backend_url)
        if not backend.isValid():
            return True
        same_host = url.host() in {backend.host(), "127.0.0.1", "localhost"} and backend.host() in {url.host(), "127.0.0.1", "localhost"}
        same_port = self._effective_url_port(url) == self._effective_url_port(backend)
        same_scheme = url.scheme() == backend.scheme()
        return not (same_host and same_port and same_scheme)

    def _open_external_url(self, url: QUrl) -> None:
        if not isinstance(url, QUrl) or not url.isValid():
            return
        self._append_log(f"[web] open external: {url.toString()}")
        QDesktopServices.openUrl(url)

    def _on_page_load_started(self) -> None:
        self._append_log("[web] load started")
        self._set_boot_phase(76, "渲染主界面", "浏览器内核正在渲染首屏，请稍候。")
        self._reveal_timer.start(3500)

    def _fallback_reveal_web_view(self) -> None:
        if not self.backend_url or self.stack.currentIndex() == 1:
            return
        try:
            with urllib.request.urlopen(self.backend_url, timeout=2) as response:
                status_code = int(getattr(response, "status", 200) or 200)
            if status_code >= 400:
                return
        except Exception:
            return
        self.stack.setCurrentIndex(1)
        self._append_log("[web] fallback reveal triggered")
        self._set_boot_phase(88, "主界面可见", "页面稍慢，已优先切换到主界面继续完成加载。")
        self.statusBar().showMessage("页面加载较慢，已切换到主界面")
        QTimer.singleShot(1200, self._probe_dom_state)

    def _on_url_changed(self, url: QUrl) -> None:
        self._apply_zoom_for_url(url)
        self._append_log(f"[web] url changed: {url.toString()}")

    def _on_title_changed(self, title: str) -> None:
        if title:
            self._append_log(f"[web] title: {title}")

    def _desired_zoom_factor(self, url: QUrl | None = None) -> float:
        if isinstance(url, QUrl) and url.isValid():
            path = str(url.path() or "").strip().lower()
            if path.startswith("/analysis"):
                return ANALYSIS_WEB_ZOOM
        return DEFAULT_WEB_ZOOM

    def _apply_zoom_for_url(self, url: QUrl | None = None) -> None:
        target = self._desired_zoom_factor(url)
        try:
            current = float(self.web_view.zoomFactor())
        except Exception:
            current = DEFAULT_WEB_ZOOM
        if abs(current - target) < 0.001:
            return
        self.web_view.setZoomFactor(target)
        if isinstance(url, QUrl) and url.isValid():
            self._append_log(f"[web] zoom -> {target:.2f} ({url.path() or '/'})")
        else:
            self._append_log(f"[web] zoom -> {target:.2f}")

    def _on_render_process_terminated(self, termination_status, exit_code: int) -> None:
        self._append_log(f"[web] renderer terminated: {termination_status} / {exit_code}")

    def _probe_dom_state(self) -> None:
        if not self.backend_url:
            return
        script = """
(() => ({
  href: location.href,
  readyState: document.readyState,
  title: document.title,
  childCount: document.body ? document.body.children.length : -1,
  textSample: ((document.body && document.body.innerText) || '').slice(0, 160)
}))();
"""
        self.web_view.page().runJavaScript(script, self._handle_dom_probe)

    def _handle_dom_probe(self, result) -> None:
        self._append_log(f"[web] dom probe: {result!r}")
        if isinstance(result, dict):
            ready_state = str(result.get("readyState", "") or "").strip().lower()
            sample = str(result.get("textSample", "") or "").strip()
            if ready_state in {"interactive", "complete"}:
                detail = "首屏 DOM 已完成挂载，正在同步最后的页面状态。"
                if sample:
                    detail = f"首屏内容已出现：{sample[:40]}"
                self._set_boot_phase(96, "主界面即将完成", detail)

    def _init_tray(self) -> None:
        self.tray_icon: QSystemTrayIcon | None = None
        if not QSystemTrayIcon.isSystemTrayAvailable():
            return

        tray_menu = QMenu(self)

        open_action = QAction("打开主界面", self)
        open_action.triggered.connect(self._show_main_window)
        tray_menu.addAction(open_action)

        hide_action = QAction("隐藏到托盘", self)
        hide_action.triggered.connect(self.hide)
        tray_menu.addAction(hide_action)

        restart_action = QAction("重启本地服务", self)
        restart_action.triggered.connect(self._restart_backend)
        tray_menu.addAction(restart_action)

        tray_menu.addSeparator()

        self.autostart_action = QAction("开机启动", self)
        self.autostart_action.setCheckable(True)
        self.autostart_action.setChecked(is_autostart_enabled())
        self.autostart_action.triggered.connect(self._toggle_autostart)
        tray_menu.addAction(self.autostart_action)

        tray_menu.addSeparator()

        quit_action = QAction("退出", self)
        quit_action.triggered.connect(self._quit_app)
        tray_menu.addAction(quit_action)

        self.tray_icon = QSystemTrayIcon(self.app_icon, self)
        self.tray_icon.setToolTip(f"WechatEngine {APP_VERSION}")
        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.activated.connect(self._on_tray_activated)
        self.tray_icon.show()

    def _append_log(self, text: str) -> None:
        clean = text.rstrip()
        if not clean:
            return
        self._log_lines.append(clean)
        if len(self._log_lines) > MAX_LOG_LINES:
            self._log_lines = self._log_lines[-MAX_LOG_LINES:]
        self.log_view.setPlainText("\n".join(self._log_lines))
        self.log_view.verticalScrollBar().setValue(self.log_view.verticalScrollBar().maximum())
        try:
            with self._debug_log_path.open("a", encoding="utf-8") as fh:
                fh.write(clean + "\n")
        except Exception:
            pass

    def _backend_command(self) -> tuple[str, list[str]]:
        if getattr(sys, "frozen", False):
            backend_path = RUNTIME_BASE_DIR / BACKEND_EXE
            if not backend_path.exists():
                raise FileNotFoundError(f"未找到后端程序: {backend_path}")
            return str(backend_path), ["--desktop-shell"]

        backend_path = RUNTIME_BASE_DIR / BACKEND_SCRIPT
        if not backend_path.exists():
            raise FileNotFoundError(f"未找到后端脚本: {backend_path}")
        return sys.executable, [str(backend_path), "--desktop-shell"]

    def _reserve_backend_port(self) -> int:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            sock.listen(1)
            return int(sock.getsockname()[1])

    def _start_backend(self) -> None:
        self._stop_backend()
        self.backend_url = ""
        self._requested_backend_port = 0
        self._backend_buffer = ""
        self.stack.setCurrentIndex(0)
        self._set_boot_phase(12, "启动本地服务", "正在拉起 WechatEngineCore 并申请本地通信端口。")
        self.statusBar().showMessage("正在启动本地服务")

        try:
            program, args = self._backend_command()
        except Exception as exc:
            self._show_backend_error(str(exc))
            return
        try:
            self._requested_backend_port = self._reserve_backend_port()
        except Exception as exc:
            self._show_backend_error(f"无法为本地服务分配端口: {exc}")
            return
        self._set_boot_phase(20, "预留通信端口", f"已分配 127.0.0.1:{self._requested_backend_port}，等待服务响应。")

        process = QProcess(self)
        process.setProgram(program)
        process.setArguments(args)
        process.setWorkingDirectory(str(RUNTIME_BASE_DIR))
        process.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
        env = QProcessEnvironment.systemEnvironment()
        env.insert("TOPICENGINE_NO_BROWSER", "1")
        env.insert("TOPICENGINE_PARENT_PID", str(os.getpid()))
        env.insert("TOPICENGINE_WEB_PORT", str(self._requested_backend_port))
        env.insert("PYTHONUTF8", "1")
        env.insert("PYTHONIOENCODING", "utf-8")
        process.setProcessEnvironment(env)
        process.readyReadStandardOutput.connect(self._read_backend_output)
        process.finished.connect(self._on_backend_finished)
        process.errorOccurred.connect(self._on_backend_error)
        self._append_log(f"[backend] requested port: {self._requested_backend_port}")
        process.start()

        self.backend_process = process

        if not process.waitForStarted(5000):
            self._show_backend_error("本地服务进程启动失败。")
            return

    def _stop_backend(self) -> None:
        process = self.backend_process
        if not process:
            return
        self._backend_shutdown_expected = True
        for signal, slot in (
            (process.readyReadStandardOutput, self._read_backend_output),
            (process.finished, self._on_backend_finished),
            (process.errorOccurred, self._on_backend_error),
        ):
            try:
                signal.disconnect(slot)
            except Exception:
                pass
        if process.state() != QProcess.ProcessState.NotRunning:
            process.terminate()
            if not process.waitForFinished(4000):
                process.kill()
                process.waitForFinished(2000)
        process.deleteLater()
        self.backend_process = None
        self._backend_shutdown_expected = False

    def _read_backend_output(self) -> None:
        if not self.backend_process:
            return
        chunk = bytes(self.backend_process.readAllStandardOutput()).decode("utf-8", errors="ignore")
        if not chunk:
            return
        self._backend_buffer += chunk
        while "\n" in self._backend_buffer:
            line, self._backend_buffer = self._backend_buffer.split("\n", 1)
            self._handle_backend_line(line.strip())

    def _handle_backend_line(self, line: str) -> None:
        self._append_log(line)
        if not line:
            return
        match = READY_URL_RE.search(line)
        if match and not self.backend_url:
            self.backend_url = match.group(1).replace("localhost", "127.0.0.1")
            self._set_boot_phase(58, "服务已启动", f"本地服务已就绪，正在连接主界面。\n{self.backend_url}")
            self.statusBar().showMessage(f"服务已启动: {self.backend_url}")
            self.stack.setCurrentIndex(1)
            self.web_view.show()
            self._load_backend_page()

    def _on_page_loaded(self, ok: bool) -> None:
        self._reveal_timer.stop()
        self._append_log(f"[web] load finished: ok={ok}")
        if ok:
            self._set_boot_phase(100, "主界面已就绪", "本地服务和首屏界面均已完成准备。")
            self.stack.setCurrentIndex(1)
            self.statusBar().showMessage("已连接到本地服务")
            QTimer.singleShot(1200, self._probe_dom_state)
            return
        if self.backend_url:
            self._set_boot_phase(100, "界面加载失败", f"请检查本地服务是否可访问。\n{self.backend_url}")
            self.statusBar().showMessage("界面加载失败")
            self.stack.setCurrentIndex(0)

    def _on_backend_finished(self, exit_code: int, _exit_status) -> None:
        if self._quitting or self._backend_shutdown_expected:
            return
        message = f"本地服务已退出，退出码: {exit_code}"
        self._show_backend_error(message)

    def _on_backend_error(self, error) -> None:
        if self._quitting or self._backend_shutdown_expected:
            return
        self._show_backend_error(f"本地服务异常: {error}")

    def _show_backend_error(self, message: str) -> None:
        self._reveal_timer.stop()
        self._set_boot_phase(100, "启动失败", message)
        self.stack.setCurrentIndex(0)
        self.statusBar().showMessage("本地服务异常")
        self._append_log(message)

    def _toggle_autostart(self, checked: bool) -> None:
        try:
            set_autostart_enabled(checked)
        except Exception as exc:
            self.autostart_action.blockSignals(True)
            self.autostart_action.setChecked(is_autostart_enabled())
            self.autostart_action.blockSignals(False)
            QMessageBox.warning(self, "开机启动设置失败", str(exc))
            return
        state_text = "已开启" if checked else "已关闭"
        self.statusBar().showMessage(f"开机启动{state_text}", 5000)

    def _restart_backend(self) -> None:
        self.statusBar().showMessage("正在重启本地服务")
        self._start_backend()

    def _show_main_window(self) -> None:
        self.showNormal()
        self.raise_()
        self.activateWindow()
        QTimer.singleShot(300, self._arm_tray_hide)

    def _arm_tray_hide(self) -> None:
        self._tray_hide_ready = True

    def _on_tray_activated(self, reason: QSystemTrayIcon.ActivationReason) -> None:
        if reason in (
            QSystemTrayIcon.ActivationReason.Trigger,
            QSystemTrayIcon.ActivationReason.DoubleClick,
        ):
            if self.isVisible():
                self.hide()
            else:
                self._show_main_window()

    def _maybe_notify_hidden(self) -> None:
        if not self.tray_icon or not self.tray_icon.isVisible():
            return
        if self.settings_data.get("hide_notice_shown"):
            return
        self.tray_icon.showMessage(
            "WechatEngine",
            "窗口已隐藏到右下角托盘，双击托盘图标即可恢复。",
            QSystemTrayIcon.MessageIcon.Information,
            3000,
        )
        self.settings_data["hide_notice_shown"] = True
        _save_settings(self.settings_data)

    def changeEvent(self, event: QEvent) -> None:
        super().changeEvent(event)
        if event.type() != QEvent.Type.WindowStateChange:
            return
        if not self._tray_hide_ready:
            return
        if self.windowState() & Qt.WindowState.WindowMinimized and self.tray_icon and self.tray_icon.isVisible():
            QTimer.singleShot(0, self.hide)
            self._maybe_notify_hidden()

    def closeEvent(self, event: QCloseEvent) -> None:
        if not self._quitting and self.tray_icon and self.tray_icon.isVisible():
            event.ignore()
            self.hide()
            self._maybe_notify_hidden()
            return
        self.settings_data["width"] = int(self.size().width())
        self.settings_data["height"] = int(self.size().height())
        _save_settings(self.settings_data)
        super().closeEvent(event)

    def _quit_app(self) -> None:
        self._quitting = True
        self.close()
        self._stop_backend()
        if self.tray_icon:
            self.tray_icon.hide()
        QApplication.instance().quit()


def main() -> int:
    _set_windows_app_id()
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setQuitOnLastWindowClosed(False)

    window = WechatEngineDesktop(start_minimized="--minimized" in sys.argv[1:])
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
