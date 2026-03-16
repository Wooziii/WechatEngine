"""
瀵邦喕淇婄€圭偞妞傚☉鍫熶紖閻╂垵鎯夐崳?- Web UI (SSE閹恒劑鈧?+ mtime濡偓濞?

http://localhost:5678
- 30ms鏉烆喛顕梂AL/DB閺傚洣娆㈤惃鍒磘ime閸欐ê瀵查敍鍦礎L閺勵垶顣╅崚鍡涘帳閸ュ搫鐣炬径褍鐨敍灞肩瑝閼崇晫鏁ize濡偓濞村绱?- 濡偓濞村鍩岄崣妯哄閸氬函绱伴崗銊╁櫤鐟欙絽鐦慏B + 閸忋劑鍣篧AL patch
- SSE 閺堝秴濮熼崳銊﹀腹闁?
"""
import builtins
import hashlib, struct, os, sys, json, time, sqlite3, io, threading, queue, re, glob, subprocess, uuid, shutil, base64, binascii, html, ctypes, zipfile, tempfile, importlib
import hmac as hmac_mod
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from Crypto.Cipher import AES
from Crypto.Util import Padding
import urllib.parse, urllib.request, urllib.error
import find_all_keys as key_extractor


def _safe_print(*args, **kwargs):
    try:
        builtins.print(*args, **kwargs)
    except Exception:
        pass


print = _safe_print

try:
    import zstandard as zstd
    _zstd_dctx = zstd.ZstdDecompressor()
except Exception:
    zstd = None
    _zstd_dctx = None


def _resource_base_dir():
    # PyInstaller one-file extracts bundled assets into _MEIPASS.
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return sys._MEIPASS
    return os.path.dirname(os.path.abspath(__file__))


def _runtime_base_dir():
    # Keep writable runtime files next to the executable when frozen.
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


RESOURCE_BASE_DIR = _resource_base_dir()
RUNTIME_BASE_DIR = _runtime_base_dir()


def _env_flag(name, default=False):
    value = os.environ.get(name)
    if value is None:
        return bool(default)
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def _has_cli_flag(flag):
    return flag in sys.argv[1:]


def _env_int(name, default=None):
    value = os.environ.get(name)
    if value is None:
        return default
    try:
        return int(str(value).strip())
    except Exception:
        return default


def _is_pid_alive(pid):
    try:
        pid = int(pid)
    except Exception:
        return False
    if pid <= 0:
        return False
    if os.name == "nt":
        SYNCHRONIZE = 0x00100000
        WAIT_TIMEOUT = 0x00000102
        handle = ctypes.windll.kernel32.OpenProcess(SYNCHRONIZE, False, pid)
        if not handle:
            return False
        try:
            state = ctypes.windll.kernel32.WaitForSingleObject(handle, 0)
            return state == WAIT_TIMEOUT
        finally:
            ctypes.windll.kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def _start_parent_watchdog():
    parent_pid = _env_int("TOPICENGINE_PARENT_PID", None)
    if not parent_pid:
        return

    def _watch():
        while True:
            time.sleep(2.0)
            if _is_pid_alive(parent_pid):
                continue
            print(f"[shutdown] parent process exited: pid={parent_pid}", flush=True)
            os._exit(0)

    threading.Thread(target=_watch, daemon=True, name="parent-watchdog").start()


def _web_host():
    if _has_cli_flag("--desktop-shell"):
        return "127.0.0.1"
    return "localhost"


def _should_open_browser():
    return (
        not _env_flag("TOPICENGINE_NO_BROWSER")
        and "--desktop-shell" not in sys.argv[1:]
        and "--no-browser" not in sys.argv[1:]
    )

PAGE_SZ = 4096
KEY_SZ = 32
SALT_SZ = 16
IV_SZ = 16
HMAC_SZ = 64
RESERVE_SZ = 80
SQLITE_HDR = b'SQLite format 3\x00'
WAL_HEADER_SZ = 32
WAL_FRAME_HEADER_SZ = 24

from config import load_config
_cfg = load_config()
DB_DIR = _cfg["db_dir"]
KEYS_FILE = _cfg["keys_file"]
CONTACT_CACHE = os.path.join(_cfg["decrypted_dir"], "contact", "contact.db")
DECRYPTED_SESSION = os.path.join(_cfg["decrypted_dir"], "session", "session.db")
DECRYPTED_MESSAGE_RESOURCE = os.path.join(_cfg["decrypted_dir"], "message", "message_resource.db")
DECRYPTED_MESSAGE_FTS = os.path.join(_cfg["decrypted_dir"], "message", "message_fts.db")
ATTACH_ROOT = os.path.join(os.path.dirname(DB_DIR), "msg", "attach")
EMOJI_CACHE_DIR = os.path.join(_cfg["decrypted_dir"], "_emoji_cache")

HEX32_RE_BYTES = re.compile(rb"[0-9a-f]{32}")
HEX32_RE_STR = re.compile(r"[0-9a-f]{32}")
WECHAT_MEDIA_V2_MAGIC_FULL = b"\x07\x08V2\x08\x07"
WECHAT_MEDIA_V1_MAGIC_FULL = b"\x07\x08V1\x08\x07"


def _parse_byte_value(value, default=0x88):
    try:
        if isinstance(value, str):
            return int(value.strip(), 0) & 0xFF
        return int(value) & 0xFF
    except Exception:
        return int(default) & 0xFF


IMAGE_AES_KEY = str(_cfg.get("image_aes_key", "") or "").strip()
IMAGE_XOR_KEY = _parse_byte_value(_cfg.get("image_xor_key", 0x88), 0x88)

# Load monitor page, preferring a runtime override next to the exe.
HTML_CANDIDATES = [
    os.path.join(RUNTIME_BASE_DIR, "monitor_web.html"),
    os.path.join(RESOURCE_BASE_DIR, "monitor_web.html"),
]
HTML_FILE = next(
    (path for path in HTML_CANDIDATES if os.path.exists(path)),
    HTML_CANDIDATES[-1],
)
with open(HTML_FILE, "r", encoding="utf-8") as f:
    HTML_PAGE = f.read()

ANALYSIS_HTML_CANDIDATES = [
    os.path.join(RUNTIME_BASE_DIR, "analysis_web.html"),
    os.path.join(RESOURCE_BASE_DIR, "analysis_web.html"),
]
ANALYSIS_HTML_FILE = next(
    (path for path in ANALYSIS_HTML_CANDIDATES if os.path.exists(path)),
    ANALYSIS_HTML_CANDIDATES[0],
)
try:
    with open(ANALYSIS_HTML_FILE, "r", encoding="utf-8") as f:
        ANALYSIS_PAGE = f.read()
except Exception:
    ANALYSIS_PAGE = """<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Analysis Page Missing</title>
  <style>
    body{font-family:Segoe UI,Microsoft YaHei,sans-serif;background:#f4f7fb;color:#12233a;margin:0}
    .wrap{max-width:760px;margin:48px auto;padding:28px;background:#fff;border:1px solid #d9e3f2;border-radius:14px;box-shadow:0 10px 30px rgba(17,34,68,.08)}
    h1{margin:0 0 14px;font-size:28px}
    p{line-height:1.7}
    code{background:#f0f4fb;padding:2px 6px;border-radius:6px}
    .actions{margin-top:18px;display:flex;gap:10px;flex-wrap:wrap}
    a.btn{display:inline-block;padding:10px 14px;border-radius:10px;text-decoration:none;border:1px solid #1d4ed8;color:#1d4ed8}
  </style>
</head>
<body>
  <div class="wrap">
    <h1>analysis_web.html 鏈壘鍒?/h1>
    <p>褰撳墠绋嬪簭宸插惎鍔紝浣嗗垎鏋愰〉闈㈡ā鏉挎枃浠剁己澶便€備綘浠嶅彲浠ュ厛浣跨敤娑堟伅闈㈡澘銆?/p>
    <p>淇鏂瑰紡锛氬皢 <code>analysis_web.html</code> 鏀惧埌绋嬪簭鍚岀洰褰曪紝鎴栦娇鐢ㄦ渶鏂板彂甯冨寘閲嶆柊瑙ｅ帇杩愯銆?/p>
    <div class="actions">
      <a class="btn" href="/">杩斿洖娑堟伅闈㈡澘</a>
      <a class="btn" href="/api/ai/status">妫€鏌?AI 鐘舵€?/a>
    </div>
  </div>
</body>
</html>"""

POLL_MS = 30  # 妤傛﹢顣舵潪顔款嚄WAL/DB閻ㄥ埓time閿?0ms娑撯偓濞?
DEFAULT_WEB_PORT = 8080
_requested_web_port = _env_int("TOPICENGINE_WEB_PORT", None)
if _requested_web_port is None and os.environ.get("TOPICENGINE_WEB_PORT") is not None:
    _requested_web_port = DEFAULT_WEB_PORT
PORT = int(_requested_web_port or _cfg.get("web_port", DEFAULT_WEB_PORT) or DEFAULT_WEB_PORT)
PORT_FALLBACKS = (8080, 8765, 9000, 18080, 0)

sse_clients = []
sse_lock = threading.Lock()
messages_log = []
messages_lock = threading.Lock()
message_db_refresh_lock = threading.Lock()
message_db_refresh_state = {}
message_db_async_refresh_state = {}
contact_db_refresh_lock = threading.Lock()
contact_db_refresh_state = {}
contact_refresh_last_try = 0.0
contact_names_cache_lock = threading.Lock()
contact_names_cache = None
contact_names_cache_sig = None
month_file_index_lock = threading.Lock()
month_file_index_cache = {}
attach_hash_cache_lock = threading.Lock()
attach_hash_file_cache = {}
_hidden_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="hidden")
_emoji_lookup_lock = threading.Lock()
_emoji_lookup = {}
_emoji_keys_dict = None
_emoji_last_refresh = 0.0
message_db_refresh_locks = {}
MAX_LOG = 5000
OFFICIAL_SYSTEM_USERS = {
    'newsapp', 'fmessage', 'medianote', 'floatbottle', 'qmessage',
    'qqmail', 'tmessage', 'brandsessionholder', 'brandservicesessionholder'
}

LOG_DIR = os.path.join(RUNTIME_BASE_DIR, "logs")
RUNTIME_TMP_DIR = os.path.join(LOG_DIR, "runtime_tmp")
CLAUDE_RUNTIME_DIR = os.path.join(LOG_DIR, "claude_runtime")
CLAUDE_RUNTIME_CONFIG_DIR = os.path.join(CLAUDE_RUNTIME_DIR, "config")
CLAUDE_RUNTIME_TEMP_DIR = os.path.join(CLAUDE_RUNTIME_DIR, "temp")
CLAUDE_PROMPT_BRIDGE_DIR = os.path.join(
    os.environ.get('LOCALAPPDATA', tempfile.gettempdir()),
    "TopicEnginePromptBridge"
)
AI_SESSIONS_FILE = os.path.join(LOG_DIR, "ai_sessions.json")
AI_UPLOAD_DIR = os.path.join(LOG_DIR, "ai_uploads")
AI_PROVIDER_FILE = os.path.join(LOG_DIR, "ai_provider.json")
AI_DEBUG_LOG_FILE = os.path.join(LOG_DIR, "ai_debug.jsonl")
MANUAL_SCORE_FILE = os.path.join(LOG_DIR, "manual_score_entries.json")
LIVE_ALERT_CONFIG_FILE = os.path.join(LOG_DIR, "live_alert_config.json")
LIVE_ALERTS_FILE = os.path.join(LOG_DIR, "live_alerts.json")
ai_sessions_lock = threading.Lock()
ai_sessions = {}
ai_tasks_lock = threading.Lock()
ai_tasks = {}
ai_task_proc_lock = threading.Lock()
ai_task_procs = {}
ai_provider_lock = threading.Lock()
ai_provider_config = {}
live_alert_config_lock = threading.Lock()
live_alert_config = {}
live_alerts_lock = threading.Lock()
live_alerts = []
live_alert_task_lock = threading.Lock()
live_alert_pending = set()
live_alert_recent = {}
ai_module_cache_lock = threading.Lock()
ai_module_cache = {}
mcp_bridge_lock = threading.Lock()
mcp_bridge_module = None
mcp_bridge_error = ''
self_manual_score_lock = threading.Lock()
manual_score_entries = []
analysis_cache_lock = threading.Lock()
analysis_cache = {}
sender_first_seen_cache = {}
self_usernames_cache_lock = threading.Lock()
self_usernames_cache = None
aux_refresh_lock = threading.Lock()
aux_refresh_last = {}
session_db_lock = threading.Lock()
session_state_snapshot_lock = threading.Lock()
session_state_snapshot = {}
_live_alert_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="live-alert")

ANALYSIS_CACHE_TTL_SEC = 180.0
SENDER_FIRST_SEEN_CACHE_TTL_SEC = 300.0
AI_MODULE_CACHE_TTL_SEC = 120.0

AI_PROVIDER_DEFAULT = {
    "provider": "openai_compat",  # claude_cli | openai_compat | anthropic_compat
    "base_url": "https://coding.dashscope.aliyuncs.com/v1",
    "api_key": "",
    "model": "qwen3-coder-plus",
    "temperature": 0.2,
    "max_tokens": 4000,
    "timeout_sec": 180,
    "anthropic_version": "2023-06-01",
}
AI_PROVIDER_OVERRIDE_KEYS = (
    "provider",
    "base_url",
    "api_key",
    "model",
    "temperature",
    "max_tokens",
    "timeout_sec",
    "anthropic_version",
    "surface_routes",
)
AI_SURFACE_KEYS = ("live_alert", "sidebar", "insight")
AI_SURFACE_ROUTE_DEFAULTS = {
    "live_alert": "shared_api",
    "sidebar": "claude_cli",
    "insight": "shared_api",
}
LIVE_ALERT_MAX_ITEMS = 1000
LIVE_ALERT_SKIP_COOLDOWN_SEC = 180
LIVE_ALERT_SEVERITY_ORDER = {
    "low": 1,
    "medium": 2,
    "high": 3,
}
LIVE_ALERT_CATEGORY_LABELS = {
    "product_question": "产品咨询",
    "bug_report": "报错反馈",
    "purchase_intent": "购买信号",
    "negative_feedback": "负反馈",
    "repeat_question": "重复追问",
    "other": "其他",
}
LIVE_ALERT_ALLOWED_CATEGORIES = tuple(LIVE_ALERT_CATEGORY_LABELS.keys())
OPENCLAW_DEFAULT_CHAT_ID = "-1003740422754"
OPENCLAW_DEFAULT_NOTES_THREAD_ID = 88
OPENCLAW_DEFAULT_NOTES_LABEL = "notes"
OPENCLAW_WORKSPACE_DIR = os.path.join(os.path.expanduser("~"), ".openclaw", "workspace")
OPENCLAW_ALERT_SKILL_DIR = os.path.join(OPENCLAW_WORKSPACE_DIR, "skills", "openclaw-alert-pusher")
OPENCLAW_ALERT_PUSH_SCRIPT = os.path.join(OPENCLAW_ALERT_SKILL_DIR, "scripts", "push_alert.py")
LIVE_ALERT_DEFAULT = {
    "enabled": False,
    "watch_mode": "pinned_auto",
    "watch_usernames": [],
    "notify_min_severity": "medium",
    "cooldown_sec": 900,
    "context_window_sec": 480,
    "context_message_limit": 6,
    "candidate_min_score": 2,
    "browser_notifications": True,
    "openclaw_push_enabled": False,
    "openclaw_push_silent": False,
    "openclaw_push_min_severity": "medium",
    "openclaw_push_categories": [
        "product_question",
        "bug_report",
        "purchase_intent",
        "negative_feedback",
    ],
    "openclaw_push_chat_id": OPENCLAW_DEFAULT_CHAT_ID,
    "openclaw_push_thread_id": OPENCLAW_DEFAULT_NOTES_THREAD_ID,
    "openclaw_push_topic_label": OPENCLAW_DEFAULT_NOTES_LABEL,
    "product_keywords": [
        "牛马AI",
        "产品",
        "功能",
        "会员",
        "套餐",
        "试用",
        "开通",
        "账号",
        "邀请码",
        "机器人",
        "agent",
        "社群",
    ],
    "question_keywords": [
        "？",
        "?",
        "请问",
        "怎么",
        "如何",
        "为啥",
        "为什么",
        "是否",
        "能不能",
        "可不可以",
        "有没有",
        "在哪",
        "是不是",
    ],
    "issue_keywords": [
        "报错",
        "bug",
        "错误",
        "失败",
        "没反应",
        "不能用",
        "用不了",
        "崩了",
        "崩溃",
        "卡住",
        "白屏",
        "异常",
        "退款",
        "投诉",
        "不行",
    ],
    "purchase_keywords": [
        "价格",
        "多少钱",
        "收费",
        "付费",
        "购买",
        "下单",
        "开通",
        "试用",
        "优惠",
        "折扣",
        "退款",
    ],
    "ignore_keywords": [
        "哈哈",
        "哈",
        "收到",
        "好的",
        "ok",
        "666",
        "打卡",
        "早",
        "晚安",
        "辛苦了",
        "路过",
    ],
    "ai_extra_prompt": "",
}
AI_MCP_ALLOWED_TOOLS = {
    "get_chat_history",
    "get_sender_messages",
    "get_sender_profile",
    "search_messages",
    "smart_search_messages",
    "get_recent_sessions",
    "get_chat_detail_stats",
    "get_daily_message_trend",
    "get_group_member_stats",
    "get_member_profile_cards",
    "get_emotion_signal_summary",
    "get_risk_alert_candidates",
    "get_topic_distribution",
    "get_score_rules",
    "get_score_leaderboard",
    "get_topic_score_candidates",
    "get_high_quality_candidates",
    "get_round_table_candidates",
    "get_new_messages",
    "export_chat_markdown",
    "read_exported_markdown",
}

AI_MCP_TOOL_SCHEMAS = [
    {
        "name": "get_chat_history",
        "description": "Read chat history with large limits, pagination, and optional time range.",
        "args": {
            "chat_name": "string",
            "limit": "int<=200000 (recommended >= 40000)",
            "offset": "int>=0",
            "start_ts": "unix seconds, optional",
            "end_ts": "unix seconds, optional",
            "max_chars": "int<=900000",
        },
    },
    {
        "name": "get_sender_messages",
        "description": "Read one member's messages in a chat, with optional before/after context.",
        "args": {
            "chat_name": "string",
            "sender": "string",
            "limit": "int<=20000",
            "offset": "int>=0",
            "start_ts": "unix seconds, optional",
            "end_ts": "unix seconds, optional",
            "max_chars": "int<=900000",
            "context_before": "int(-1..60)",
            "context_after": "int(-1..60)",
        },
    },
    {
        "name": "get_sender_profile",
        "description": "Get one member's profile: topics, active hours, sentiment distribution, quotes.",
        "args": {
            "chat_name": "string",
            "sender": "string",
            "start_ts": "unix seconds, optional",
            "end_ts": "unix seconds, optional",
            "context_before": "int(-1..60), optional",
            "context_after": "int(-1..60), optional",
        },
    },
    {
        "name": "search_messages",
        "description": "Search messages by keyword, optionally constrained by chat and time range.",
        "args": {
            "keyword": "string",
            "limit": "int<=5000",
            "offset": "int>=0",
            "start_ts": "unix seconds, optional",
            "end_ts": "unix seconds, optional",
            "chat_name": "string, optional",
        },
    },
    {
        "name": "smart_search_messages",
        "description": "Search messages with simple/boolean/regex modes for richer evidence retrieval.",
        "args": {
            "chat_name": "string",
            "query": "string",
            "search_mode": "simple|boolean|regex, optional",
            "start_ts": "unix seconds, optional",
            "end_ts": "unix seconds, optional",
            "limit": "int<=20000, optional",
        },
    },
    {
        "name": "get_recent_sessions",
        "description": "Get recent sessions.",
        "args": {"limit": "int<=2000"},
    },
    {
        "name": "get_chat_detail_stats",
        "description": "Get structured stats for one chat.",
        "args": {
            "chat_name": "string",
            "start_ts": "unix seconds, optional",
            "end_ts": "unix seconds, optional",
            "include_topics": "bool, optional",
            "include_media_breakdown": "bool, optional",
        },
    },
    {
        "name": "get_daily_message_trend",
        "description": "Get message trend by day/week/month.",
        "args": {
            "chat_name": "string",
            "granularity": "day|week|month",
            "start_ts": "unix seconds, optional",
            "end_ts": "unix seconds, optional",
        },
    },
    {
        "name": "get_group_member_stats",
        "description": "Get group member activity stats.",
        "args": {
            "chat_name": "string",
            "limit": "int<=500",
            "start_ts": "unix seconds, optional",
            "end_ts": "unix seconds, optional",
        },
    },
    {
        "name": "get_member_profile_cards",
        "description": "Get batch member profile cards for segmentation, KOL, and persona analysis.",
        "args": {
            "chat_name": "string",
            "start_ts": "unix seconds, optional",
            "end_ts": "unix seconds, optional",
            "limit": "int<=30, optional",
        },
    },
    {
        "name": "get_emotion_signal_summary",
        "description": "Get aggregated emotion signals, trend, representative quotes, and sentiment-heavy members.",
        "args": {
            "chat_name": "string",
            "start_ts": "unix seconds, optional",
            "end_ts": "unix seconds, optional",
            "limit": "int<=60000, optional",
        },
    },
    {
        "name": "get_risk_alert_candidates",
        "description": "Get risk candidates: risk-keyword counts, alerts, external-link spikes, and evidence rows.",
        "args": {
            "chat_name": "string",
            "start_ts": "unix seconds, optional",
            "end_ts": "unix seconds, optional",
            "limit": "int<=80000, optional",
        },
    },
    {
        "name": "get_topic_distribution",
        "description": "Get topic distribution for a chat.",
        "args": {
            "chat_name": "string",
            "start_ts": "unix seconds, optional",
            "end_ts": "unix seconds, optional",
            "min_topic_frequency": "int>=1",
            "clustering_method": "keyword",
        },
    },
    {
        "name": "get_score_rules",
        "description": "Get scoring rules.",
        "args": {},
    },
    {
        "name": "get_score_leaderboard",
        "description": "Get score leaderboard.",
        "args": {
            "chat_name": "string",
            "start_ts": "unix seconds, optional",
            "end_ts": "unix seconds, optional",
            "include_manual": "bool",
            "limit": "int<=500",
        },
    },
    {
        "name": "get_topic_score_candidates",
        "description": "Get candidate evidences for topic-start scoring.",
        "args": {
            "chat_name": "string",
            "start_ts": "unix seconds, optional",
            "end_ts": "unix seconds, optional",
            "limit": "int<=1000",
        },
    },
    {
        "name": "get_high_quality_candidates",
        "description": "Heuristic candidates for m_high_quality.",
        "args": {
            "chat_name": "string",
            "start_ts": "unix seconds, optional",
            "end_ts": "unix seconds, optional",
            "min_text_length": "int (20..300)",
            "min_quality_score": "int (30..95)",
            "context_window_seconds": "int (30..600)",
            "limit": "int<=500",
        },
    },
    {
        "name": "get_round_table_candidates",
        "description": "Heuristic candidates for m_round_table.",
        "args": {
            "chat_name": "string",
            "start_ts": "unix seconds, optional",
            "end_ts": "unix seconds, optional",
            "window_minutes": "int (30..720)",
            "min_participants": "int (2..200)",
            "keywords": "string, optional",
            "limit": "int<=500",
        },
    },
    {
        "name": "get_new_messages",
        "description": "Read incremental new messages.",
        "args": {},
    },
    {
        "name": "export_chat_markdown",
        "description": "Export a chat transcript to markdown files for a time range, then read the files for deep analysis.",
        "args": {
            "chat_name": "string",
            "time_range": "all|last_7_days|last_30_days|last_180_days|last_365_days, optional",
            "start_ts": "unix seconds, optional",
            "end_ts": "unix seconds, optional",
            "per_file_messages": "int<=10000, optional",
            "max_chars_per_file": "int<=1200000, optional",
            "include_media": "bool, optional",
            "include_system": "bool, optional",
        },
    },
    {
        "name": "read_exported_markdown",
        "description": "Read a previously exported markdown transcript in chunks.",
        "args": {
            "path": "string",
            "start_line": "int>=1, optional",
            "max_lines": "int<=4000, optional",
        },
    },
]
ANALYSIS_SCORE_RULES = [
    {
        "id": "r_msg_once",
        "name": "发言 1 次",
        "points": 1,
        "cap_desc": "每天最多 5 次",
        "manual": False,
        "desc": "每天按消息数计分，单日最多记 5 分。",
    },
    {
        "id": "r_day_ge5",
        "name": "单日发言 >= 5 次",
        "points": 5,
        "cap_desc": "每天 1 次",
        "manual": False,
        "desc": "当天消息数达到 5 条及以上记 5 分。",
    },
    {
        "id": "r_month_ge12",
        "name": "30 天发言天数 >= 12 天",
        "points": 20,
        "cap_desc": "每 30 天 1 次",
        "manual": False,
        "desc": "以结束日往前 30 天窗口统计。",
    },
    {
        "id": "r_year_ge120",
        "name": "365 天发言天数 >= 120 天",
        "points": 30,
        "cap_desc": "每 365 天 1 次",
        "manual": False,
        "desc": "以结束日往前 365 天窗口统计。",
    },
    {
        "id": "m_topic_start",
        "name": "主动发起话题 1 次",
        "points": 5,
        "cap_desc": "每天最多 3 次",
        "manual": True,
        "desc": "需要人工判定是否为有效发起。",
    },
    {
        "id": "m_topic_resp5",
        "name": "主动话题响应人数 >= 5 人",
        "points": 3,
        "cap_desc": "每天最多 3 次",
        "manual": True,
        "desc": "需要人工判定响应人数。",
    },
    {
        "id": "m_high_quality",
        "name": "单日带图/高质干货内容",
        "points": 5,
        "cap_desc": "每天最多 1 次",
        "manual": True,
        "desc": "需要人工审核内容质量。",
    },
    {
        "id": "m_round_table",
        "name": "参与线上圆桌讨论",
        "points": 10,
        "cap_desc": "按活动记分",
        "manual": True,
        "desc": "需人工记录活动参与。",
    },
    {
        "id": "m_group_admin",
        "name": "承担社群管理任务",
        "points": 50,
        "cap_desc": "每年最多 1 次",
        "manual": True,
        "desc": "全年单次记分。",
    },
    {
        "id": "m_forum_post",
        "name": "帖子板块发帖",
        "points": 3,
        "cap_desc": "每天最多 1 次",
        "manual": True,
        "desc": "论坛/帖子板块行为，需人工录入。",
    },
    {
        "id": "m_forum_reply",
        "name": "帖子板块回帖",
        "points": 1,
        "cap_desc": "每天最多 3 次",
        "manual": True,
        "desc": "论坛/帖子板块行为，需人工录入。",
    },
    {
        "id": "m_forum_top3",
        "name": "周发帖/回帖点赞前 3",
        "points": 20,
        "cap_desc": "每周最多 1 次",
        "manual": True,
        "desc": "需人工统计点赞排行。",
    },
]

ANALYSIS_KEYWORD_STOPWORDS = {
    "??", "??", "??", "??", "??", "??", "??", "??", "??", "??",
    "??", "??", "??", "??", "??", "??", "??", "??", "???", "??",
    "??", "??", "??", "??", "??", "??", "??", "??", "??", "??",
    "??", "??", "??", "??", "??", "??", "??", "??", "???", "??",
    "???", "??", "??", "???", "???", "??", "??", "??", "??",
    "?", "?", "?", "?", "?", "?", "?", "?", "?", "?",
    "openim", "chatroom", "wxid", "gh",
}

WECHAT_BRACKET_EMOJI_RE = re.compile(r"\[([^\[\]\s]{1,8})\]")
WECHAT_BRACKET_EMOJI_SKIP = {
    "图片", "表情", "链接/文件", "链接", "文件", "语音", "视频", "文本",
    "动画表情", "聊天记录", "系统消息",
}


def _looks_like_account_token(token):
    t = str(token or "").strip().lower()
    if not t:
        return True
    if re.match(r"^wxid_[0-9a-z_]{4,}$", t):
        return True
    if re.match(r"^gh_[0-9a-z_]{4,}$", t):
        return True
    if re.match(r"^[a-z]{1,5}_[a-z0-9_]{5,}$", t):
        return True
    if re.match(r"^[0-9a-z]{18,}$", t):
        return True
    if "_" in t and len(t) >= 10 and re.search(r"\d", t):
        return True
    if t.startswith(("wxid", "gh_", "wx_", "id_")) and len(t) >= 7:
        return True
    return False


def _is_unknown_source_text(source):
    s = str(source or "").strip()
    if not s:
        return True
    low = s.lower()
    return low in {
        "鏈煡", "鏈煡鏉ユ簮", "unknown", "unknown source",
        "n/a", "na", "null", "none", "-", "--", "?",
    }


def _normalize_link_source_name(source, url=""):
    s = str(source or "").strip()
    if _is_unknown_source_text(s):
        return "澶栭儴缃戠珯"
    url_source = _source_name_from_url(url) if url else ""
    if url_source in {"公众号", "视频号"} and s in {"微信", "其他", ""}:
        return url_source
    if s in {"链接卡片", "卡片"}:
        return "卡片消息"
    if s == "引用回复":
        return "引用消息"
    if "拍一拍" in s:
        return "拍一拍"
    if _looks_like_account_token(s.lower()):
        return ""
    if len(s) > 24:
        s = s[:24]
    if not s and str(url or "").strip():
        return "澶栭儴缃戠珯"
    return s


def _is_noise_keyword(token):
    t = str(token or "").strip()
    if not t:
        return True
    low = t.lower()
    if low in ANALYSIS_KEYWORD_STOPWORDS:
        return True
    if t in {"所有人", "@所有人"}:
        return True
    if _looks_like_account_token(low):
        return True
    if "wxid_" in low or "gh_" in low or "chatroom" in low:
        return True
    if re.search(r"^rid[:_]\d+$", low):
        return True
    if re.search(r"[a-z].*[_\-].*\d|\d.*[_\-].*[a-z]", low) and len(low) >= 8:
        return True
    if re.fullmatch(r"[_\-\.]{2,}", low):
        return True
    if re.fullmatch(r"\d{3,}", low):
        return True
    if re.fullmatch(r"[\u4e00-\u9fff]", t):
        return True
    if re.fullmatch(r"[A-Za-z]{1,2}", t):
        return True
    if len(set(low)) <= 2 and len(low) >= 6:
        return True
    return False


def _extract_wechat_bracket_emojis(text):
    out = []
    cleaned = _clean_rich_text(text if isinstance(text, str) else "")
    if not cleaned:
        return out
    for m in WECHAT_BRACKET_EMOJI_RE.finditer(cleaned):
        token = str(m.group(1) or "").strip()
        if not token or token in WECHAT_BRACKET_EMOJI_SKIP:
            continue
        if len(token) > 8:
            continue
        if re.fullmatch(r"[A-Za-z0-9_\-\/]{2,}", token):
            continue
        if not (re.search(r"[\u4e00-\u9fff]", token) or token in {"OK", "强", "弱"}):
            continue
        out.append(token)
    return out


def _strip_wechat_bracket_emojis(text):
    cleaned = _clean_rich_text(text if isinstance(text, str) else "")
    if not cleaned:
        return ""

    def _repl(match):
        token = str(match.group(1) or "").strip()
        if token in WECHAT_BRACKET_EMOJI_SKIP:
            return match.group(0)
        if not token or len(token) > 8:
            return match.group(0)
        if re.fullmatch(r"[A-Za-z0-9_\-\/]{2,}", token):
            return match.group(0)
        if not (re.search(r"[\u4e00-\u9fff]", token) or token in {"OK", "强", "弱"}):
            return match.group(0)
        return " "

    return WECHAT_BRACKET_EMOJI_RE.sub(_repl, cleaned)


def _extract_keyword_candidates(text):
    if not isinstance(text, str):
        return []
    cleaned = _clean_rich_text(text)
    if not cleaned:
        return []
    cleaned = _strip_wechat_bracket_emojis(cleaned)
    cleaned = re.sub(r"https?://\S+", " ", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"www\.\S+", " ", cleaned, flags=re.IGNORECASE)

    out = []
    # English / mixed tokens
    for tok in re.findall(r"[A-Za-z][A-Za-z0-9_\-]{2,31}", cleaned):
        t = tok.strip().lower()
        if _is_noise_keyword(t):
            continue
        # Heavily numeric mixed strings are usually ids.
        digits = sum(ch.isdigit() for ch in t)
        if digits >= 3 and (digits / max(len(t), 1)) > 0.34:
            continue
        out.append(t)

    # Chinese chunks + n-grams for long chunks.
    chunks = re.findall(r"[\u4e00-\u9fff]{2,20}", cleaned)
    zh_edge_stop = set("的一是了在和与及就都也又还把将被到来去给让入出对上中下着过吗呢吧啊呀哦嗯哟")
    for ch in chunks:
        seg = ch.strip()
        if not seg:
            continue
        if 2 <= len(seg) <= 8 and not _is_noise_keyword(seg):
            out.append(seg)
        if len(seg) > 8:
            # Split long chunks on stop-like chars first to reduce meaningless fragments.
            sep_pat = "[" + re.escape("".join(sorted(zh_edge_stop))) + "]"
            parts = [p.strip() for p in re.split(sep_pat, seg) if isinstance(p, str) and p.strip()]
            local_seen = set()
            for p in parts:
                if len(p) <= 8:
                    if not _is_noise_keyword(p):
                        out.append(p)
                    continue
                for n in (3, 4):
                    if len(p) < n:
                        continue
                    for i in range(0, len(p) - n + 1):
                        tok = p[i:i + n]
                        if tok in local_seen:
                            continue
                        local_seen.add(tok)
                        if tok[0] in zh_edge_stop or tok[-1] in zh_edge_stop:
                            continue
                        if _is_noise_keyword(tok):
                            continue
                        out.append(tok)
    return out


def _extract_emoji_display_name(source_blob=None, content_blob=None):
    merged = "\n".join([
        _decode_maybe_text(source_blob),
        _decode_maybe_text(content_blob),
    ]).strip()
    if not merged:
        return ""
    for tag in ("emojiattr", "des", "desc", "title", "productid"):
        val = _sanitize_link_text(_xml_tag_text(merged, tag))
        if val and val not in {"表情", "动画表情"}:
            return val[:24]
    return ""


def _collect_emoji_preferences(username, start_ts=0, end_ts=0, limit=12000):
    username = str(username or "").strip()
    if not username:
        return {"cloud": [], "stickers": []}
    db_path, table_name = _find_msg_table_for_user(username, ensure_fresh=True)
    if not db_path or not table_name:
        return {"cloud": [], "stickers": []}
    try:
        refresh_decrypted_message_db(db_path)
    except Exception as e:
        print(f"[analysis] emoji refresh failed: {e}", flush=True)

    rows = []
    where_clauses = ["(local_type & 4294967295) IN (1,47,49)"]
    where_params = []
    if start_ts:
        where_clauses.append("create_time >= ?")
        where_params.append(int(start_ts))
    if end_ts:
        where_clauses.append("create_time <= ?")
        where_params.append(int(end_ts))
    where_sql = " WHERE " + " AND ".join(where_clauses)

    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        try:
            cols = {
                str(r[1]).lower()
                for r in conn.execute(f"PRAGMA table_info([{table_name}])").fetchall()
                if len(r) >= 2
            }
            has_source = "source" in cols
            has_ct = "content_type" in cols
            rows = conn.execute(
                f"""
                SELECT
                  (local_type & 4294967295) AS msg_type,
                  create_time,
                  message_content,
                  {"source" if has_source else "'' AS source"},
                  {"content_type" if has_ct else "NULL AS content_type"}
                FROM [{table_name}]
                {where_sql}
                ORDER BY create_time DESC
                LIMIT ?
                """,
                tuple(where_params + [int(limit)])
            ).fetchall()
        finally:
            conn.close()
    except (sqlite3.DatabaseError, sqlite3.OperationalError) as e:
        if not _is_recoverable_message_query_error(e):
            raise
        print(f"[analysis] emoji fallback due db error: {e}", flush=True)
        _, _, safe_rows = _load_message_rows_safe(
            db_path,
            table_name,
            start_ts=start_ts,
            end_ts=end_ts,
            limit=min(max(int(limit or 0) * 4, 4000), 40000),
            newest_first=True,
        )
        for item in safe_rows:
            msg_type = _normalize_msg_type((item or {}).get("local_type", 0))
            if msg_type not in (1, 47, 49):
                continue
            rows.append((
                msg_type,
                int((item or {}).get("timestamp", 0) or 0),
                (item or {}).get("content", ""),
                (item or {}).get("source", ""),
                (item or {}).get("ct_flag", None),
            ))
            if len(rows) >= int(limit):
                break

    builtin_counter = Counter()
    sticker_map = {}
    for msg_type, ts, content, source_blob, ct_flag in rows:
        mt = _normalize_msg_type(msg_type)
        if mt == 47:
            image_url = _resolve_emoji_media_url(source_blob, content, ct_flag=ct_flag)
            label = _extract_emoji_display_name(source_blob, content) or "表情包"
            key = str(image_url or _extract_emoji_md5_from_xml(_decode_maybe_text(source_blob)) or "").strip()
            if not key:
                continue
            rec = sticker_map.setdefault(key, {
                "label": label,
                "image_url": image_url or "",
                "count": 0,
                "last_ts": int(ts or 0),
            })
            rec["count"] += 1
            if int(ts or 0) >= int(rec.get("last_ts", 0)):
                rec["last_ts"] = int(ts or 0)
                if image_url:
                    rec["image_url"] = image_url
                if label:
                    rec["label"] = label
            continue

        text = content if isinstance(content, str) else ""
        if (not text.strip()) and isinstance(content, (bytes, bytearray)):
            text = _extract_text_from_message_blob(content, mt)
        if _is_text_garbled(text):
            continue
        rendered = _render_link_or_quote_text(mt, text, source_blob)
        rendered = _sanitize_link_text(rendered)
        rendered = _clean_rich_text(rendered)
        if not rendered:
            continue
        for emo in set(_extract_wechat_bracket_emojis(rendered)):
            builtin_counter[emo] += 1

    cloud = [{"label": k, "count": int(v)} for k, v in builtin_counter.most_common(80) if int(v) > 0]
    stickers = sorted(
        (
            v for v in sticker_map.values()
            if str(v.get("image_url", "")).strip()
        ),
        key=lambda x: (int(x.get("count", 0)), int(x.get("last_ts", 0))),
        reverse=True
    )[:24]
    return {"cloud": cloud, "stickers": stickers}


def _build_keyword_mention_names():
    names = {"所有人"}
    try:
        contact_names = load_contact_names()
    except Exception:
        contact_names = {}
    for display in (contact_names or {}).values():
        cleaned = re.sub(r"\s+", " ", _clean_rich_text(display))
        cleaned = str(cleaned or "").strip()
        if not cleaned or len(cleaned) > 32:
            continue
        names.add(cleaned)
    return sorted(names, key=len, reverse=True)


KEYWORD_MENTION_PATTERNS = (
    re.compile(r"(?<![A-Za-z0-9_])[@＠]([A-Za-z0-9][A-Za-z0-9_\-\.]{1,31})"),
    re.compile(r"(?<![A-Za-z0-9_])[@＠]([^\s@＠]{1,24})(?=[\s\u3000,，。！？!?:：;；、]|$)"),
)
KEYWORD_MENTION_REMOVE_PATTERNS = (
    re.compile(r"(?<![A-Za-z0-9_])[@＠](?:所有人|all)\b", flags=re.IGNORECASE),
    re.compile(r"(?<![A-Za-z0-9_])[@＠](?:[A-Za-z0-9][A-Za-z0-9_\-\.]{1,31})"),
    re.compile(r"(?<![A-Za-z0-9_])[@＠](?:[^\s@＠]{1,24})(?=[\s\u3000,，。！？!?:：;；、]|$)"),
)


def _strip_keyword_mentions(text, mention_names=None):
    cleaned = str(text or "").strip()
    if not cleaned:
        return ""
    for pat in KEYWORD_MENTION_REMOVE_PATTERNS:
        cleaned = pat.sub(" ", cleaned)
    return re.sub(r"\s+", " ", cleaned).strip()


def _extract_keyword_mentions(text, mention_names=None):
    cleaned = str(text or "").strip()
    if not cleaned:
        return set()
    found = set()
    for pat in KEYWORD_MENTION_PATTERNS:
        for m in pat.finditer(cleaned):
            item = str(m.group(1) or "").strip().lower()
            if item:
                found.add(item)
    return found


def decrypt_page(enc_key, page_data, pgno):
    """鐟欙絽鐦戦崡鏇氶嚋閸旂姴鐦戞い鐢告桨"""
    iv = page_data[PAGE_SZ - RESERVE_SZ: PAGE_SZ - RESERVE_SZ + IV_SZ]
    if pgno == 1:
        encrypted = page_data[SALT_SZ: PAGE_SZ - RESERVE_SZ]
        cipher = AES.new(enc_key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypted)
        return bytearray(SQLITE_HDR + decrypted + b'\x00' * RESERVE_SZ)
    else:
        encrypted = page_data[:PAGE_SZ - RESERVE_SZ]
        cipher = AES.new(enc_key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypted)
        return decrypted + b'\x00' * RESERVE_SZ


ALL_KEYS = dict(_cfg.get("keys", {}) or {})


def derive_mac_key(enc_key, salt):
    mac_salt = bytes(b ^ 0x3a for b in salt)
    return hashlib.pbkdf2_hmac("sha512", enc_key, mac_salt, 2, dklen=KEY_SZ)


def _verify_db_key_hmac(db_path, enc_key_hex):
    try:
        enc_key = bytes.fromhex(str(enc_key_hex or "").strip())
    except Exception:
        return False
    if len(enc_key) != KEY_SZ:
        return False
    try:
        with open(db_path, "rb") as f:
            page1 = f.read(PAGE_SZ)
    except Exception:
        return False
    if len(page1) < PAGE_SZ:
        return False

    salt = page1[:SALT_SZ]
    mac_key = derive_mac_key(enc_key, salt)
    p1_hmac_data = page1[SALT_SZ: PAGE_SZ - RESERVE_SZ + IV_SZ]
    p1_stored_hmac = page1[PAGE_SZ - HMAC_SZ: PAGE_SZ]
    hm = hmac_mod.new(mac_key, p1_hmac_data, hashlib.sha512)
    hm.update(struct.pack("<I", 1))
    return hm.digest() == p1_stored_hmac


def _iter_enc_key_candidates(keys_obj, rel_path):
    if not isinstance(keys_obj, dict):
        return

    seen = set()

    def _yield_enc(enc):
        e = str(enc or "").strip().lower()
        if len(e) != 64 or e in seen:
            return
        seen.add(e)
        yield e

    cands = [rel_path, rel_path.replace("\\", "/"), rel_path.replace("/", "\\")]
    for k in cands:
        item = keys_obj.get(k)
        if isinstance(item, dict):
            for x in _yield_enc(item.get("enc_key", "")):
                yield x

    rel_low = rel_path.replace("\\", "/").lower()
    for k, item in keys_obj.items():
        if not isinstance(item, dict):
            continue
        key_low = str(k).replace("\\", "/").lower()
        if key_low.endswith(rel_low):
            for x in _yield_enc(item.get("enc_key", "")):
                yield x

    for item in keys_obj.values():
        if not isinstance(item, dict):
            continue
        for x in _yield_enc(item.get("enc_key", "")):
            yield x


def _find_valid_db_enc_key(keys_obj, rel_path, db_path):
    for enc in _iter_enc_key_candidates(keys_obj, rel_path):
        if _verify_db_key_hmac(db_path, enc):
            return enc
    return None


def _looks_like_sqlite_file(path):
    try:
        if not os.path.exists(path) or os.path.getsize(path) < 16:
            return False
        with open(path, "rb") as f:
            return f.read(16) == SQLITE_HDR
    except Exception:
        return False


def _sqlite_db_is_readable(path):
    try:
        if not _looks_like_sqlite_file(path):
            return False
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=1.0)
        try:
            conn.execute("SELECT 1 FROM sqlite_master LIMIT 1").fetchone()
            return True
        finally:
            conn.close()
    except Exception:
        return False


def _load_all_keys(force=False):
    global ALL_KEYS
    if ALL_KEYS and not force:
        return ALL_KEYS
    with open(KEYS_FILE, "r", encoding="utf-8") as f:
        obj = json.load(f)
    if not isinstance(obj, dict):
        raise RuntimeError(f"invalid keys file: {KEYS_FILE}")
    ALL_KEYS = obj
    return ALL_KEYS

def _display_name_for_username(username, contact_names):
    if username == 'brandsessionholder':
        return '订阅号消息'
    if username == 'brandservicesessionholder':
        return '服务号消息'
    return contact_names.get(username, username)


def _is_official_account(username):
    if not username:
        return False
    if username.startswith('gh_'):
        return True
    return username in OFFICIAL_SYSTEM_USERS


def _table_exists(db_path, table_name):
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        try:
            row = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                (table_name,)
            ).fetchone()
            return bool(row)
        finally:
            conn.close()
    except Exception:
        return False


def _message_db_filenames():
    names = set()
    encrypted_dir = os.path.join(DB_DIR, "message")
    decrypted_dir = os.path.join(_cfg["decrypted_dir"], "message")
    for d in (encrypted_dir, decrypted_dir):
        if not os.path.exists(d):
            continue
        for n in os.listdir(d):
            if n.startswith("message_") and n.endswith(".db"):
                if n == "message_resource.db":
                    continue
                names.add(n)
    return sorted(names)


def _find_msg_table_for_user(username, ensure_fresh=False):
    """Find Msg_<md5(username)> table and optionally refresh decrypted DBs first."""
    table_hash = hashlib.md5(username.encode()).hexdigest()
    table_name = f"Msg_{table_hash}"
    decrypted_dir = os.path.join(_cfg["decrypted_dir"], "message")
    os.makedirs(decrypted_dir, exist_ok=True)

    db_files = _message_db_filenames()

    # Fast path: check current decrypted copies first (no refresh).
    for db_file in db_files:
        db_path = os.path.join(decrypted_dir, db_file)
        if _table_exists(db_path, table_name):
            return db_path, table_name

    if not ensure_fresh:
        return None, None

    # Slow path: refresh each DB only when fast path missed.
    for db_file in db_files:
        db_path = os.path.join(decrypted_dir, db_file)
        try:
            refresh_decrypted_message_db(db_path)
        except Exception:
            # Best-effort refresh: keep scanning others.
            pass
        if _table_exists(db_path, table_name):
            return db_path, table_name
    return None, None


def _find_all_msg_tables_for_user(username, ensure_fresh=False):
    table_hash = hashlib.md5(username.encode()).hexdigest()
    table_name = f"Msg_{table_hash}"
    decrypted_dir = os.path.join(_cfg["decrypted_dir"], "message")
    os.makedirs(decrypted_dir, exist_ok=True)

    db_files = _message_db_filenames()
    found = []

    for db_file in db_files:
        db_path = os.path.join(decrypted_dir, db_file)
        if _table_exists(db_path, table_name):
            found.append(db_path)

    if found or not ensure_fresh:
        return found, table_name

    for db_file in db_files:
        db_path = os.path.join(decrypted_dir, db_file)
        try:
            refresh_decrypted_message_db(db_path)
        except Exception:
            pass
        if _table_exists(db_path, table_name):
            found.append(db_path)
    return found, table_name


def _build_username_db_map():
    """Build username -> [decrypted message db path] map via Name2Id."""
    mapping = {}
    decrypted_dir = os.path.join(_cfg["decrypted_dir"], "message")
    os.makedirs(decrypted_dir, exist_ok=True)
    db_files = _message_db_filenames()

    encrypted_mtime = {}
    for db_file in db_files:
        enc_path = os.path.join(DB_DIR, "message", db_file)
        try:
            encrypted_mtime[db_file] = os.path.getmtime(enc_path)
        except OSError:
            encrypted_mtime[db_file] = 0

    for db_file in db_files:
        db_path = os.path.join(decrypted_dir, db_file)
        try:
            refresh_decrypted_message_db(db_path)
        except Exception:
            pass
        if not os.path.exists(db_path):
            continue
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
            rows = conn.execute("SELECT user_name FROM Name2Id").fetchall()
            conn.close()
            for row in rows:
                u = str(row[0] if row else "").strip()
                if not u:
                    continue
                mapping.setdefault(u, []).append(db_path)
        except Exception:
            continue

    for username, paths in list(mapping.items()):
        uniq = list(dict.fromkeys(paths))
        uniq.sort(
            key=lambda p: encrypted_mtime.get(os.path.basename(p), 0),
            reverse=True
        )
        mapping[username] = uniq

    return mapping


def _get_key_info_by_rel_path(rel_path):
    """
    Lookup enc_key metadata by relative DB path, e.g.:
    - message\\message_0.db
    - contact\\contact.db
    """
    if not isinstance(rel_path, str) or not rel_path:
        return None
    try:
        keys_obj = _load_all_keys()
    except Exception:
        return None
    want = rel_path.replace("/", "\\").lower()
    for key_name, key_info in keys_obj.items():
        key_norm = str(key_name).replace("/", "\\").lower()
        if key_norm == want or key_norm.endswith("\\" + want):
            return key_info
    return None


def _get_message_db_key_info(db_file):
    """Find key metadata for message DB by filename (e.g. message_0.db)."""
    normalized = str(db_file).lower()
    return _get_key_info_by_rel_path(f"message\\{normalized}")


def _get_message_db_refresh_lock(cache_key):
    with message_db_refresh_lock:
        lock = message_db_refresh_locks.get(cache_key)
        if lock is None:
            lock = threading.Lock()
            message_db_refresh_locks[cache_key] = lock
    return lock


def _get_message_db_source_state(decrypted_db_path):
    db_file = os.path.basename(decrypted_db_path)
    encrypted_db_path = os.path.join(DB_DIR, "message", db_file)
    wal_path = encrypted_db_path + "-wal"
    if not os.path.exists(encrypted_db_path):
        raise RuntimeError(f"Encrypted message DB not found: {encrypted_db_path}")
    db_mtime = os.path.getmtime(encrypted_db_path)
    wal_mtime = os.path.getmtime(wal_path) if os.path.exists(wal_path) else 0
    cache_key = os.path.abspath(encrypted_db_path)
    return {
        "cache_key": cache_key,
        "db_file": db_file,
        "encrypted_db_path": encrypted_db_path,
        "wal_path": wal_path,
        "db_mtime": db_mtime,
        "wal_mtime": wal_mtime,
    }


def _message_db_needs_refresh(decrypted_db_path):
    src = _get_message_db_source_state(decrypted_db_path)
    has_decrypted = os.path.exists(decrypted_db_path) and _sqlite_db_is_readable(decrypted_db_path)
    with message_db_refresh_lock:
        cache_val = message_db_refresh_state.get(src["cache_key"])
    if not has_decrypted:
        return True, src
    if not cache_val:
        return True, src
    prev_db_mtime, prev_wal_mtime = cache_val
    needs = prev_db_mtime != src["db_mtime"] or prev_wal_mtime != src["wal_mtime"]
    return needs, src


def _schedule_message_db_refresh(decrypted_db_path, min_interval_sec=12):
    try:
        src = _get_message_db_source_state(decrypted_db_path)
    except Exception:
        src = {
            "cache_key": os.path.abspath(decrypted_db_path),
            "db_file": os.path.basename(decrypted_db_path),
        }
    key = src["cache_key"]
    now = time.time()
    with message_db_refresh_lock:
        meta = dict(message_db_async_refresh_state.get(key) or {})
        last_started = float(meta.get("last_started", 0.0) or 0.0)
        if meta.get("running"):
            return False
        if last_started and (now - last_started) < float(min_interval_sec):
            return False
        meta["running"] = True
        meta["last_started"] = now
        meta["last_error"] = ""
        message_db_async_refresh_state[key] = meta

    def _worker():
        pages = 0
        ms = 0.0
        err_text = ""
        try:
            pages, ms = refresh_decrypted_message_db(decrypted_db_path)
            print(
                f"[chat_history] async refreshed {src['db_file']} {pages}pg/{ms:.1f}ms",
                flush=True
            )
        except Exception as e:
            err_text = str(e)
            print(
                f"[chat_history] async refresh failed {src['db_file']}: {err_text}",
                flush=True
            )
        finally:
            with message_db_refresh_lock:
                meta = dict(message_db_async_refresh_state.get(key) or {})
                meta["running"] = False
                meta["last_finished"] = time.time()
                meta["last_pages"] = int(pages or 0)
                meta["last_ms"] = float(ms or 0.0)
                meta["last_error"] = err_text
                message_db_async_refresh_state[key] = meta

    threading.Thread(
        target=_worker,
        daemon=True,
        name=f"msgdb-refresh-{src['db_file']}",
    ).start()
    return True


def ensure_message_db_ready_for_read(decrypted_db_path, prefer_stale=True, min_async_interval_sec=12):
    readable = os.path.exists(decrypted_db_path) and _sqlite_db_is_readable(decrypted_db_path)
    if not readable:
        pages, ms = refresh_decrypted_message_db(decrypted_db_path)
        return {
            "mode": "sync",
            "pages": int(pages or 0),
            "ms": float(ms or 0.0),
            "scheduled": False,
        }

    if not prefer_stale:
        pages, ms = refresh_decrypted_message_db(decrypted_db_path)
        return {
            "mode": "sync",
            "pages": int(pages or 0),
            "ms": float(ms or 0.0),
            "scheduled": False,
        }

    needs_refresh, src = _message_db_needs_refresh(decrypted_db_path)
    if not needs_refresh:
        return {
            "mode": "ready",
            "pages": 0,
            "ms": 0.0,
            "scheduled": False,
        }

    scheduled = _schedule_message_db_refresh(
        decrypted_db_path,
        min_interval_sec=min_async_interval_sec,
    )
    return {
        "mode": "stale",
        "pages": 0,
        "ms": 0.0,
        "scheduled": bool(scheduled),
        "db_file": src.get("db_file", os.path.basename(decrypted_db_path)),
    }


def refresh_decrypted_contact_db():
    """
    Refresh decrypted contact.db from encrypted source + WAL.
    This keeps newly joined groups/new friends name mapping up-to-date.
    """
    encrypted_db_path = os.path.join(DB_DIR, "contact", "contact.db")
    key_info = _get_key_info_by_rel_path("contact\\contact.db")
    if not key_info:
        return 0, 0.0
    if not os.path.exists(encrypted_db_path):
        return 0, 0.0

    enc_key = bytes.fromhex(key_info["enc_key"])
    wal_path = encrypted_db_path + "-wal"
    db_mtime = os.path.getmtime(encrypted_db_path)
    wal_mtime = os.path.getmtime(wal_path) if os.path.exists(wal_path) else 0

    os.makedirs(os.path.dirname(CONTACT_CACHE), exist_ok=True)
    with contact_db_refresh_lock:
        cache_key = os.path.abspath(encrypted_db_path)
        cache_val = contact_db_refresh_state.get(cache_key)
        prev_db_mtime = cache_val[0] if cache_val else None
        prev_wal_mtime = cache_val[1] if cache_val else None
        has_decrypted = os.path.exists(CONTACT_CACHE)

        if (
            cache_val
            and has_decrypted
            and prev_db_mtime == db_mtime
            and prev_wal_mtime == wal_mtime
        ):
            return 0, 0.0

        if has_decrypted and prev_db_mtime == db_mtime and os.path.exists(wal_path):
            wal_patched, wal_ms = decrypt_wal_full(wal_path, CONTACT_CACHE, enc_key)
            contact_db_refresh_state[cache_key] = (db_mtime, wal_mtime)
            return wal_patched, wal_ms

        pages, ms = full_decrypt(encrypted_db_path, CONTACT_CACHE, enc_key)
        wal_patched, wal_ms = 0, 0.0
        if os.path.exists(wal_path):
            wal_patched, wal_ms = decrypt_wal_full(wal_path, CONTACT_CACHE, enc_key)
        contact_db_refresh_state[cache_key] = (db_mtime, wal_mtime)
        return pages + wal_patched, ms + wal_ms


def refresh_decrypted_message_db(decrypted_db_path):
    """Refresh one decrypted message DB from encrypted source + WAL."""
    db_file = os.path.basename(decrypted_db_path)
    encrypted_db_path = os.path.join(DB_DIR, "message", db_file)
    key_info = _get_message_db_key_info(db_file)
    if not key_info:
        raise RuntimeError(f"No enc_key found for message DB: {db_file}")
    if not os.path.exists(encrypted_db_path):
        raise RuntimeError(f"Encrypted message DB not found: {encrypted_db_path}")

    enc_key = bytes.fromhex(key_info["enc_key"])
    wal_path = encrypted_db_path + "-wal"
    db_mtime = os.path.getmtime(encrypted_db_path)
    wal_mtime = os.path.getmtime(wal_path) if os.path.exists(wal_path) else 0

    os.makedirs(os.path.dirname(decrypted_db_path), exist_ok=True)
    cache_key = os.path.abspath(encrypted_db_path)
    per_db_lock = _get_message_db_refresh_lock(cache_key)
    with per_db_lock:
        with message_db_refresh_lock:
            cache_val = message_db_refresh_state.get(cache_key)
        prev_db_mtime = cache_val[0] if cache_val else None
        prev_wal_mtime = cache_val[1] if cache_val else None
        has_decrypted = os.path.exists(decrypted_db_path)

        # No source changes.
        if (
            cache_val
            and prev_db_mtime == db_mtime
            and prev_wal_mtime == wal_mtime
            and has_decrypted
            and _sqlite_db_is_readable(decrypted_db_path)
        ):
            return 0, 0

        # Fast path: DB file unchanged, only WAL moved -> patch WAL incrementally.
        if (
            has_decrypted
            and prev_db_mtime == db_mtime
            and os.path.exists(wal_path)
            and _sqlite_db_is_readable(decrypted_db_path)
        ):
            wal_patched, wal_ms = decrypt_wal_full(wal_path, decrypted_db_path, enc_key)
            with message_db_refresh_lock:
                message_db_refresh_state[cache_key] = (db_mtime, wal_mtime)
            return wal_patched, wal_ms

        # Slow path: DB file changed or no decrypted copy -> rebuild via temp file, then swap in.
        temp_path = f"{decrypted_db_path}.tmp.{os.getpid()}.{threading.get_ident()}"
        try:
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except Exception:
                    pass
            pages, ms = full_decrypt(encrypted_db_path, temp_path, enc_key)
            wal_patched, wal_ms = 0, 0
            if os.path.exists(wal_path):
                wal_patched, wal_ms = decrypt_wal_full(wal_path, temp_path, enc_key)
            replaced = False
            last_replace_err = None
            for _ in range(8):
                try:
                    os.replace(temp_path, decrypted_db_path)
                    replaced = True
                    break
                except PermissionError as e:
                    last_replace_err = e
                    time.sleep(0.2)
            if not replaced:
                if last_replace_err:
                    raise last_replace_err
                raise RuntimeError(f"failed to replace refreshed db: {decrypted_db_path}")
        finally:
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except Exception:
                    pass
        with message_db_refresh_lock:
            message_db_refresh_state[cache_key] = (db_mtime, wal_mtime)
    return pages + wal_patched, ms + wal_ms


def _get_emoticon_key_info(keys_dict):
    if not isinstance(keys_dict, dict):
        return None
    for cand in ("emoticon\\emoticon.db", "emoticon/emoticon.db"):
        item = keys_dict.get(cand)
        if isinstance(item, dict):
            return item
    want = "emoticon/emoticon.db"
    for k, v in keys_dict.items():
        if not isinstance(v, dict):
            continue
        nk = str(k).replace("\\", "/").lower()
        if nk.endswith(want):
            return v
    return None


def _build_emoji_lookup(keys_dict=None):
    """Build md5 -> emoji download meta from emoticon.db."""
    global _emoji_lookup, _emoji_keys_dict, _emoji_last_refresh
    if keys_dict is None:
        try:
            keys_dict = _load_all_keys()
        except Exception:
            keys_dict = {}
    _emoji_keys_dict = keys_dict if isinstance(keys_dict, dict) else {}

    key_info = _get_emoticon_key_info(_emoji_keys_dict)
    if not isinstance(key_info, dict):
        return
    enc_key_hex = str(key_info.get("enc_key", "") or "").strip()
    if len(enc_key_hex) != 64:
        return

    src = os.path.join(DB_DIR, "emoticon", "emoticon.db")
    if not os.path.exists(src):
        return

    try:
        os.makedirs(EMOJI_CACHE_DIR, exist_ok=True)
    except Exception:
        pass

    tmp_name = f"wechat_emoticon_{os.getpid()}_{int(time.time() * 1000)}.db"
    _ensure_dir(RUNTIME_TMP_DIR)
    dst = os.path.join(RUNTIME_TMP_DIR, tmp_name)
    wal = src + "-wal"
    try:
        enc_key = bytes.fromhex(enc_key_hex)
        full_decrypt(src, dst, enc_key)
        if os.path.exists(wal):
            decrypt_wal_full(wal, dst, enc_key)
    except Exception as e:
        print(f"[emoji] decrypt emoticon.db failed: {e}", flush=True)
        try:
            if os.path.exists(dst):
                os.unlink(dst)
        except OSError:
            pass
        return

    new_lookup = {}
    non_store_count = 0
    store_added = 0
    try:
        conn = sqlite3.connect(f"file:{dst}?mode=ro", uri=True)
        pkg_template = {}
        try:
            rows = conn.execute(
                "SELECT md5, aes_key, cdn_url, encrypt_url, product_id FROM kNonStoreEmoticonTable"
            ).fetchall()
        except Exception:
            rows = []

        for md5, aes_key, cdn_url, encrypt_url, product_id in rows:
            m = str(md5 or "").strip().lower()
            if re.fullmatch(r"[0-9a-f]{32}", m):
                new_lookup[m] = {
                    "cdn_url": str(cdn_url or "").strip(),
                    "aes_key": str(aes_key or "").strip(),
                    "encrypt_url": str(encrypt_url or "").strip(),
                }
            pkg = str(product_id or "").strip()
            if pkg and cdn_url:
                pkg_template[pkg] = str(cdn_url or "").strip()
        non_store_count = len(new_lookup)

        try:
            store_rows = conn.execute(
                "SELECT package_id_, md5_ FROM kStoreEmoticonFilesTable"
            ).fetchall()
        except Exception:
            store_rows = []

        for pkg_id, md5 in store_rows:
            m = str(md5 or "").strip().lower()
            if not re.fullmatch(r"[0-9a-f]{32}", m):
                continue
            if m in new_lookup:
                continue
            template = str(pkg_template.get(str(pkg_id or "").strip(), "") or "")
            if template and "m=" in template:
                constructed = re.sub(r"m=[0-9a-f]{8,64}", f"m={m}", template, flags=re.I)
                new_lookup[m] = {"cdn_url": constructed, "aes_key": "", "encrypt_url": ""}
                store_added += 1

        conn.close()
        with _emoji_lookup_lock:
            _emoji_lookup = new_lookup
        _emoji_last_refresh = time.time()
        print(
            f"[emoji] loaded {non_store_count} non-store + {store_added} store = {len(new_lookup)}",
            flush=True
        )
    except Exception as e:
        print(f"[emoji] build lookup failed: {e}", flush=True)
    finally:
        try:
            if os.path.exists(dst):
                os.unlink(dst)
        except OSError:
            pass


def _build_emoji_url(file_name):
    return "/api/emoji?f=" + urllib.parse.quote(str(file_name or ""))


def _extract_emoji_md5_from_xml(xml_text):
    t = _clean_rich_text(xml_text if isinstance(xml_text, str) else "")
    if not t:
        return ""
    m = re.search(r'<emoji[^>]*\bmd5="([0-9a-f]{32})"', t, flags=re.I)
    if m:
        return m.group(1).lower()
    m = re.search(r"\b([0-9a-f]{32})\b", t, flags=re.I)
    return m.group(1).lower() if m else ""


def _extract_emoji_url_from_xml(xml_text):
    t = _clean_rich_text(xml_text if isinstance(xml_text, str) else "")
    if not t:
        return ""
    for attr in ("cdnurl", "thumburl", "cdnthumburl", "cdnbigimgurl", "url", "externurl", "encrypturl"):
        m = re.search(rf'{attr}="([^"]+)"', t, flags=re.I)
        if not m:
            continue
        u = html.unescape(str(m.group(1) or "").strip())
        if u.startswith("http://") or u.startswith("https://"):
            return u
    return ""


def _http_get_bytes(url, timeout=15):
    req = urllib.request.Request(
        str(url or ""),
        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def _download_emoji_by_md5(md5_hex):
    md5 = str(md5_hex or "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{32}", md5):
        return ""

    try:
        os.makedirs(EMOJI_CACHE_DIR, exist_ok=True)
    except Exception:
        pass

    for ext in (".gif", ".png", ".jpg", ".jpeg", ".webp"):
        name = f"emoji_{md5}{ext}"
        if os.path.exists(os.path.join(EMOJI_CACHE_DIR, name)):
            return name

    with _emoji_lookup_lock:
        info = _emoji_lookup.get(md5)
        last_refresh = float(_emoji_last_refresh or 0.0)

    if not info and _emoji_keys_dict and (time.time() - last_refresh) > 45:
        _build_emoji_lookup(_emoji_keys_dict)
        with _emoji_lookup_lock:
            info = _emoji_lookup.get(md5)

    if not isinstance(info, dict):
        return ""

    cdn_url = str(info.get("cdn_url", "") or "").strip()
    aes_key = str(info.get("aes_key", "") or "").strip()
    encrypt_url = str(info.get("encrypt_url", "") or "").strip()

    data = b""
    if cdn_url:
        try:
            data = _http_get_bytes(cdn_url)
        except Exception:
            data = b""

    if (not data) and encrypt_url and re.fullmatch(r"[0-9a-fA-F]{32}", aes_key):
        try:
            enc = _http_get_bytes(encrypt_url)
            key_bytes = bytes.fromhex(aes_key)
            cipher = AES.new(key_bytes, AES.MODE_CBC, iv=key_bytes)
            data = cipher.decrypt(enc)
            if data:
                pad = data[-1]
                if isinstance(pad, int) and 1 <= pad <= 16 and data[-pad:] == bytes([pad]) * pad:
                    data = data[:-pad]
        except Exception:
            data = b""

    if not data:
        return ""

    ext = ""
    if data[:3] == b"\xff\xd8\xff":
        ext = ".jpg"
    elif data[:8] == b"\x89PNG\r\n\x1a\n":
        ext = ".png"
    elif data[:6] in (b"GIF87a", b"GIF89a"):
        ext = ".gif"
    elif data[:4] == b"RIFF" and len(data) >= 12 and data[8:12] == b"WEBP":
        ext = ".webp"
    if not ext:
        return ""

    name = f"emoji_{md5}{ext}"
    out_path = os.path.join(EMOJI_CACHE_DIR, name)
    try:
        with open(out_path, "wb") as f:
            f.write(data)
        return name
    except Exception:
        return ""


def _resolve_emoji_media_url(source_blob, content_blob, ct_flag=None):
    src_text = _decode_maybe_text(source_blob)
    content_text = _decode_message_content(content_blob, 47, ct_flag)
    merged = "\n".join([src_text, content_text]).strip()
    if not merged:
        return ""

    direct = _extract_emoji_url_from_xml(merged)
    if direct:
        return direct

    md5 = _extract_emoji_md5_from_xml(merged)
    if not md5:
        md5 = _extract_hex_hash_from_packed_info(source_blob) or _extract_hex_hash_from_packed_info(content_blob)
    if not md5:
        return ""
    name = _download_emoji_by_md5(md5)
    if not name:
        return ""
    return _build_emoji_url(name)


def _extract_hex_hash_from_packed_info(value):
    if value is None:
        return ""
    if isinstance(value, (bytes, bytearray)):
        m = HEX32_RE_BYTES.search(bytes(value))
        return m.group(0).decode() if m else ""
    if isinstance(value, str):
        m = HEX32_RE_STR.search(value.lower())
        return m.group(0) if m else ""
    return ""


def _load_resource_meta_maps(server_ids, local_ids):
    by_server = {}
    by_local = {}
    sids = [int(x) for x in server_ids if isinstance(x, int) and x > 0]
    lids = [int(x) for x in local_ids if isinstance(x, int) and x >= 0]
    if (not sids and not lids) or not os.path.exists(DECRYPTED_MESSAGE_RESOURCE):
        return by_server, by_local

    sids = list(dict.fromkeys(sids))
    lids = list(dict.fromkeys(lids))
    try:
        conn = sqlite3.connect(f"file:{DECRYPTED_MESSAGE_RESOURCE}?mode=ro", uri=True)
        chunk = 200
        # Query by server ids
        for i in range(0, len(sids), chunk):
            sub = sids[i:i + chunk]
            placeholders = ",".join("?" for _ in sub)
            sql = f"""
                SELECT i.message_svr_id, i.message_local_id, i.message_create_time, i.packed_info, d.type, d.size
                FROM MessageResourceInfo i
                LEFT JOIN MessageResourceDetail d ON d.message_id = i.message_id
                WHERE i.message_svr_id IN ({placeholders})
                ORDER BY i.message_id DESC, d.resource_id DESC
            """
            for svr_id, local_id, create_time, packed_info, detail_type, detail_size in conn.execute(sql, sub).fetchall():
                if svr_id not in by_server:
                    by_server[svr_id] = {'hash': '', 'sticker_size': 0, 'create_time': create_time or 0}
                rec = by_server[svr_id]
                if not rec['hash']:
                    rec['hash'] = _extract_hex_hash_from_packed_info(packed_info)
                if not rec['sticker_size'] and detail_type == 65540 and isinstance(detail_size, int):
                    rec['sticker_size'] = detail_size
                if isinstance(local_id, int) and local_id >= 0 and local_id not in by_local:
                    by_local[local_id] = {'hash': rec['hash'], 'sticker_size': rec['sticker_size'], 'create_time': create_time or 0}

        # Query by local ids
        for i in range(0, len(lids), chunk):
            sub = lids[i:i + chunk]
            placeholders = ",".join("?" for _ in sub)
            sql = f"""
                SELECT i.message_svr_id, i.message_local_id, i.message_create_time, i.packed_info, d.type, d.size
                FROM MessageResourceInfo i
                LEFT JOIN MessageResourceDetail d ON d.message_id = i.message_id
                WHERE i.message_local_id IN ({placeholders})
                ORDER BY i.message_id DESC, d.resource_id DESC
            """
            for svr_id, local_id, create_time, packed_info, detail_type, detail_size in conn.execute(sql, sub).fetchall():
                if isinstance(local_id, int) and local_id >= 0:
                    if local_id not in by_local:
                        by_local[local_id] = {'hash': '', 'sticker_size': 0, 'create_time': create_time or 0}
                    rec = by_local[local_id]
                    if not rec['hash']:
                        rec['hash'] = _extract_hex_hash_from_packed_info(packed_info)
                    if not rec['sticker_size'] and detail_type == 65540 and isinstance(detail_size, int):
                        rec['sticker_size'] = detail_size
                if isinstance(svr_id, int) and svr_id > 0:
                    if svr_id not in by_server:
                        by_server[svr_id] = {'hash': '', 'sticker_size': 0, 'create_time': create_time or 0}
                    srec = by_server[svr_id]
                    if not srec['hash']:
                        srec['hash'] = _extract_hex_hash_from_packed_info(packed_info)
                    if not srec['sticker_size'] and detail_type == 65540 and isinstance(detail_size, int):
                        srec['sticker_size'] = detail_size
        conn.close()
    except Exception as e:
        print(f"[media] load resource meta failed: {e}", flush=True)
    return by_server, by_local


def _find_attach_file(chat_hash, ts, file_hash, local_type):
    if not chat_hash or not file_hash:
        return None
    month = datetime.fromtimestamp(ts).strftime('%Y-%m')
    img_dir = os.path.join(ATTACH_ROOT, chat_hash, month, "Img")
    if local_type == 47:
        names = [
            f"{file_hash}_t_W.dat", f"{file_hash}_W.dat", f"{file_hash}_h_W.dat",
            f"{file_hash}_t.dat", f"{file_hash}.dat", f"{file_hash}_h.dat",
        ]
    else:
        names = [
            f"{file_hash}_t.dat", f"{file_hash}.dat", f"{file_hash}_h.dat",
            f"{file_hash}_t_W.dat", f"{file_hash}_W.dat", f"{file_hash}_h_W.dat",
        ]
    for n in names:
        p = os.path.join(img_dir, n)
        if os.path.exists(p):
            return p

    # Fallback: search all months for this chat
    pattern = os.path.join(ATTACH_ROOT, chat_hash, "*", "Img", f"{file_hash}*.dat")
    for p in sorted(glob.glob(pattern)):
        if os.path.isfile(p):
            return p
    return None


def _find_attach_file_global_by_hash(file_hash, local_type):
    h = str(file_hash or "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{8,64}", h):
        return None
    lt = _normalize_msg_type(local_type)
    cache_key = (h, lt)
    with attach_hash_cache_lock:
        cached = attach_hash_file_cache.get(cache_key, None)
        if cached is not None:
            return cached or None

    pattern = os.path.join(ATTACH_ROOT, "*", "*", "Img", f"{h}*.dat")
    cands = []
    for p in glob.glob(pattern):
        if not os.path.isfile(p):
            continue
        name = os.path.basename(p)
        rank = _rank_sticker_name(name) if lt == 47 else _rank_image_name(name)
        try:
            mt = os.path.getmtime(p)
        except OSError:
            mt = 0.0
        cands.append((rank, -float(mt), p))
    if not cands:
        with attach_hash_cache_lock:
            attach_hash_file_cache[cache_key] = ""
        return None

    cands.sort(key=lambda x: (x[0], x[1]))
    best = cands[0][2]
    with attach_hash_cache_lock:
        attach_hash_file_cache[cache_key] = best
    return best


def _rank_sticker_name(file_name):
    n = file_name.lower()
    if n.endswith("_t_w.dat"):
        return 0
    if n.endswith("_w.dat"):
        return 1
    if n.endswith("_t.dat"):
        return 2
    if "_h" in n:
        return 4
    return 3


def _rank_image_name(file_name):
    n = file_name.lower()
    if n.endswith("_t.dat") or n.endswith("_t_w.dat"):
        return 0
    if n.endswith(".dat") and ("_h" not in n):
        return 1
    if "_h" in n:
        return 2
    return 3


def _time_candidates(ts):
    base = int(ts or 0)
    if base <= 0:
        return []
    offsets = [0, 8 * 3600, -8 * 3600, 9 * 3600, -9 * 3600, 10 * 3600, -10 * 3600, 12 * 3600, -12 * 3600]
    out = []
    seen = set()
    for off in offsets:
        v = base + off
        if v in seen:
            continue
        seen.add(v)
        out.append(v)
    return out


def _best_time_diff(file_mtime, ts_candidates):
    if not ts_candidates:
        return 10 ** 12
    mt = float(file_mtime or 0.0)
    return min(abs(mt - float(t)) for t in ts_candidates)


def _get_month_file_index(month):
    with month_file_index_lock:
        if month in month_file_index_cache:
            return month_file_index_cache[month]
    pattern = os.path.join(ATTACH_ROOT, "*", month, "Img", "*.dat")
    files = []
    for p in glob.glob(pattern):
        if not os.path.isfile(p):
            continue
        try:
            files.append({
                'path': p,
                'mtime': os.path.getmtime(p),
                'size': os.path.getsize(p),
                'name': os.path.basename(p),
                'rank': _rank_sticker_name(os.path.basename(p)),
            })
        except OSError:
            pass
    with month_file_index_lock:
        month_file_index_cache[month] = files
    return files


def _find_sticker_file_by_time(chat_hash, ts, size_hint=0):
    """Best-effort sticker match using time + optional size hint."""
    ts_cands = _time_candidates(ts)
    month = datetime.fromtimestamp(ts).strftime('%Y-%m')
    cands = []

    # 1) Prefer same chat hash directory.
    if chat_hash:
        img_dir = os.path.join(ATTACH_ROOT, chat_hash, month, "Img")
        if os.path.exists(img_dir):
            for p in glob.glob(os.path.join(img_dir, "*.dat")):
                if not os.path.isfile(p):
                    continue
                try:
                    mt = os.path.getmtime(p)
                    sz = os.path.getsize(p)
                    diff = _best_time_diff(mt, ts_cands)
                    if diff > 12 * 3600:
                        continue
                    size_penalty = abs(sz - size_hint) if size_hint else 0
                    cands.append((diff, size_penalty, _rank_sticker_name(os.path.basename(p)), p))
                except OSError:
                    pass
        if cands:
            cands.sort(key=lambda x: (x[0], x[1], x[2]))
            return cands[0][3]

    # 2) Global month fallback with stricter time window.
    for ent in _get_month_file_index(month):
        diff = _best_time_diff(ent['mtime'], ts_cands)
        if diff > 3600:
            continue
        size_penalty = abs(ent['size'] - size_hint) if size_hint else 0
        cands.append((diff, size_penalty, ent['rank'], ent['path']))
    if not cands:
        return None
    cands.sort(key=lambda x: (x[0], x[1], x[2]))
    return cands[0][3]


def _find_image_file_by_time(chat_hash, ts):
    ts_cands = _time_candidates(ts)
    month = datetime.fromtimestamp(ts).strftime('%Y-%m')
    cands = []

    if chat_hash:
        img_dir = os.path.join(ATTACH_ROOT, chat_hash, month, "Img")
        if os.path.exists(img_dir):
            for p in glob.glob(os.path.join(img_dir, "*.dat")):
                if not os.path.isfile(p):
                    continue
                try:
                    mt = os.path.getmtime(p)
                    diff = _best_time_diff(mt, ts_cands)
                    if diff > 12 * 3600:
                        continue
                    cands.append((diff, _rank_image_name(os.path.basename(p)), p))
                except OSError:
                    pass
        if cands:
            cands.sort(key=lambda x: (x[0], x[1]))
            return cands[0][2]

    for ent in _get_month_file_index(month):
        diff = _best_time_diff(ent['mtime'], ts_cands)
        if diff > 3600:
            continue
        cands.append((diff, _rank_image_name(ent['name']), ent['path']))
    if not cands:
        return None
    cands.sort(key=lambda x: (x[0], x[1]))
    return cands[0][2]


def _build_media_url(abs_path):
    if not abs_path:
        return ""
    root = os.path.abspath(ATTACH_ROOT)
    path = os.path.abspath(abs_path)
    if not path.startswith(root + os.sep):
        return ""
    rel = os.path.relpath(path, root).replace("\\", "/")
    return "/api/media?f=" + urllib.parse.quote(rel)


def _resolve_media_url_for_row(
    base_type,
    username,
    ts,
    server_id=0,
    local_id=0,
    source_blob=None,
    content_blob=None,
    ct_flag=None,
    resource_server_map=None,
    resource_local_map=None,
):
    t = _normalize_msg_type(base_type)
    if t not in (3, 47):
        return ""

    # Emoji: prefer xml/cdn md5 fallback first to cover custom/store stickers.
    if t == 47:
        emoji_url = _resolve_emoji_media_url(source_blob, content_blob, ct_flag=ct_flag)
        if emoji_url:
            return emoji_url

    resource_server_map = resource_server_map or {}
    resource_local_map = resource_local_map or {}

    meta = {}
    if isinstance(server_id, int) and server_id > 0:
        meta = resource_server_map.get(server_id, {}) or {}
    if not meta and isinstance(local_id, int) and local_id >= 0:
        meta = resource_local_map.get(local_id, {}) or {}
    size_hint = int(meta.get("sticker_size", 0) or 0) if isinstance(meta, dict) else 0
    if meta and meta.get("create_time"):
        try:
            if abs(int(meta.get("create_time", 0)) - int(ts or 0)) > 86400:
                meta = {}
                size_hint = 0
        except Exception:
            meta = {}
            size_hint = 0

    media_hash = str(meta.get("hash", "") or "")
    if not media_hash:
        media_hash = _extract_hex_hash_from_packed_info(source_blob)
    if not media_hash:
        media_hash = _extract_hex_hash_from_packed_info(content_blob)

    chat_hash = hashlib.md5(str(username or "").encode()).hexdigest() if username else ""
    if media_hash:
        media_path = _find_attach_file(chat_hash, int(ts or 0), media_hash, t)
        if media_path:
            return _build_media_url(media_path)
        media_path = _find_attach_file_global_by_hash(media_hash, t)
        if media_path:
            return _build_media_url(media_path)
    if t == 47:
        media_path = _find_sticker_file_by_time(chat_hash, int(ts or 0), size_hint=size_hint)
        if media_path:
            return _build_media_url(media_path)
    if t == 3:
        media_path = _find_image_file_by_time(chat_hash, int(ts or 0))
        if media_path:
            return _build_media_url(media_path)
    return ""


def _analysis_cache_get(key):
    now = time.time()
    with analysis_cache_lock:
        rec = analysis_cache.get(key)
        if not rec:
            return None
        ts, data = rec
        if (now - float(ts or 0.0)) > ANALYSIS_CACHE_TTL_SEC:
            analysis_cache.pop(key, None)
            return None
        return data


def _analysis_cache_set(key, data):
    with analysis_cache_lock:
        analysis_cache[key] = (time.time(), data)


def _analysis_cache_clear():
    with analysis_cache_lock:
        analysis_cache.clear()
        sender_first_seen_cache.clear()


def _sender_first_seen_cache_get(username):
    u = str(username or "").strip()
    if not u:
        return None
    now = time.time()
    with analysis_cache_lock:
        rec = sender_first_seen_cache.get(u)
        if not rec:
            return None
        ts, data = rec
        if (now - float(ts or 0.0)) > SENDER_FIRST_SEEN_CACHE_TTL_SEC:
            sender_first_seen_cache.pop(u, None)
            return None
        return data


def _sender_first_seen_cache_set(username, data):
    u = str(username or "").strip()
    if not u:
        return
    with analysis_cache_lock:
        sender_first_seen_cache[u] = (time.time(), data)


def _ensure_manual_score_loaded():
    global manual_score_entries
    with self_manual_score_lock:
        if manual_score_entries:
            return
        try:
            if os.path.exists(MANUAL_SCORE_FILE):
                with open(MANUAL_SCORE_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, list):
                    manual_score_entries = data
                else:
                    manual_score_entries = []
            else:
                manual_score_entries = []
        except Exception as e:
            print(f"[score] load manual entries failed: {e}", flush=True)
            manual_score_entries = []


def _save_manual_score_entries():
    with self_manual_score_lock:
        os.makedirs(os.path.dirname(MANUAL_SCORE_FILE), exist_ok=True)
        with open(MANUAL_SCORE_FILE, "w", encoding="utf-8") as f:
            json.dump(manual_score_entries, f, ensure_ascii=False, indent=2)


def _manual_score_list(username="", start_ts=0, end_ts=0):
    _ensure_manual_score_loaded()
    u = str(username or "").strip()
    out = []
    with self_manual_score_lock:
        rows = list(manual_score_entries)
    for r in rows:
        if not isinstance(r, dict):
            continue
        if u and str(r.get("username", "")).strip() != u:
            continue
        ts = int(r.get("ts", 0) or 0)
        if start_ts and ts and ts < int(start_ts):
            continue
        if end_ts and ts and ts > int(end_ts):
            continue
        out.append(r)
    out.sort(key=lambda x: int(x.get("created_at", 0) or 0), reverse=True)
    return out


def _manual_score_add(entry):
    _ensure_manual_score_loaded()
    now = int(time.time())
    obj = {
        "id": str(uuid.uuid4()),
        "username": str(entry.get("username", "") or "").strip(),
        "sender_id": str(entry.get("sender_id", "") or "").strip(),
        "sender": str(entry.get("sender", "") or "").strip(),
        "rule_id": str(entry.get("rule_id", "") or "").strip(),
        "points": int(entry.get("points", 0) or 0),
        "note": str(entry.get("note", "") or "").strip(),
        "ts": int(entry.get("ts", now) or now),
        "created_at": now,
    }
    if not obj["username"]:
        raise RuntimeError("missing username")
    if not obj["sender_id"]:
        raise RuntimeError("missing sender_id")
    if not obj["rule_id"]:
        raise RuntimeError("missing rule_id")
    if obj["points"] == 0:
        raise RuntimeError("points cannot be 0")
    with self_manual_score_lock:
        manual_score_entries.append(obj)
    _save_manual_score_entries()
    _analysis_cache_clear()
    return obj


def _manual_score_delete(entry_id):
    _ensure_manual_score_loaded()
    eid = str(entry_id or "").strip()
    if not eid:
        return False
    removed = False
    with self_manual_score_lock:
        keep = []
        for r in manual_score_entries:
            if isinstance(r, dict) and str(r.get("id", "")).strip() == eid:
                removed = True
                continue
            keep.append(r)
        if removed:
            manual_score_entries[:] = keep
    if removed:
        _save_manual_score_entries()
        _analysis_cache_clear()
    return removed


def _detect_image_mime(data):
    if len(data) >= 3 and data[:3] == b"\xff\xd8\xff":
        return "image/jpeg"
    if len(data) >= 8 and data[:8] == b"\x89PNG\r\n\x1a\n":
        return "image/png"
    if len(data) >= 6 and (data[:6] == b"GIF87a" or data[:6] == b"GIF89a"):
        return "image/gif"
    if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    if len(data) >= 2 and data[:2] == b"BM":
        return "image/bmp"
    return ""


def _normalize_image_aes_key(aes_key=None):
    raw = aes_key if aes_key is not None else IMAGE_AES_KEY
    if isinstance(raw, (bytes, bytearray)):
        buf = bytes(raw)
    else:
        text = str(raw or "").strip()
        if not text:
            return b""
        buf = text.encode("ascii", errors="ignore")
    if len(buf) < 16:
        return b""
    return buf[:16]


def _decrypt_wechat_v2_media(raw, aes_key=None, xor_key=None):
    if not isinstance(raw, (bytes, bytearray)) or len(raw) < 15:
        return "", b""

    sig = bytes(raw[:6])
    if sig not in (WECHAT_MEDIA_V2_MAGIC_FULL, WECHAT_MEDIA_V1_MAGIC_FULL):
        return "", b""

    key_bytes = b"cfcd208495d565ef" if sig == WECHAT_MEDIA_V1_MAGIC_FULL else _normalize_image_aes_key(aes_key)
    if len(key_bytes) < 16:
        return "", b""

    try:
        aes_size, xor_size = struct.unpack_from("<LL", raw, 6)
    except Exception:
        return "", b""

    aligned_aes_size = int(aes_size or 0)
    aligned_aes_size -= ~(~aligned_aes_size % 16)
    offset = 15
    if offset + aligned_aes_size > len(raw):
        return "", b""

    try:
        cipher = AES.new(key_bytes[:16], AES.MODE_ECB)
        dec_aes = Padding.unpad(cipher.decrypt(raw[offset:offset + aligned_aes_size]), AES.block_size)
    except Exception:
        return "", b""
    offset += aligned_aes_size

    raw_end = len(raw) - int(xor_size or 0)
    if raw_end < offset:
        return "", b""
    raw_data = raw[offset:raw_end]
    xor_tail = raw[raw_end:]
    xor_byte = _parse_byte_value(IMAGE_XOR_KEY if xor_key is None else xor_key, 0x88)
    dec_xor = bytes((b ^ xor_byte) for b in xor_tail)
    decoded = dec_aes + raw_data + dec_xor

    mime = _detect_image_mime(decoded)
    if mime:
        return mime, decoded
    return "", b""


def _read_wechat_media(file_path):
    with open(file_path, "rb") as f:
        raw = f.read()
    if not raw:
        return "application/octet-stream", raw

    mime = _detect_image_mime(raw)
    if mime:
        return mime, raw

    mime, decoded = _decrypt_wechat_v2_media(raw, IMAGE_AES_KEY, IMAGE_XOR_KEY)
    if mime and decoded:
        return mime, decoded

    # WeChat .dat may be XOR-obfuscated image data.
    signatures = [
        b"\xff\xd8\xff",               # jpeg
        b"\x89PNG\r\n\x1a\n",          # png
        b"GIF89a",                     # gif
        b"GIF87a",                     # gif
        b"RIFF",                       # webp (needs extra check)
        b"BM",                         # bmp
    ]
    for sig in signatures:
        key = raw[0] ^ sig[0]
        if len(raw) < len(sig):
            continue
        ok = True
        for i in range(len(sig)):
            if (raw[i] ^ key) != sig[i]:
                ok = False
                break
        if not ok:
            continue
        decoded = bytes(b ^ key for b in raw)
        mime = _detect_image_mime(decoded)
        if mime:
            return mime, decoded

    return "application/octet-stream", raw

def full_decrypt(db_path, out_path, enc_key):
    """Full decrypt one encrypted SQLite DB file to output path."""
    t0 = time.perf_counter()
    file_size = os.path.getsize(db_path)
    total_pages = file_size // PAGE_SZ
    os.makedirs(os.path.dirname(out_path), exist_ok=True)

    with open(db_path, 'rb') as fin, open(out_path, 'wb') as fout:
        for pgno in range(1, total_pages + 1):
            page = fin.read(PAGE_SZ)
            if len(page) < PAGE_SZ:
                if len(page) > 0:
                    page = page + b'\x00' * (PAGE_SZ - len(page))
                else:
                    break
            fout.write(decrypt_page(enc_key, page, pgno))

    ms = (time.perf_counter() - t0) * 1000
    return total_pages, ms


def decrypt_wal_full(wal_path, out_path, enc_key):
    """Replay WAL frames into decrypted DB and return (patched_pages, elapsed_ms)."""
    t0 = time.perf_counter()

    if not os.path.exists(wal_path):
        return 0, 0

    wal_size = os.path.getsize(wal_path)
    if wal_size <= WAL_HEADER_SZ:
        return 0, 0

    frame_size = WAL_FRAME_HEADER_SZ + PAGE_SZ  # 24 + 4096 = 4120
    patched = 0

    with open(wal_path, 'rb') as wf, open(out_path, 'r+b') as df:
        # 鐠囩睕AL header閿涘矁骞忛崣鏍х秼閸撳炒alt閸?
        wal_hdr = wf.read(WAL_HEADER_SZ)
        wal_salt1 = struct.unpack('>I', wal_hdr[16:20])[0]
        wal_salt2 = struct.unpack('>I', wal_hdr[20:24])[0]

        while wf.tell() + frame_size <= wal_size:
            fh = wf.read(WAL_FRAME_HEADER_SZ)
            if len(fh) < WAL_FRAME_HEADER_SZ:
                break
            pgno = struct.unpack('>I', fh[0:4])[0]
            frame_salt1 = struct.unpack('>I', fh[8:12])[0]
            frame_salt2 = struct.unpack('>I', fh[12:16])[0]

            ep = wf.read(PAGE_SZ)
            if len(ep) < PAGE_SZ:
                break

            # 閺嶏繝鐛? pgno閺堝鏅?娑?salt閸栧綊鍘よぐ鎾冲WAL閸涖劍婀?            if pgno == 0 or pgno > 1000000:
                continue
            if frame_salt1 != wal_salt1 or frame_salt2 != wal_salt2:
                continue  # 閺冄冩噯閺堢喖浠愰悾娆戞畱frame閿涘矁鐑︽潻?

            dec = decrypt_page(enc_key, ep, pgno)
            df.seek((pgno - 1) * PAGE_SZ)
            df.write(dec)
            patched += 1

    ms = (time.perf_counter() - t0) * 1000
    return patched, ms


def load_contact_names():
    global contact_names_cache, contact_names_cache_sig, contact_refresh_last_try

    now = time.time()
    # Best-effort refresh with light throttle.
    if (now - float(contact_refresh_last_try or 0.0)) >= 6.0:
        contact_refresh_last_try = now
        try:
            pages, ms = refresh_decrypted_contact_db()
            if pages:
                print(f"[contact] refreshed {pages}pg/{ms:.1f}ms", flush=True)
        except Exception as e:
            print(f"[contact] refresh failed: {e}", flush=True)

    try:
        stat = os.stat(CONTACT_CACHE)
        sig = (int(stat.st_mtime), int(stat.st_size))
    except Exception:
        sig = None

    with contact_names_cache_lock:
        if (
            contact_names_cache is not None
            and contact_names_cache_sig is not None
            and contact_names_cache_sig == sig
        ):
            return dict(contact_names_cache)

    names = {}
    try:
        conn = sqlite3.connect(f"file:{CONTACT_CACHE}?mode=ro", uri=True)
        rows = conn.execute("SELECT username, nick_name, remark FROM contact").fetchall()
        conn.close()
        for username, nick_name, remark in rows:
            if not isinstance(username, str) or not username:
                continue
            display = remark if isinstance(remark, str) and remark.strip() else (
                nick_name if isinstance(nick_name, str) and nick_name.strip() else username
            )
            names[username] = display
    except Exception:
        pass

    with contact_names_cache_lock:
        contact_names_cache = dict(names)
        contact_names_cache_sig = sig
    return names


def _normalize_msg_type(t):
    if isinstance(t, int) and t > 0xFFFFFFFF:
        return t & 0xFFFFFFFF
    return t


def format_msg_type(t):
    t = _normalize_msg_type(t)
    return {
        1: '文本',
        3: '图片',
        34: '语音',
        42: '名片',
        43: '视频',
        47: '表情',
        48: '位置',
        49: '链接/文件',
        50: '通话',
        10000: '系统',
        10002: '撤回',
    }.get(t, f'type={t}')


def msg_type_icon(t):
    t = _normalize_msg_type(t)
    return {
        1: 'TXT',
        3: 'IMG',
        34: 'AUD',
        42: 'CARD',
        43: 'VID',
        47: 'STK',
        48: 'LOC',
        49: 'LINK',
        50: 'CALL',
        10000: 'SYS',
        10002: 'REVOKE',
    }.get(t, 'MSG')


def _is_placeholder_session(username):
    """Skip synthetic fold sessions that duplicate real chats."""
    if not username:
        return False
    u = str(username).lower()
    return (
        u.startswith("@placeholder_")
        or u.startswith("placeholder_")
        or "placeholder_foldgroup" in u
    )


def _set_session_state_snapshot(state):
    global session_state_snapshot
    safe = dict(state) if isinstance(state, dict) else {}
    with session_state_snapshot_lock:
        session_state_snapshot = safe


def _get_session_state_snapshot():
    with session_state_snapshot_lock:
        return dict(session_state_snapshot)


def _parse_group_sender_prefix(text):
    if not isinstance(text, str):
        return "", ""
    if ':\n' not in text:
        return "", text
    sender, body = text.split(':\n', 1)
    return sender.strip(), body


def _guess_self_usernames():
    """Best-effort detection of current account wxid for sender matching."""
    global self_usernames_cache
    with self_usernames_cache_lock:
        if self_usernames_cache is not None:
            return set(self_usernames_cache)

        guesses = set()
        parts = re.split(r"[\\/]", DB_DIR)
        for part in parts:
            if not part:
                continue
            low = part.lower()
            if not low.startswith("wxid_"):
                continue
            guesses.add(low)
            m = re.match(r"(wxid_[0-9a-z]+)", low)
            if m:
                guesses.add(m.group(1))

        self_usernames_cache = guesses
        return set(guesses)


def _is_self_sender_username(sender_username):
    sender_norm = str(sender_username or "").strip().lower()
    if not sender_norm:
        return False
    return sender_norm in {
        str(item or "").strip().lower()
        for item in _guess_self_usernames()
        if str(item or "").strip()
    }


def _resolve_is_self_message(is_group, status, sender_username):
    if _is_self_sender_username(sender_username):
        return True
    if is_group:
        return False
    return isinstance(status, int) and status == 2


def _load_name2id_rowid_map(conn):
    mapping = {}
    try:
        rows = conn.execute("SELECT rowid, user_name FROM Name2Id").fetchall()
    except Exception:
        return mapping
    for rid, uname in rows:
        if not isinstance(rid, int):
            continue
        if not isinstance(uname, str) or not uname.strip():
            continue
        mapping[rid] = uname.strip()
    return mapping


def _is_malformed_sqlite_error(exc):
    text = str(exc or "").strip().lower()
    if not text:
        return False
    return ("malformed" in text) or ("database disk image is malformed" in text)


def _is_recoverable_message_query_error(exc):
    text = str(exc or "").strip().lower()
    if not text:
        return False
    if _is_malformed_sqlite_error(exc):
        return True
    return "database or disk is full" in text


def _load_message_rows_safe(
    db_path,
    table_name,
    start_ts=0,
    end_ts=0,
    limit=0,
    newest_first=False,
    before_ts=0,
    before_local_id=0,
):
    db_path = str(db_path or "").strip()
    table_name = str(table_name or "").strip()
    if not db_path or not table_name:
        return {}, {}, []

    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        cols = {
            str(r[1]).lower()
            for r in conn.execute(f"PRAGMA table_info([{table_name}])").fetchall()
            if len(r) >= 2
        }
        sender_map = _load_name2id_rowid_map(conn)
        select_parts = [
            "local_id",
            "create_time",
            "local_type",
            "message_content",
            "source" if "source" in cols else "'' AS source",
            "real_sender_id" if "real_sender_id" in cols else "0 AS real_sender_id",
            "status" if "status" in cols else "0 AS status",
            "server_id" if "server_id" in cols else "0 AS server_id",
            "WCDB_CT_message_content" if "wcdb_ct_message_content" in cols else "NULL AS WCDB_CT_message_content",
        ]

        minmax = conn.execute(
            f"SELECT MIN(create_time), MAX(create_time) FROM [{table_name}]"
        ).fetchone()
        bound_start = int(start_ts or 0)
        bound_end = int(end_ts or 0)
        table_min = int((minmax[0] or 0) if minmax else 0)
        table_max = int((minmax[1] or 0) if minmax else 0)
        if not bound_start:
            bound_start = table_min
        if not bound_end:
            bound_end = table_max
        if bound_start and bound_end and bound_start > bound_end:
            bound_start, bound_end = bound_end, bound_start

        def _decode_rows(raw_rows):
            out = []
            for row in raw_rows:
                local_id = row[0] if len(row) > 0 and isinstance(row[0], int) else 0
                ts = row[1] if len(row) > 1 and isinstance(row[1], int) else 0
                local_type = row[2] if len(row) > 2 and isinstance(row[2], int) else 0
                content = row[3] if len(row) > 3 else ""
                source = row[4] if len(row) > 4 else b""
                real_sender_id = row[5] if len(row) > 5 and isinstance(row[5], int) else 0
                status = row[6] if len(row) > 6 and isinstance(row[6], int) else 0
                server_id = row[7] if len(row) > 7 and isinstance(row[7], int) else 0
                ct_flag = row[8] if len(row) > 8 else None
                out.append({
                    "timestamp": ts,
                    "local_id": local_id,
                    "server_id": server_id,
                    "local_type": local_type,
                    "content": content,
                    "source": source,
                    "real_sender_id": real_sender_id,
                    "sender_username": sender_map.get(real_sender_id, ""),
                    "status": status,
                    "ct_flag": ct_flag,
                })
            return out

        cursor_ts = int(before_ts or 0)
        cursor_local_id = int(before_local_id or 0)

        def _build_where(lo, hi):
            where_clauses = []
            params = []
            if lo:
                where_clauses.append("create_time >= ?")
                params.append(int(lo))
            if hi:
                where_clauses.append("create_time <= ?")
                params.append(int(hi))
            if newest_first and cursor_ts > 0:
                if cursor_local_id > 0:
                    where_clauses.append("(create_time < ? OR (create_time = ? AND local_id < ?))")
                    params.extend([cursor_ts, cursor_ts, cursor_local_id])
                else:
                    where_clauses.append("create_time < ?")
                    params.append(cursor_ts)
            return where_clauses, params

        def _fetch_direct(lo, hi):
            where_clauses, params = _build_where(lo, hi)
            where_sql = (" WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
            order_dir = "DESC" if newest_first else "ASC"
            sql = (
                f"SELECT {', '.join(select_parts)} FROM [{table_name}]"
                f"{where_sql} ORDER BY create_time {order_dir}, local_id {order_dir}"
            )
            if int(limit or 0) > 0:
                sql += " LIMIT ?"
                params.append(int(limit))
            return _decode_rows(conn.execute(sql, tuple(params)).fetchall())

        def _fetch_range(lo, hi, depth=0):
            where_clauses, params = _build_where(lo, hi)
            where_sql = (" WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
            sql = (
                f"SELECT {', '.join(select_parts)} FROM [{table_name}]"
                f"{where_sql} ORDER BY create_time ASC, local_id ASC"
            )
            try:
                return _decode_rows(conn.execute(sql, tuple(params)).fetchall())
            except sqlite3.DatabaseError as e:
                if (not _is_malformed_sqlite_error(e)) or depth >= 18:
                    return []
                if lo <= 0 and hi <= 0:
                    return []
                if hi <= lo:
                    return []
                mid = int((int(lo) + int(hi)) // 2)
                if mid <= int(lo):
                    return []
                return _fetch_range(int(lo), mid, depth + 1) + _fetch_range(mid + 1, int(hi), depth + 1)

        try:
            rows = _fetch_direct(bound_start, bound_end)
            return cols, sender_map, rows
        except sqlite3.DatabaseError as e:
            if not _is_malformed_sqlite_error(e):
                return cols, sender_map, []

        rows = _fetch_range(bound_start, bound_end, 0)
        rows.sort(key=lambda x: (int(x.get("timestamp", 0) or 0), int(x.get("local_id", 0) or 0)))
        if newest_first:
            rows.reverse()
        if int(limit or 0) > 0:
            rows = rows[:int(limit)]
        return cols, sender_map, rows
    finally:
        conn.close()


def _load_fts_fallback_meta(username, local_rows):
    """
    Load best-effort plain text + sender mapping from message_fts.db.
    local_rows: iterable of (local_id, timestamp)
    returns: {local_id: [ {'create_time', 'sender_username', 'text'} ... ] }
    """
    rows = [
        (int(lid), int(ts or 0))
        for lid, ts in local_rows
        if isinstance(lid, int) and lid >= 0
    ]
    if not rows or not os.path.exists(DECRYPTED_MESSAGE_FTS):
        return {}

    local_ids = list(dict.fromkeys([lid for lid, _ in rows]))
    ts_by_lid = {}
    for lid, ts in rows:
        if lid not in ts_by_lid or ts > ts_by_lid[lid]:
            ts_by_lid[lid] = ts
    if not local_ids:
        return {}

    conn = None
    candidates = {}
    sender_ids = set()
    try:
        conn = sqlite3.connect(f"file:{DECRYPTED_MESSAGE_FTS}?mode=ro", uri=True)
        sid_row = conn.execute(
            "SELECT rowid FROM name2id WHERE username=?",
            (username,)
        ).fetchone()
        if not sid_row or not isinstance(sid_row[0], int):
            return {}
        session_id = sid_row[0]

        chunk = 200
        primary_shard = session_id % 4
        shard_order = [primary_shard] + [x for x in range(4) if x != primary_shard]

        def fetch_by_local_ids(shard, id_list):
            found_lids = set()
            table = f"message_fts_v4_{shard}"
            for i in range(0, len(id_list), chunk):
                sub = id_list[i:i + chunk]
                if not sub:
                    continue
                placeholders = ",".join("?" for _ in sub)
                sql = (
                    f"SELECT message_local_id, create_time, sender_id, acontent "
                    f"FROM [{table}] "
                    f"WHERE session_id=? AND message_local_id IN ({placeholders})"
                )
                params = tuple([session_id] + sub)
                try:
                    fetched = conn.execute(sql, params).fetchall()
                except Exception:
                    fetched = []
                for lid, cts, sid, acontent in fetched:
                    if not isinstance(lid, int):
                        continue
                    text = _clean_rich_text(acontent if isinstance(acontent, str) else "")
                    rec = {
                        'create_time': int(cts or 0),
                        'sender_id': int(sid or 0) if isinstance(sid, int) else 0,
                        'sender_username': '',
                        'text': text,
                    }
                    candidates.setdefault(lid, []).append(rec)
                    found_lids.add(lid)
                    if rec['sender_id'] > 0:
                        sender_ids.add(rec['sender_id'])
            return found_lids

        def has_reasonable_match(lid):
            recs = candidates.get(lid, [])
            if not recs:
                return False
            target = int(ts_by_lid.get(lid, 0) or 0)
            if target <= 0:
                return any(_clean_rich_text(rec.get('text', '')) for rec in recs)
            best_delta = None
            has_text = False
            for rec in recs:
                cts = int(rec.get('create_time', 0) or 0)
                if cts > 0:
                    d = abs(cts - target)
                    best_delta = d if best_delta is None else min(best_delta, d)
                if _clean_rich_text(rec.get('text', '')):
                    has_text = True
            if best_delta is None:
                return False
            # local_id can be reused across long time ranges; require close timestamp.
            if best_delta > 3600:
                return False
            # If text is empty, require an even tighter timestamp match.
            if (not has_text) and best_delta > 15:
                return False
            return True

        # Pass 1: query primary shard first.
        fetch_by_local_ids(primary_shard, local_ids)

        # Pass 2: query other shards for ids missing or weakly matched on primary.
        # Some datasets reuse message_local_id across shards/time; primary hit may be stale.
        remaining_ids = [lid for lid in local_ids if not has_reasonable_match(lid)]
        if remaining_ids:
            # Keep bounded in very large requests, but large enough for normal history pages.
            max_fanout_ids = 8000
            remaining_ids = remaining_ids[:max_fanout_ids]
            for shard in shard_order[1:]:
                # Query all remaining ids on every shard so we can select best timestamp later.
                fetch_by_local_ids(shard, remaining_ids)

        # Pass 3: fallback for unresolved local_id by matching close create_time.
        # Keep this bounded to avoid heavy scans on very large result sets.
        missing = [
            (lid, ts_by_lid.get(lid, 0))
            for lid in local_ids
            if (not has_reasonable_match(lid)) and ts_by_lid.get(lid, 0) > 0
        ]
        if 0 < len(missing) <= 120:
            for lid, ts in missing:
                found = False
                for shard in shard_order:
                    table = f"message_fts_v4_{shard}"
                    sql = (
                        f"SELECT message_local_id, create_time, sender_id, acontent "
                        f"FROM [{table}] "
                        f"WHERE session_id=? AND create_time BETWEEN ? AND ? "
                        f"ORDER BY ABS(create_time - ?) ASC "
                        f"LIMIT 2"
                    )
                    params = (session_id, ts - 3, ts + 3, ts)
                    try:
                        fetched = conn.execute(sql, params).fetchall()
                    except Exception:
                        fetched = []
                    for _lid2, cts, sid, acontent in fetched:
                        text = _clean_rich_text(acontent if isinstance(acontent, str) else "")
                        rec = {
                            'create_time': int(cts or 0),
                            'sender_id': int(sid or 0) if isinstance(sid, int) else 0,
                            'sender_username': '',
                            'text': text,
                        }
                        candidates.setdefault(lid, []).append(rec)
                        if rec['sender_id'] > 0:
                            sender_ids.add(rec['sender_id'])
                        found = True
                    if found:
                        break

        sender_map = {}
        if sender_ids:
            sender_id_list = list(sender_ids)
            for i in range(0, len(sender_id_list), 500):
                sub = sender_id_list[i:i + 500]
                placeholders = ",".join("?" for _ in sub)
                sql = f"SELECT rowid, username FROM name2id WHERE rowid IN ({placeholders})"
                for rid, uname in conn.execute(sql, tuple(sub)).fetchall():
                    if isinstance(rid, int) and isinstance(uname, str) and uname.strip():
                        sender_map[rid] = uname.strip()

        for lid, recs in candidates.items():
            recs.sort(key=lambda x: x.get('create_time', 0), reverse=True)
            for rec in recs:
                sid = rec.get('sender_id', 0)
                if sid in sender_map:
                    rec['sender_username'] = sender_map[sid]
    except Exception as e:
        print(f"[chat_history] load fts fallback failed: {e}", flush=True)
    finally:
        if conn is not None:
            conn.close()
    return candidates


def _pick_best_fts_candidate(cands, ts):
    if not cands:
        return None
    target = int(ts or 0)
    if target <= 0:
        return cands[0]
    best = min(
        cands,
        key=lambda x: (
            abs(int(x.get('create_time', 0)) - target),
            -int(x.get('create_time', 0))
        )
    )
    # FTS local_id may collide across time ranges; require close timestamp.
    if abs(int(best.get('create_time', 0)) - target) > 6 * 3600:
        return None
    return best


def _refresh_aux_db_throttled(decrypted_db_path, min_interval_sec=30):
    """
    Refresh heavy auxiliary DBs with throttle to avoid request-time stalls.
    Returns: (pages, ms, skipped)
    """
    key = os.path.abspath(decrypted_db_path)
    now = time.time()
    with aux_refresh_lock:
        last = aux_refresh_last.get(key, 0.0)
        if last and (now - last) < float(min_interval_sec):
            return 0, 0.0, True
        aux_refresh_last[key] = now

    try:
        pages, ms = refresh_decrypted_message_db(decrypted_db_path)
        return pages, ms, False
    except Exception:
        # Allow next request to retry soon when refresh failed.
        with aux_refresh_lock:
            aux_refresh_last[key] = max(0.0, now - float(min_interval_sec) + 2.0)
        raise


def _background_warm_message_indexes():
    # Warm heavy auxiliary DBs in background so first chat click is faster.
    time.sleep(1.0)
    for path, label in (
        (DECRYPTED_MESSAGE_RESOURCE, "resource"),
        (DECRYPTED_MESSAGE_FTS, "fts"),
    ):
        try:
            pages, ms = refresh_decrypted_message_db(path)
            print(
                f"[warmup] {label} refreshed {pages}pg/{ms:.1f}ms",
                flush=True
            )
        except Exception as e:
            print(f"[warmup] {label} failed: {e}", flush=True)


def _decode_maybe_text(value):
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if not isinstance(value, (bytes, bytearray)):
        return str(value)
    raw = bytes(value)
    for enc in ("utf-8", "utf-16le", "gb18030"):
        try:
            t = raw.decode(enc)
            if t:
                t = t.replace("\x00", "")
                if "<msg" in t or "<appmsg" in t:
                    return t
                if not _is_text_garbled(t):
                    return t
        except Exception:
            continue
    t = raw.decode("utf-8", errors="ignore").replace("\x00", "")
    if t and not _is_text_garbled(t):
        return t
    return ""


def _try_decompress_zstd(raw):
    if not isinstance(raw, (bytes, bytearray)):
        return raw
    if _zstd_dctx is None:
        return raw
    try:
        return _zstd_dctx.decompress(bytes(raw))
    except Exception:
        return raw


def _decode_message_content(value, msg_type=None, ct_flag=None):
    if value is None:
        return ""
    if isinstance(value, str):
        return _clean_rich_text(value)
    if not isinstance(value, (bytes, bytearray)):
        return _clean_rich_text(str(value))

    raw = bytes(value)
    if ct_flag == 4:
        raw = _try_decompress_zstd(raw)

    txt = _extract_text_from_message_blob(raw, msg_type)
    if not txt:
        txt = _decode_maybe_text(raw)
    return _clean_rich_text(txt)


def _is_text_garbled(text):
    """
    Heuristic detection for mojibake-like strings decoded from binary blobs.
    Keep it conservative to avoid hurting normal multilingual content.
    """
    if not isinstance(text, str):
        return False
    t = text.replace("\x00", "").strip()
    if not t:
        return False
    core = re.sub(r"\s+", "", t)
    if len(core) < 14:
        return False

    total = len(core)
    good = 0
    bad = 0
    latin_ext = 0
    ctrl_count = 0

    for ch in core:
        code = ord(ch)
        if ch == "\ufffd":
            bad += 3
            continue
        if code < 32 or 0x7F <= code <= 0x9F:
            bad += 2
            ctrl_count += 1
            continue
        if (
            0x4E00 <= code <= 0x9FFF
            or 0x3400 <= code <= 0x4DBF
            or 0x3040 <= code <= 0x30FF
            or 0xAC00 <= code <= 0xD7AF
        ):
            good += 2
            continue
        if ch.isascii():
            good += 1
            continue
        if 0x00C0 <= code <= 0x024F:
            latin_ext += 1
            bad += 1
            continue
        if 0x2000 <= code <= 0x206F:
            good += 1
            continue
        if 0x1F300 <= code <= 0x1FAFF:
            good += 1
            continue
        good += 1

    if bad >= 8 and bad > good:
        return True
    if ctrl_count >= 2 and (ctrl_count / max(total, 1)) >= 0.03:
        return True
    if latin_ext >= 6 and (latin_ext / max(total, 1)) > 0.30 and (good / max(total, 1)) < 0.55:
        return True
    return False


def _parse_int_loose(value, default=0):
    try:
        return int(str(value).strip())
    except Exception:
        return default


def _dedup_non_empty_texts(items):
    out = []
    seen = set()
    for item in items:
        t = _clean_rich_text(item)
        if not t:
            continue
        k = t.lower()
        if k in seen:
            continue
        seen.add(k)
        out.append(t)
    return out


def _strip_xml_tags(text):
    if not isinstance(text, str) or not text:
        return ""
    return _clean_rich_text(re.sub(r"<[^>]+>", "", text))

def _looks_noise_text(text):
    if not isinstance(text, str):
        return True
    t = text.strip()
    if not t:
        return True
    if t.startswith("(/`") or t.startswith("(/"):
        return True
    if re.fullmatch(r"[()\/`\[\]\{\}\|:;,.+\-_=~*'\"\\]{1,12}", t):
        return True
    if len(t) <= 4 and not re.search(r"[A-Za-z0-9\u4e00-\u9fff]", t):
        return True
    return False


def _has_mojibake_fragment(text):
    """
    Detect common mojibake fragments seen in link/appmsg decoded tails.
    Keep it conservative to avoid hurting normal CJK text.
    """
    if not isinstance(text, str):
        return False
    t = text.replace("\x00", "").strip()
    if not t:
        return False

    if _is_text_garbled(t):
        return True

    core = re.sub(r"\s+", "", t)
    if len(core) < 8:
        return False

    latin_ext = sum(1 for ch in core if 0x00C0 <= ord(ch) <= 0x024F)
    odd_marks = len(re.findall(r"[脴脨脼脝艗艙艁艂母茮僻屁譬篇偏片骗飘票撇瞥拼频贫品聘乒坪苹萍平凭瓶]", core))
    cjk = len(re.findall(r"[\u4e00-\u9fff]", core))
    ascii_word = len(re.findall(r"[A-Za-z0-9]", core))

    if latin_ext >= 6 and (latin_ext / max(len(core), 1)) > 0.18:
        return True
    if odd_marks >= 3:
        return True
    if latin_ext >= 4 and cjk <= 2 and ascii_word <= 4:
        return True
    if re.search(r"[\u00C0-\u024F]{4,}", core):
        return True
    return False


def _is_probably_garbled_line(line):
    """
    Stronger line-level detector for mixed mojibake tails.
    """
    if not isinstance(line, str):
        return False
    s = line.replace("\x00", "").strip()
    if not s:
        return False
    if _is_text_garbled(s):
        return True
    if _has_mojibake_fragment(s):
        return True

    # Keep normal Chinese/English/punctuation/URL chars, treat the rest as suspicious.
    allowed = re.compile(
        r"[\u4e00-\u9fffA-Za-z0-9\s\.\,\!\?\:\;\(\)\[\]\{\}銆娿€嬧€溾€濃€樷€欍€侊紝銆傦紒锛燂細锛涒€β封€擾/\-+=@#%&*|`~<>$]"
    )
    total = 0
    suspicious = 0
    for ch in s:
        if ch.isspace():
            continue
        total += 1
        if not allowed.fullmatch(ch):
            suspicious += 1

    if total >= 20 and suspicious >= 6 and (suspicious / max(total, 1)) > 0.14:
        return True

    # Continuous suspicious run is a strong signal.
    clean_map = "".join(ch if allowed.fullmatch(ch) else "搂" for ch in s)
    if "搂搂搂搂" in clean_map:
        return True
    return False


def _sanitize_link_text(text):
    """
    Sanitize appmsg/link text by removing likely mojibake lines.
    """
    t = _clean_rich_text(text if isinstance(text, str) else "")
    if not t:
        return ""

    lines = [ln.strip() for ln in t.split("\n")]
    good_lines = []
    for ln in lines:
        if not ln:
            continue
        if _looks_noise_text(ln):
            continue
        if _has_mojibake_fragment(ln):
            continue
        if _is_probably_garbled_line(ln):
            continue
        good_lines.append(ln)

    if good_lines:
        return "\n".join(good_lines).strip()

    if _looks_noise_text(t):
        return ""
    if _has_mojibake_fragment(t) or _is_probably_garbled_line(t):
        return ""
    return t


def _clip_one_line(text, max_len=160):
    t = _clean_rich_text(text if isinstance(text, str) else "")
    if not t:
        return ""
    t = re.sub(r"\s*\n+\s*", " ", t)
    t = re.sub(r"\s{2,}", " ", t).strip()
    if max_len and len(t) > int(max_len):
        keep = max(12, int(max_len) - 3)
        t = t[:keep].rstrip() + "..."
    return t


def _preview_xml_payload(xml_text, max_len=160, depth=0):
    """
    Extract human-readable summary from nested WeChat xml payloads.
    """
    if depth > 2:
        return ""
    t = _clean_rich_text(xml_text if isinstance(xml_text, str) else "")
    if not t:
        return ""
    low = t.lower()
    if "<" not in low or ">" not in low:
        return ""

    app_type = _parse_int_loose(_xml_tag_text(t, "type"), 0)
    title = _sanitize_link_text(_xml_tag_text(t, "title"))
    desc = _sanitize_link_text(_xml_tag_text(t, "des") or _xml_tag_text(t, "description"))
    content = _clean_rich_text(_xml_tag_text(t, "content"))

    if app_type == 62:
        # "拍一拍" payload
        if title:
            return _clip_one_line(title, max_len=max_len)
        plain_pat = _sanitize_link_text(_strip_xml_tags(t))
        if plain_pat:
            return _clip_one_line(plain_pat, max_len=max_len)
        return "拍一拍"

    # Prioritize concrete media markers.
    if "<location" in low:
        poi = _sanitize_link_text(
            _xml_tag_text(t, "label")
            or _xml_tag_text(t, "poiname")
            or _xml_tag_text(t, "name")
        )
        if poi:
            return _clip_one_line(f"位置：{poi}", max_len=max_len)
        return "[位置]"
    if "<videomsg" in low or "<video" in low:
        return "[视频]"
    if "<voicemsg" in low or "<voicetrans" in low:
        return "[语音]"
    if "<filemsg" in low:
        return "[文件]"
    if "<img" in low:
        return "[图片]"
    if "<emoji" in low:
        return "[表情]"

    if content:
        nested = _preview_xml_payload(content, max_len=max_len, depth=depth + 1)
        if nested:
            return nested
        content_clean = _sanitize_link_text(content)
        if content_clean:
            return _clip_one_line(content_clean, max_len=max_len)

    for cand in (title, desc):
        if cand:
            return _clip_one_line(cand, max_len=max_len)

    plain = _sanitize_link_text(_strip_xml_tags(t))
    if plain:
        return _clip_one_line(plain, max_len=max_len)
    return ""


def _extract_refer_content(xml_text):
    if not isinstance(xml_text, str) or not xml_text:
        return ""
    refer_block = _xml_tag_text(xml_text, "refermsg")
    if not refer_block:
        m = re.search(r"<refermsg[^>]*>(.*?)</refermsg>", xml_text, flags=re.S | re.I)
        refer_block = _clean_rich_text(m.group(1)) if m else ""
    if not refer_block:
        return ""

    content = _clean_rich_text(_xml_tag_text(refer_block, "content"))
    if content:
        nested = _preview_xml_payload(content, max_len=180)
        if nested:
            return nested
        content_clean = _sanitize_link_text(content)
        if content_clean:
            return content_clean

    for cand in (
        _xml_tag_text(refer_block, "title"),
        _strip_xml_tags(refer_block),
    ):
        nested = _preview_xml_payload(cand, max_len=180)
        if nested:
            return nested
        clean = _sanitize_link_text(cand)
        if clean:
            return clean
    return ""


def _preview_line(text, max_len=160):
    """
    Build a compact one-line preview for link/quote text.
    """
    raw = _clean_rich_text(text if isinstance(text, str) else "")
    if not raw:
        return ""
    has_xml = ("<" in raw and ">" in raw)
    if has_xml:
        xml_preview = _preview_xml_payload(raw, max_len=max_len)
        if xml_preview:
            raw = xml_preview
        else:
            stripped = _clip_one_line(_strip_xml_tags(raw), max_len=max_len)
            if stripped:
                return stripped
            return "[引用内容]"

    t = _sanitize_link_text(raw)
    if not t:
        # Keep very short visible originals like "?" or "[寮篯".
        fb = _clip_one_line(_strip_xml_tags(raw), max_len=max_len)
        if (
            fb
            and len(fb) <= 12
            and (not _has_mojibake_fragment(fb))
            and re.search(r"[A-Za-z0-9\u4e00-\u9fff\?\!锛燂紒銆傗€︷煈嶐煈庰煈岎煓忦煒傪煠ｐ煒勷煒咅煒嗮煓傪煓凁煒夝煒煒煒○煒庰煠旔煠濔煍ヰ煉煄夆潳馃挃]", fb)
        ):
            return fb
        return ""
    if not t:
        return ""
    return _clip_one_line(t, max_len=max_len)


def _finalize_display_content(msg_type, text):
    """
    Final UI-safe content for message cards.
    """
    t = _normalize_msg_type(msg_type)
    raw = _clean_rich_text(text if isinstance(text, str) else "")
    if _is_text_garbled(raw) or _has_mojibake_fragment(raw):
        raw = ""
    if raw and re.fullmatch(r"(?:0+\s*){2,}", raw):
        raw = ""

    # Media/sticker message bodies in DB are often binary tails; keep stable placeholders.
    if t == 3:
        return "[图片]"
    if t == 47:
        return "[表情]"
    if t == 49:
        raw = _sanitize_link_text(raw)
    return _fallback_content_by_type(t, raw)


def _extract_text_from_message_blob(value, msg_type=None):
    """
    Best-effort plain text extraction for WCDB encrypted/blob message_content.
    """
    norm_type = _normalize_msg_type(msg_type) if msg_type is not None else None
    if norm_type is not None and norm_type not in (1, 34, 43, 47, 48, 49, 10000, 10002):
        return ""

    if value is None:
        return ""
    if isinstance(value, str):
        t = _clean_rich_text(value)
        if _is_text_garbled(t) or _looks_noise_text(t):
            return ""
        return t
    if not isinstance(value, (bytes, bytearray)):
        t = _clean_rich_text(str(value))
        if _is_text_garbled(t) or _looks_noise_text(t):
            return ""
        return t

    raw = bytes(value)
    for enc in ("utf-8", "gb18030"):
        try:
            txt = raw.decode(enc, errors="ignore")
        except Exception:
            continue
        if not txt:
            continue
        # Keep from sender-prefix when possible: wxid_xxx:\n姝ｆ枃
        m = re.search(r"(wxid_[0-9a-z_]{4,}:\n.*)", txt, flags=re.I | re.S)
        if m:
            txt = m.group(1)
        # Cut trailing binary noise at first control char.
        txt = re.split(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]", txt, maxsplit=1)[0]
        txt = _clean_rich_text(txt)
        if not txt:
            continue
        if _is_text_garbled(txt) or _looks_noise_text(txt):
            continue
        # For appmsg(49) blobs, require stronger confidence.
        if norm_type == 49 and not re.search(r"[A-Za-z0-9\u4e00-\u9fff]{4,}", txt):
            continue
        if txt and not _is_text_garbled(txt):
            return txt
    return ""


def _clean_rich_text(text):
    if not isinstance(text, str):
        return ""
    t = text.replace("\x00", "").replace("\r", "")
    t = re.sub(r"[\x01-\x08\x0b-\x1f\x7f-\x9f]", "", t)
    t = re.sub(r"<!\[CDATA\[(.*?)\]\]>", r"\1", t, flags=re.S)
    t = html.unescape(t)
    t = t.strip()
    return t


def _xml_tag_text(xml_text, tag):
    if not isinstance(xml_text, str) or not xml_text:
        return ""
    m = re.search(rf"<{tag}>(.*?)</{tag}>", xml_text, flags=re.S | re.I)
    if not m:
        return ""
    return _clean_rich_text(m.group(1))


def _xml_attr_text(xml_text, tag, attr):
    if not isinstance(xml_text, str) or not xml_text:
        return ""
    m = re.search(rf"<{tag}\b[^>]*\b{attr}=\"(.*?)\"", xml_text, flags=re.S | re.I)
    if not m:
        return ""
    return _clean_rich_text(m.group(1))


def _extract_url(text):
    if not isinstance(text, str) or not text:
        return ""
    m = re.search(r"(https?://[^\s\"'<>]+)", text, flags=re.I)
    return m.group(1).strip() if m else ""


def _normalize_http_url(url):
    if not isinstance(url, str):
        return ""
    u = _clean_rich_text(url)
    if not u:
        return ""
    u = u.strip(" \t\r\n\"'<>[](){}，。！？；:：")
    if not re.match(r"^https?://", u, flags=re.I):
        return ""
    return u


def _extract_revoke_text(xml_text):
    raw = _clean_rich_text(xml_text if isinstance(xml_text, str) else "")
    if not raw:
        return ""
    low = raw.lower()
    if "revokemsg" not in low and "撤回了一条消息" not in raw:
        return ""

    content = _sanitize_link_text(_xml_tag_text(raw, "content"))
    if content and "撤回" in content and not _is_text_garbled(content):
        return content

    plain = _preview_line(_strip_xml_tags(raw), max_len=180)
    if plain and "撤回" in plain and not _is_text_garbled(plain):
        return plain

    return "撤回了一条消息"


def _source_name_from_url(url):
    u = _normalize_http_url(url)
    if not u:
        return ""
    try:
        host = (urllib.parse.urlparse(u).hostname or "").lower()
    except Exception:
        host = ""
    if not host:
        return ""

    if host.startswith("www."):
        host = host[4:]
    if host.startswith("m."):
        host = host[2:]

    domain_map = (
        (("xiaohongshu.com", "xhslink.com", "xhscdn.com"), "小红书"),
        (("bilibili.com", "b23.tv", "bili22.cn", "bili23.cn", "bili2233.cn"), "B站"),
        (("music.163.com", "y.music.163.com"), "网易云"),
        (("douyin.com", "iesdouyin.com", "v.douyin.com"), "抖音"),
        (("kuaishou.com", "chenzhongtech.com"), "快手"),
        (("weibo.com", "weibo.cn", "t.cn"), "微博"),
        (("zhihu.com", "zhihuishu.com"), "知乎"),
        (("mp.weixin.qq.com",), "公众号"),
        (("channels.weixin.qq.com",), "视频号"),
        (("weixin.qq.com",), "微信"),
        (("meeting.tencent.com",), "腾讯会议"),
        (("cloud.tencent.com",), "腾讯云"),
        (("docs.qq.com", "qq.com"), "腾讯"),
        (("aliyun.com", "aliyuncs.com"), "阿里云"),
        (("openai.com",), "OpenAI"),
        (("anthropic.com",), "Anthropic"),
        (("huggingface.co",), "HuggingFace"),
        (("notion.so", "notion.site"), "Notion"),
        (("juejin.cn",), "掘金"),
        (("github.com", "gist.github.com"), "GitHub"),
        (("youtube.com", "youtu.be"), "YouTube"),
        (("toutiao.com", "ixigua.com"), "头条"),
    )
    for domains, name in domain_map:
        for d in domains:
            if host == d or host.endswith("." + d):
                return name
    return "外部网站"


def _source_name_from_text(text):
    if not isinstance(text, str) or not text:
        return ""
    t = _clean_rich_text(text)
    if not t:
        return ""
    low = t.lower()

    checks = (
        (("微信聊天记录", "的聊天记录"), "微信聊天记录"),
        (("邀请你加入群聊", "邀请.*加入群聊", "加入了群聊"), "群聊邀请"),
        (("微信红包",), "微信红包"),
        (("微信转账",), "微信转账"),
        (("#接龙", "微信接龙"), "微信接龙"),
        (("拍了拍",), "拍一拍"),
        (("快速会议", "腾讯会议", "meeting.tencent.com"), "腾讯会议"),
        (("点击领取", "miniprogram", "mini program", "weapp", "小程序"), "小程序"),
        (("分享歌手", "网易云", "music.163.com"), "网易云"),
        (("发布了一篇笔记", "我发布了一篇笔记", "的笔记", "小红书", "xiaohongshu", "xhslink"), "小红书"),
        (("up主", "哔哩哔哩", "bilibili", "b站", "b23.tv"), "B站"),
        (("抖音", "douyin", "tiktok"), "抖音"),
        (("快手", "kuaishou"), "快手"),
        (("微博", "weibo", "t.cn/"), "微博"),
        (("知乎", "zhihu"), "知乎"),
        (("引用", "refermsg"), "引用消息"),
        (("公众号", "mp.weixin.qq.com"), "公众号"),
        (("视频号", "channels.weixin.qq.com", "finder"), "视频号"),
        (("weixin.qq.com",), "微信"),
        (("openai", "chatgpt"), "OpenAI"),
        (("anthropic", "claude"), "Anthropic"),
        (("github", "gitlab"), "GitHub"),
        (("阿里云", "aliyun"), "阿里云"),
        (("腾讯云", "tencent cloud", "cloud.tencent"), "腾讯云"),
    )
    for keys, name in checks:
        hit = False
        for k in keys:
            if not k:
                continue
            if any(ch in k for ch in (".", "*", "?", "^", "$", "+", "|", "(", ")", "[", "]", "{", "}")):
                try:
                    if re.search(k, t, flags=re.I):
                        hit = True
                        break
                except Exception:
                    pass
            if k in low:
                hit = True
                break
        if hit:
            return name

    if re.search(r"(?:^|[\s,，。；:：])[^ \n]{1,120}\.(?:docx?|pdf|zip|rar|7z|pptx?|xlsx?|xls|csv|txt|md|rtf|apk|exe)(?:$|[\s,，。；:：])", t, flags=re.I):
        return "文件"
    if _extract_url(t):
        return "外部网站"
    return ""


def _classify_link_like_text(text):
    """
    Classification labels for link/file-like messages (especially local_type=49).
    """
    t = _clean_rich_text(text if isinstance(text, str) else "")
    if not t:
        return ""
    low = t.lower()

    if "微信聊天记录" in t or "的聊天记录" in t:
        return "微信聊天记录"
    if "邀请你加入群聊" in t or re.search(r"邀请.*加入群聊|加入了群聊|通过扫描.*加入群聊", t):
        return "群聊邀请"
    if "微信红包" in t:
        return "微信红包"
    if "微信转账" in t:
        return "微信转账"
    if "#接龙" in t or "微信接龙" in t:
        return "微信接龙"
    if "拍了拍" in t:
        return "拍一拍"
    if "小程序" in t:
        return "小程序"
    if "快速会议" in t or "腾讯会议" in t or "meeting.tencent.com" in low:
        return "腾讯会议"
    if "点击领取" in t or "小程序" in t or "miniprogram" in low or "mini program" in low or "weapp" in low:
        return "小程序"
    if "分享歌手" in t or "网易云" in t or "music.163.com" in low:
        return "网易云"
    if "我发布了一篇笔记" in t or "发布了一篇笔记" in t or "的笔记" in t:
        return "小红书"
    if "up主" in low or "哔哩哔哩" in t or "bilibili" in low or "b站" in t:
        return "B站"
    if re.search(r"(?:^|[\s,，。；:：])[^ \n]{1,120}\.(?:docx?|pdf|zip|rar|7z|pptx?|xlsx?|xls|csv|txt|md|rtf|apk|exe)(?:$|[\s,，。；:：])", t, flags=re.I):
        return "文件"
    return ""


def _extract_link_meta(msg_type, rendered_text, source_blob=None):
    """
    Return best-effort (source_name, url) for link-like messages.
    """
    mt = _normalize_msg_type(msg_type)
    text = _clean_rich_text(rendered_text if isinstance(rendered_text, str) else "")
    source_text = _clean_rich_text(_decode_maybe_text(source_blob)) if source_blob is not None else ""
    if _is_text_garbled(source_text):
        source_text = ""
    merged_text = "\n".join([source_text, text]).strip()
    special_type = _classify_link_like_text(merged_text)

    if mt != 49 and not _extract_url(text) and not special_type:
        return "", ""

    url = ""
    if source_text:
        for tag in ("url", "shorturl", "dataurl", "weburl"):
            url = _normalize_http_url(_xml_tag_text(source_text, tag))
            if url:
                break
    if not url:
        url = _normalize_http_url(_extract_url(source_text) or _extract_url(text))
    card_title = _sanitize_link_text(_xml_tag_text(source_text, "title")) if source_text else ""
    card_desc = _sanitize_link_text(_xml_tag_text(source_text, "des") or _xml_tag_text(source_text, "description")) if source_text else ""
    card_source = _sanitize_link_text(_xml_tag_text(source_text, "appname") or _xml_tag_text(source_text, "sourcedisplayname")) if source_text else ""
    has_structured_card_bits = bool(card_title or card_desc or card_source or url)

    appmsg_type = 0
    refer_content = ""
    is_quote = False
    is_chatlog = False
    is_pat = False
    is_mini_program = False
    is_channels = False
    is_file = special_type == "文件"
    record_items = []

    if source_text:
        appmsg_type = _parse_int_loose(_xml_tag_text(source_text, "type"), 0)
        refer_content = _sanitize_link_text(_extract_refer_content(source_text))
        record_items = _extract_recorditem_items(_xml_tag_text(source_text, "recorditem"))
        is_chatlog = appmsg_type == 19 or bool(record_items) or ("聊天记录" in source_text)
        is_quote = (not is_chatlog) and (
            bool(refer_content) or appmsg_type in {40, 57} or ("<refermsg" in source_text.lower())
        )
        is_pat = appmsg_type == 62 or ("拍了拍" in source_text)
        is_mini_program = appmsg_type in {33, 36} or ("小程序" in source_text.lower()) or ("miniprogram" in source_text.lower())
        is_channels = appmsg_type == 51 or ("channels.weixin.qq.com" in source_text.lower()) or ("视频号" in source_text)
        is_file = is_file or appmsg_type == 6
    else:
        is_pat = "拍了拍" in text

    source = ""
    if source_text:
        for tag in ("appname", "sourcedisplayname", "sourceusername", "nickname", "publisher"):
            v = _sanitize_link_text(_xml_tag_text(source_text, tag))
            if v and not _is_probably_garbled_line(v):
                source = v
                break

    source_by_url = _source_name_from_url(url)
    source_by_text = _source_name_from_text("\n".join([source_text, text, source]))
    if special_type:
        source = special_type
    elif is_pat:
        source = "拍一拍"
    elif is_chatlog:
        source = "微信聊天记录"
    elif is_quote:
        source = "引用消息"
    elif is_mini_program:
        source = "小程序"
    elif is_channels:
        source = "视频号"
    elif mt == 49 and not url and not is_file:
        source = "卡片消息" if has_structured_card_bits else "引用消息"
    elif source_by_url:
        source = source_by_url
    elif source_by_text:
        source = source_by_text

    if not source and mt == 49 and text and not url:
        source = "卡片消息" if has_structured_card_bits else "引用消息"

    if isinstance(source, str):
        source = source.strip()
    else:
        source = ""
    if source and len(source) > 24:
        source = source[:24]

    return source, url


def _format_bytes_brief(size):
    n = _parse_int_loose(size, 0)
    if n <= 0:
        return ""
    if n < 1024:
        return f"{n}B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f}KB"
    if n < 1024 * 1024 * 1024:
        return f"{n / 1024 / 1024:.1f}MB"
    return f"{n / 1024 / 1024 / 1024:.2f}GB"


def _parse_xml_tree_loose(xml_text):
    import xml.etree.ElementTree as ET

    t = _clean_rich_text(xml_text if isinstance(xml_text, str) else "")
    if not t:
        return None

    start = len(t)
    for marker in ("<?xml", "<msg", "<appmsg", "<location", "<videomsg", "<voicemsg", "<refermsg"):
        idx = t.find(marker)
        if idx >= 0 and idx < start:
            start = idx
    if start < len(t):
        t = t[start:]

    wrappers = [t]
    low = t.lower()
    if low.startswith("<appmsg") or low.startswith("<location") or low.startswith("<videomsg") or low.startswith("<voicemsg") or low.startswith("<refermsg"):
        wrappers.append(f"<msg>{t}</msg>")

    for candidate in wrappers:
        try:
            return ET.fromstring(candidate)
        except ET.ParseError:
            continue
    return None


def _et_findtext(node, path):
    if node is None:
        return ""
    try:
        return _clean_rich_text(node.findtext(path) or "")
    except Exception:
        return ""


def _rich_body_text(text, placeholders=None):
    preview = _preview_line(text, max_len=220)
    if not preview:
        return ""
    if placeholders and preview in placeholders:
        return ""
    return preview


def _extract_recorditem_items(record_xml):
    root = _parse_xml_tree_loose(record_xml)
    if root is None:
        return []
    items = []
    for item in root.findall(".//dataitem"):
        name = _sanitize_link_text(
            _et_findtext(item, "sourcename")
            or _et_findtext(item, "displayname")
            or _et_findtext(item, "sourceusername")
        )
        text = _sanitize_link_text(
            _et_findtext(item, "datadesc")
            or _et_findtext(item, "title")
            or _et_findtext(item, "desc")
            or _et_findtext(item, "content")
        )
        if not name and not text:
            continue
        items.append({
            "name": name[:48] if name else "",
            "text": text[:120] if text else "",
        })
        if len(items) >= 8:
            break
    return items


def _build_appmsg_rich_media(rendered_text, source_blob=None, link_source="", link_url="", media_url=""):
    rendered = _clean_rich_text(rendered_text if isinstance(rendered_text, str) else "")
    source_text = _clean_rich_text(_decode_maybe_text(source_blob)) if source_blob is not None else ""
    if _is_text_garbled(source_text):
        source_text = ""

    xml_text = source_text if "<appmsg" in source_text.lower() or "<msg" in source_text.lower() else rendered
    root = _parse_xml_tree_loose(xml_text)
    appmsg = None
    if root is not None:
        if str(getattr(root, "tag", "")).lower() == "appmsg":
            appmsg = root
        else:
            appmsg = root.find(".//appmsg")

    title = ""
    desc = ""
    url = _normalize_http_url(link_url)
    source = _sanitize_link_text(link_source)
    app_type = 0
    ref_name = ""
    ref_preview = ""
    file_ext = ""
    file_size = 0
    file_name = ""
    record_items = []

    if appmsg is not None:
        title = _sanitize_link_text(_et_findtext(appmsg, "title"))
        desc = _sanitize_link_text(_et_findtext(appmsg, "des") or _et_findtext(appmsg, "description"))
        url = _normalize_http_url(_et_findtext(appmsg, "url") or url)
        source = _sanitize_link_text(
            _et_findtext(appmsg, "sourcedisplayname")
            or _et_findtext(appmsg, "appname")
            or _et_findtext(appmsg, "sourceusername")
            or source
        )
        app_type = _parse_int_loose(_et_findtext(appmsg, "type"), 0)

        ref = appmsg.find(".//refermsg")
        if ref is not None:
            ref_name = _sanitize_link_text(
                _et_findtext(ref, "displayname")
                or _et_findtext(ref, "sourcename")
            )
            ref_preview = _preview_line(
                _et_findtext(ref, "content")
                or _et_findtext(ref, "title"),
                max_len=140,
            )
        if not ref_name:
            ref_name = _sanitize_link_text(
                _xml_tag_text(source_text, "displayname")
                or _xml_tag_text(source_text, "sourcename")
            )
        if not ref_preview:
            ref_preview = _preview_line(_extract_refer_content(source_text), max_len=140)
        if ref_name and ref_preview and ref_name == ref_preview:
            ref_preview = ""

        attach = appmsg.find(".//appattach")
        if attach is not None:
            file_ext = _sanitize_link_text(_et_findtext(attach, "fileext"))
            file_size = _parse_int_loose(_et_findtext(attach, "totallen"), 0)
            file_name = _sanitize_link_text(_et_findtext(attach, "filekey") or _et_findtext(attach, "filename"))

        record_items = _extract_recorditem_items(_xml_tag_text(source_text, "recorditem"))

    if not title:
        title = _preview_line(rendered, max_len=120)
    if not desc:
        desc = ""
    if not source:
        source = _sanitize_link_text(link_source) or _source_name_from_url(url) or _source_name_from_text("\n".join([source_text, rendered]))

    quote_text = title or rendered
    if not ref_preview and "引用：" in quote_text:
        head, tail = quote_text.split("引用：", 1)
        head = _preview_line(head, max_len=120)
        tail = _preview_line(tail, max_len=140)
        if tail:
            title = head or title or "引用回复"
            ref_preview = tail
            body = ""
            if not source or source == "其他":
                source = "引用消息"

    is_chatlog = app_type == 19 or bool(record_items)
    is_quote = (not is_chatlog) and (bool(ref_preview) or app_type in {40, 57})
    is_pat = app_type == 62 or "拍了拍" in "\n".join([title, desc, rendered, source_text])
    is_file = app_type == 6 or bool(file_ext or file_size) or _source_name_from_text("\n".join([title, desc, rendered])) == "文件"
    is_miniapp = app_type in {33, 36} or ("小程序" in source_text) or ("miniprogram" in source_text.lower())
    is_channels = app_type == 51 or ("channels.weixin.qq.com" in url.lower()) or ("finder" in url.lower()) or ("视频号" in "\n".join([title, desc, source_text]))
    if url:
        source = _source_name_from_url(url) or source
    if is_chatlog and (not source or source in {"其他", "微信", "卡片消息", "引用消息"}):
        source = "微信聊天记录"
    elif is_quote and (not source or source in {"其他", "微信"}):
        source = "引用消息"
    elif is_pat and (not source or source in {"其他", "微信", "卡片消息"}):
        source = "拍一拍"
    elif is_miniapp and (not source or source == "其他"):
        source = "小程序"
    elif is_channels and (not source or source in {"其他", "微信"}):
        source = "视频号"
    elif not url and not is_quote and not is_chatlog and not is_file and not is_miniapp and not is_channels:
        source = "卡片消息"

    body = _rich_body_text(rendered, {"[链接/文件]"})

    if is_chatlog:
        return {
            "kind": "chatlog",
            "badge": "聊天记录",
            "title": title or "聊天记录",
            "desc": desc,
            "source": source,
            "url": url,
            "items": record_items,
            "body": body if body and body != title else "",
            "meta": f"{len(record_items)} 条摘录" if record_items else "",
            "suppress_content": True,
            "suppress_link": bool(url),
            "suppress_media": True,
        }

    if is_quote:
        quote_body = body
        if quote_body and "引用：" in quote_body:
            quote_body = _preview_line(quote_body.split("引用：", 1)[0], max_len=120)
        return {
            "kind": "quote",
            "badge": "引用回复",
            "title": title or body or "引用回复",
            "desc": desc,
            "source": source,
            "url": url,
            "body": quote_body if quote_body and quote_body != title else "",
            "quote_author": ref_name,
            "quote": ref_preview,
            "meta": "",
            "suppress_content": True,
            "suppress_link": bool(url),
            "suppress_media": True,
        }

    if is_pat:
        return {
            "kind": "pat",
            "badge": "拍一拍",
            "title": title or body or "拍一拍",
            "desc": desc,
            "source": source or "拍一拍",
            "url": url,
            "body": body if body and body != title else "",
            "meta": "",
            "suppress_content": True,
            "suppress_link": bool(url),
            "suppress_media": True,
        }

    if is_file:
        meta_bits = []
        if file_ext:
            meta_bits.append(file_ext.upper())
        size_text = _format_bytes_brief(file_size)
        if size_text:
            meta_bits.append(size_text)
        return {
            "kind": "file",
            "badge": "文件",
            "title": title or file_name or "文件消息",
            "desc": desc,
            "source": source,
            "url": url,
            "body": body if body and body != title else "",
            "meta": " · ".join(meta_bits),
            "suppress_content": True,
            "suppress_link": bool(url),
            "suppress_media": True,
        }

    if is_miniapp:
        return {
            "kind": "miniapp",
            "badge": "小程序",
            "title": title or "小程序",
            "desc": desc,
            "source": source,
            "url": url,
            "body": body if body and body != title else "",
            "meta": "",
            "suppress_content": True,
            "suppress_link": bool(url),
            "suppress_media": True,
        }

    if is_channels:
        return {
            "kind": "channels",
            "badge": "视频号",
            "title": title or "视频号内容",
            "desc": desc,
            "source": source,
            "url": url,
            "body": body if body and body != title else "",
            "meta": "",
            "suppress_content": True,
            "suppress_link": bool(url),
            "suppress_media": True,
        }

    if not url and not desc and source in ("", "其他") and title in {"拍一拍", "[链接/文件]"}:
        return None

    if title or desc or url or source:
        return {
            "kind": "link",
            "badge": "链接卡片",
            "title": title or body or "链接分享",
            "desc": desc,
            "source": source,
            "url": url,
            "body": body if body and body != title else "",
            "meta": "",
            "suppress_content": True,
            "suppress_link": bool(url),
            "suppress_media": True,
        }

    return None


def _extract_rich_media_payload(msg_type, rendered_text, source_blob=None, link_source="", link_url="", media_url=""):
    msg_type = _normalize_msg_type(msg_type)
    rendered = _clean_rich_text(rendered_text if isinstance(rendered_text, str) else "")
    source_text = _clean_rich_text(_decode_maybe_text(source_blob)) if source_blob is not None else ""
    if _is_text_garbled(source_text):
        source_text = ""

    if msg_type == 48:
        merged = source_text or rendered
        title = _sanitize_link_text(
            _xml_tag_text(merged, "label")
            or _xml_attr_text(merged, "location", "label")
            or _xml_tag_text(merged, "poiname")
            or _xml_attr_text(merged, "location", "poiname")
            or _xml_tag_text(merged, "name")
            or _xml_attr_text(merged, "location", "name")
        )
        x = _sanitize_link_text(
            _xml_tag_text(merged, "x")
            or _xml_attr_text(merged, "location", "x")
            or _xml_attr_text(merged, "location", "lat")
        )
        y = _sanitize_link_text(
            _xml_tag_text(merged, "y")
            or _xml_attr_text(merged, "location", "y")
            or _xml_attr_text(merged, "location", "lng")
            or _xml_attr_text(merged, "location", "lon")
        )
        desc = _rich_body_text(rendered, {"位置：" + title if title else "", "[位置]"})
        meta = f"{x},{y}" if x and y else ""
        if title or meta or desc:
            return {
                "kind": "location",
                "badge": "位置分享",
                "title": title or "位置消息",
                "desc": desc,
                "source": "",
                "url": "",
                "body": "",
                "meta": meta,
                "suppress_content": True,
                "suppress_link": True,
                "suppress_media": True,
            }
        return None

    if msg_type == 49:
        return _build_appmsg_rich_media(rendered, source_blob=source_blob, link_source=link_source, link_url=link_url, media_url=media_url)

    if msg_type == 43:
        length_ms = _parse_int_loose(
            _xml_attr_text(source_text, "videomsg", "playlength")
            or _xml_tag_text(source_text, "playlength"),
            0,
        )
        size_bytes = _parse_int_loose(
            _xml_attr_text(source_text, "videomsg", "length")
            or _xml_tag_text(source_text, "length"),
            0,
        )
        meta_bits = []
        if length_ms > 0:
            meta_bits.append(f"{length_ms / 1000:.1f}s")
        size_text = _format_bytes_brief(size_bytes)
        if size_text:
            meta_bits.append(size_text)
        return {
            "kind": "video",
            "badge": "视频",
            "title": _rich_body_text(rendered, {"[视频]"}) or "视频消息",
            "desc": "",
            "source": "",
            "url": "",
            "body": "",
            "meta": " · ".join(meta_bits),
            "suppress_content": True,
            "suppress_link": True,
            "suppress_media": False,
        }

    if msg_type == 34:
        length_ms = _parse_int_loose(
            _xml_attr_text(source_text, "voicemsg", "voicelength")
            or _xml_tag_text(source_text, "voicelength"),
            0,
        )
        meta = f"{length_ms / 1000:.1f}s" if length_ms > 0 else ""
        return {
            "kind": "voice",
            "badge": "语音",
            "title": "语音消息",
            "desc": _rich_body_text(rendered, {"[语音]"}) or "",
            "source": "",
            "url": "",
            "body": "",
            "meta": meta,
            "suppress_content": True,
            "suppress_link": True,
            "suppress_media": True,
        }

    return None


def _render_link_or_quote_text(msg_type, text, source_blob):
    """
    Improve readability for link/quote messages:
    - Link share: show visible text/title/url
    - Quote message: show current text + quoted text
    """
    msg_type = _normalize_msg_type(msg_type)
    text_in = _clean_rich_text(text if isinstance(text, str) else "")
    if _is_text_garbled(text_in):
        text_in = ""
    source_text = _clean_rich_text(_decode_maybe_text(source_blob))
    if _is_text_garbled(source_text):
        source_text = ""

    if msg_type in (10000, 10002):
        revoke_text = _extract_revoke_text(source_text) or _extract_revoke_text(text_in)
        if revoke_text:
            return revoke_text
        if source_text and "<" in source_text and ">" in source_text:
            plain = _preview_line(_strip_xml_tags(source_text), max_len=220)
            if plain and not _is_text_garbled(plain):
                return plain
        if text_in and "<" in text_in and ">" in text_in:
            plain = _preview_line(_strip_xml_tags(text_in), max_len=220)
            if plain and not _is_text_garbled(plain):
                return plain

    if msg_type == 48:
        merged = source_text or text_in
        if "<location" in merged.lower() or "<msg" in merged.lower():
            poi = (
                _xml_tag_text(merged, "label")
                or _xml_tag_text(merged, "poiname")
                or _xml_tag_text(merged, "name")
            )
            x = _xml_tag_text(merged, "x")
            y = _xml_tag_text(merged, "y")
            if poi:
                return f"位置：{poi}"
            if x and y:
                return f"位置：{x},{y}"

    if msg_type == 62:
        merged = source_text or text_in
        pat_preview = _preview_xml_payload(merged, max_len=220)
        if pat_preview:
            return pat_preview
        title = _preview_line(_xml_tag_text(merged, "title"), max_len=220)
        if title:
            return title
        plain = _preview_line(_strip_xml_tags(merged), max_len=220)
        if plain:
            return plain
        return "拍一拍"

    if msg_type == 49 and text_in.startswith("分享了一个链接："):
        text_in = _clean_rich_text(text_in.replace("分享了一个链接：", "", 1))

    if "<msg" in text_in or "<appmsg" in text_in:
        st_low = source_text.lower()
        source_has_payload = any(
            tag in st_low for tag in (
                "<appmsg", "<emoji", "<img", "<location", "<videomsg", "<voicemsg", "<refermsg"
            )
        )
        if not source_has_payload:
            source_text = text_in
            text_in = ""

    if msg_type == 49 and source_text:
        appmsg_type = _parse_int_loose(_xml_tag_text(source_text, "type"), 0)
        title = _sanitize_link_text(_xml_tag_text(source_text, "title"))
        desc = _sanitize_link_text(_xml_tag_text(source_text, "des") or _xml_tag_text(source_text, "description"))
        url = _xml_tag_text(source_text, "url") or _xml_tag_text(source_text, "shorturl")
        if not url:
            url = _extract_url(source_text) or _extract_url(text_in)

        refer_content = _sanitize_link_text(_extract_refer_content(source_text))
        record_items = _extract_recorditem_items(_xml_tag_text(source_text, "recorditem"))
        quote_types = {40, 57}
        link_types = {3, 5, 6, 33, 36, 74}
        is_chatlog = appmsg_type == 19 or bool(_extract_recorditem_items(_xml_tag_text(source_text, "recorditem")))
        is_quote = (not is_chatlog) and (
            bool(refer_content) or appmsg_type in quote_types or ("<refermsg" in source_text.lower())
        )
        is_link = bool(url) or appmsg_type in link_types or ("<url>" in source_text.lower())

        if appmsg_type == 62:
            pat_text = _preview_line(title or text_in, max_len=220)
            if not pat_text:
                pat_text = _preview_xml_payload(source_text, max_len=220)
            if not pat_text:
                pat_text = _preview_line(_strip_xml_tags(source_text), max_len=220)
            return pat_text or "拍一拍"

        if is_chatlog:
            preview_lines = []
            title_preview = _preview_line(title, max_len=150)
            if title_preview:
                preview_lines.append(title_preview)
            for item in record_items[:4]:
                item_name = _sanitize_link_text(item.get("name", ""))
                item_text = _sanitize_link_text(item.get("text", ""))
                line = ""
                if item_name and item_text:
                    line = f"{item_name}: {item_text}"
                else:
                    line = item_name or item_text
                line_preview = _preview_line(line, max_len=170)
                if not line_preview:
                    continue
                if any(line_preview == x or line_preview in x or x in line_preview for x in preview_lines):
                    continue
                preview_lines.append(line_preview)
            if not preview_lines:
                for cand, cap in (
                    (title, 150),
                    (refer_content, 160),
                    (desc, 130),
                    (_strip_xml_tags(source_text), 240),
                ):
                    p = _preview_line(cand, max_len=cap)
                    if not p:
                        continue
                    if any(p == x or p in x or x in p for x in preview_lines):
                        continue
                    preview_lines.append(p)
                    if len(preview_lines) >= 4:
                        break
            if preview_lines:
                return "\n".join(preview_lines).strip()

        if is_quote:
            current_preview = _preview_line(text_in, max_len=260)
            refer_preview = _preview_line(refer_content, max_len=170)
            title_preview = _preview_line(title, max_len=150)
            desc_preview = _preview_line(desc, max_len=130)

            if (not current_preview) and title_preview:
                current_preview = title_preview
                title_preview = ""

            if current_preview and title_preview and title_preview == current_preview:
                title_preview = ""

            quote_preview = ""
            for cand in (refer_preview, title_preview, desc_preview):
                if cand and cand != current_preview:
                    quote_preview = cand
                    break

            if current_preview and quote_preview:
                return f"{current_preview}\n引用：{quote_preview}"
            if current_preview:
                return current_preview
            if quote_preview:
                return f"引用：{quote_preview}"

            xml_fallback = _preview_xml_payload(source_text, max_len=240)
            if xml_fallback:
                return xml_fallback
            plain = _preview_line(_strip_xml_tags(source_text), max_len=240)
            if plain and not _is_text_garbled(plain):
                return plain

        if is_link:
            pieces = []
            for cand, cap in ((text_in, 240), (title, 150), (desc, 130)):
                p = _preview_line(cand, max_len=cap)
                if not p:
                    continue
                if any(p == x or p in x or x in p for x in pieces):
                    continue
                pieces.append(p)
            if url:
                url_clean = _normalize_http_url(url) or _extract_url(url)
                if url_clean and not any(url_clean in p for p in pieces):
                    pieces.append(url_clean)
            if pieces:
                return "\n".join(pieces).strip()

        plain_candidates = []
        for cand, cap in (
            (text_in, 240),
            (refer_content, 160),
            (title, 150),
            (desc, 130),
            (_strip_xml_tags(source_text), 240),
        ):
            p = _preview_line(cand, max_len=cap)
            if not p:
                continue
            if any(p == x or p in x or x in p for x in plain_candidates):
                continue
            plain_candidates.append(p)
            if len(plain_candidates) >= 2:
                break
        if plain_candidates:
            return "\n".join(plain_candidates).strip()

    if not text_in and source_text:
        src_text = _xml_tag_text(source_text, "content") or _xml_tag_text(source_text, "title")
        if src_text and not _is_text_garbled(src_text):
            return src_text
        if "<" in source_text and ">" in source_text:
            plain = _strip_xml_tags(source_text)
            if plain and not _is_text_garbled(plain):
                return plain
    plain = _sanitize_link_text(text_in)
    if msg_type == 49 and plain:
        return _preview_line(plain, max_len=260) or plain
    return plain


def _fallback_content_by_type(msg_type, content):
    msg_type = _normalize_msg_type(msg_type)
    text = content if isinstance(content, str) else ""
    text = text.strip()
    if text:
        return text
    return {
        1: "",
        3: "[图片]",
        34: "[语音]",
        42: "[名片]",
        43: "[视频]",
        47: "[表情]",
        48: "[位置]",
        49: "[链接/文件]",
        50: "[通话]",
        10000: "[系统消息]",
        10002: "[撤回消息]",
    }.get(msg_type, "[消息]")


def _display_msg_type(msg_type, content="", source_blob=None):
    t = _normalize_msg_type(msg_type)
    if t in (10000, 10002):
        source_text = _clean_rich_text(_decode_maybe_text(source_blob)) if source_blob is not None else ""
        revoke_text = _extract_revoke_text(source_text) or _extract_revoke_text(content)
        if revoke_text:
            return "撤回"
    if t == 49:
        source_text = _clean_rich_text(_decode_maybe_text(source_blob)) if source_blob is not None else ""
        appmsg_type = _parse_int_loose(_xml_tag_text(source_text, "type"), 0) if source_text else 0
        if source_text and (
            appmsg_type == 19
            or bool(_extract_recorditem_items(_xml_tag_text(source_text, "recorditem")))
            or ("聊天记录" in source_text)
        ):
            return "聊天记录"
        if (
            _extract_refer_content(source_text)
            or appmsg_type in {40, 57}
            or ("<refermsg" in source_text.lower())
            or ("引用：" in _clean_rich_text(content if isinstance(content, str) else ""))
        ):
            return "引用消息"
    return format_msg_type(t)


def _display_msg_type_icon(msg_type, content="", source_blob=None):
    t = _normalize_msg_type(msg_type)
    if t in (10000, 10002):
        source_text = _clean_rich_text(_decode_maybe_text(source_blob)) if source_blob is not None else ""
        revoke_text = _extract_revoke_text(source_text) or _extract_revoke_text(content)
        if revoke_text:
            return "REVOKE"
    if t == 49:
        source_text = _clean_rich_text(_decode_maybe_text(source_blob)) if source_blob is not None else ""
        appmsg_type = _parse_int_loose(_xml_tag_text(source_text, "type"), 0) if source_text else 0
        if source_text and (
            appmsg_type == 19
            or bool(_extract_recorditem_items(_xml_tag_text(source_text, "recorditem")))
            or ("聊天记录" in source_text)
        ):
            return "CHATLOG"
        if (
            _extract_refer_content(source_text)
            or appmsg_type in {40, 57}
            or ("<refermsg" in source_text.lower())
            or ("引用：" in _clean_rich_text(content if isinstance(content, str) else ""))
        ):
            return "QUOTE"
    return msg_type_icon(t)


def _analysis_type_bucket(msg_type):
    t = _normalize_msg_type(msg_type)
    if t == 1:
        return "text"
    if t in (3, 47):
        return "media"
    if t in (43,):
        return "video"
    if t in (34,):
        return "audio"
    if t in (49,):
        return "link"
    if t in (10000, 10002):
        return "system"
    return "other"


def _analysis_sender_for_row(is_group, status, sender_username, username, contact_names):
    sender_username = str(sender_username or "").strip()
    if _is_self_sender_username(sender_username):
        return "__self__", "?"
    if is_group:
        if sender_username:
            return sender_username, contact_names.get(sender_username, sender_username)
        return "__unknown__", "未知成员"

    # Private chat: map by status when sender id is unavailable.
    if isinstance(status, int) and status == 2:
        return "__self__", "?"
    return username, contact_names.get(username, username)


def _should_skip_sender_aggregate(
    sender_id="",
    sender_name="",
    text_count=0,
    media_count=0,
    link_count=0,
    system_count=0,
):
    sid = str(sender_id or "").strip()
    name = _clean_rich_text(str(sender_name or ""))
    text_c = int(text_count or 0)
    media_c = int(media_count or 0)
    link_c = int(link_count or 0)
    system_c = int(system_count or 0)
    user_generated = text_c + media_c

    if not sid:
        return True
    if sid == "__unknown__":
        return user_generated <= 0
    if sid.startswith("rid:"):
        if user_generated <= 0 and (link_c > 0 or system_c > 0):
            return True
        if not name:
            return True
    return False


def _build_chat_analysis(username, start_ts=0, end_ts=0, link_limit=6000, lightweight=False):
    username = str(username or "").strip()
    if not username:
        raise RuntimeError("missing username")
    lightweight = bool(lightweight)

    db_path, table_name = _find_msg_table_for_user(username, ensure_fresh=True)
    if not db_path or not table_name:
        raise RuntimeError("chat table not found")

    # Prefer readable local copy immediately; refresh in background when source changed.
    try:
        refresh_info = ensure_message_db_ready_for_read(
            db_path,
            prefer_stale=True,
            min_async_interval_sec=12,
        )
        if refresh_info.get("mode") == "sync":
            print(
                f"[analysis] sync refreshed {os.path.basename(db_path)} "
                f"{refresh_info.get('pages', 0)}pg/{float(refresh_info.get('ms', 0.0)):.1f}ms",
                flush=True
            )
        elif refresh_info.get("mode") == "stale":
            print(
                f"[analysis] using readable cached copy for {os.path.basename(db_path)}; "
                f"background refresh scheduled={bool(refresh_info.get('scheduled', False))}",
                flush=True
            )
    except Exception as e:
        print(f"[analysis] refresh failed: {e}", flush=True)

    contact_names = load_contact_names()
    is_group = "@chatroom" in username
    where_clauses = []
    where_params = []
    if start_ts:
        where_clauses.append("create_time >= ?")
        where_params.append(int(start_ts))
    if end_ts:
        where_clauses.append("create_time <= ?")
        where_params.append(int(end_ts))
    where_sql = (" WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    recent_samples = []
    try:
        cols = {
            str(r[1]).lower()
            for r in conn.execute(f"PRAGMA table_info([{table_name}])").fetchall()
            if len(r) >= 2
        }
        has_source = "source" in cols
        has_status = "status" in cols
        has_sender = "real_sender_id" in cols
        rowid_sender_map = _load_name2id_rowid_map(conn)

        total = conn.execute(
            f"SELECT COUNT(1) FROM [{table_name}]{where_sql}",
            tuple(where_params)
        ).fetchone()[0]
        minmax = conn.execute(
            f"SELECT MIN(create_time), MAX(create_time) FROM [{table_name}]{where_sql}",
            tuple(where_params)
        ).fetchone()
        first_ts = int(minmax[0] or 0)
        last_ts = int(minmax[1] or 0)

        by_type_rows = conn.execute(
            f"""
            SELECT (local_type & 4294967295) AS msg_type, COUNT(1) AS c
            FROM [{table_name}]
            {where_sql}
            GROUP BY msg_type
            ORDER BY c DESC
            """,
            tuple(where_params)
        ).fetchall()
        by_type = [
            {
                "msg_type": int(t),
                "name": format_msg_type(int(t)),
                "count": int(c),
                "bucket": _analysis_type_bucket(int(t)),
            }
            for t, c in by_type_rows
        ]

        trend_rows = conn.execute(
            f"""
            SELECT
              strftime('%Y-%m-%d', create_time, 'unixepoch', 'localtime') AS d,
              SUM(CASE WHEN (local_type & 4294967295)=1 THEN 1 ELSE 0 END) AS text_c,
              SUM(CASE WHEN (local_type & 4294967295) IN (3,47,43,34) THEN 1 ELSE 0 END) AS media_c,
              SUM(CASE WHEN (local_type & 4294967295)=49 THEN 1 ELSE 0 END) AS link_c,
              SUM(CASE WHEN (local_type & 4294967295) IN (10000,10002) THEN 1 ELSE 0 END) AS system_c,
              COUNT(1) AS total_c
            FROM [{table_name}]
            {where_sql}
            GROUP BY d
            ORDER BY d
            """,
            tuple(where_params)
        ).fetchall()
        trend = [
            {
                "date": str(d),
                "text": int(text_c or 0),
                "media": int(media_c or 0),
                "link": int(link_c or 0),
                "system": int(system_c or 0),
                "total": int(total_c or 0),
            }
            for d, text_c, media_c, link_c, system_c, total_c in trend_rows
            if d
        ]

        heat_rows = conn.execute(
            f"""
            SELECT
              CAST(strftime('%w', create_time, 'unixepoch', 'localtime') AS INTEGER) AS wd,
              CAST(strftime('%H', create_time, 'unixepoch', 'localtime') AS INTEGER) AS hh,
              COUNT(1) AS c
            FROM [{table_name}]
            {where_sql}
            GROUP BY wd, hh
            ORDER BY wd, hh
            """,
            tuple(where_params)
        ).fetchall()
        heatmap = [
            {"weekday": int(wd), "hour": int(hh), "count": int(c)}
            for wd, hh, c in heat_rows
        ]

        top_senders = []
        members = []
        if is_group and has_sender:
            sender_rows = conn.execute(
                f"""
                SELECT
                  real_sender_id,
                  COUNT(1) AS c,
                  MAX(create_time) AS last_ts,
                  SUM(CASE WHEN (local_type & 4294967295)=1 THEN 1 ELSE 0 END) AS text_c,
                  SUM(CASE WHEN (local_type & 4294967295) IN (3,47,43,34) THEN 1 ELSE 0 END) AS media_c,
                  SUM(CASE WHEN (local_type & 4294967295)=49 THEN 1 ELSE 0 END) AS link_c,
                  SUM(CASE WHEN (local_type & 4294967295) IN (10000,10002) THEN 1 ELSE 0 END) AS system_c
                FROM [{table_name}]
                {where_sql}
                GROUP BY real_sender_id
                ORDER BY c DESC
                LIMIT 300
                """,
                tuple(where_params)
            ).fetchall()
            for rid, c, ts, text_c, media_c, link_c, system_c in sender_rows:
                sender_username = rowid_sender_map.get(int(rid), "") if isinstance(rid, int) else ""
                sender_id, sender_name = _analysis_sender_for_row(
                    True, 0, sender_username, username, contact_names
                )
                if _should_skip_sender_aggregate(
                    sender_id=sender_id,
                    sender_name=sender_name,
                    text_count=text_c,
                    media_count=media_c,
                    link_count=link_c,
                    system_count=system_c,
                ):
                    continue
                item = {
                    "sender_id": sender_id,
                    "sender": sender_name,
                    "count": int(c or 0),
                    "last_ts": int(ts or 0),
                }
                if len(top_senders) < 20:
                    top_senders.append(item)
                members.append(item)
        else:
            status_expr = "status" if has_status else "0"
            private_rows = conn.execute(
                f"""
                SELECT
                  CASE WHEN {status_expr}=2 THEN '__self__' ELSE '__peer__' END AS role,
                  COUNT(1) AS c,
                  MAX(create_time) AS last_ts
                FROM [{table_name}]
                {where_sql}
                GROUP BY role
                ORDER BY c DESC
                """,
                tuple(where_params)
            ).fetchall()
            for role, c, ts in private_rows:
                if role == "__self__":
                    sender_name = "?"
                    sender_id = "__self__"
                else:
                    sender_name = contact_names.get(username, username)
                    sender_id = username
                item = {
                    "sender_id": sender_id,
                    "sender": sender_name,
                    "count": int(c or 0),
                    "last_ts": int(ts or 0),
                }
                top_senders.append(item)
                members.append(item)

        source_counter = Counter()
        hot_links_map = {}
        if not lightweight:
            # Collect recent text-like samples as evidence for AI module rendering.
            sample_where = where_sql
            if sample_where:
                sample_where += " AND (local_type & 4294967295) IN (1,49)"
            else:
                sample_where = " WHERE (local_type & 4294967295) IN (1,49)"
            sample_select = [
                "create_time",
                "(local_type & 4294967295) AS msg_type",
                "message_content",
                "real_sender_id" if has_sender else "0 AS real_sender_id",
                "status" if has_status else "0 AS status",
                "source" if has_source else "'' AS source",
            ]
            sample_limit = 700 if int(link_limit or 0) >= 9000 else 420
            sample_sql = (
                f"SELECT {', '.join(sample_select)} FROM [{table_name}] "
                f"{sample_where} ORDER BY create_time DESC LIMIT ?"
            )
            sample_params = list(where_params)
            sample_params.append(int(sample_limit))
            try:
                sample_rows = conn.execute(sample_sql, tuple(sample_params)).fetchall()
            except (sqlite3.DatabaseError, sqlite3.OperationalError) as e:
                if not _is_recoverable_message_query_error(e):
                    raise
                print(f"[analysis] sample fallback due db error: {e}", flush=True)
                _, _, safe_rows = _load_message_rows_safe(
                    db_path,
                    table_name,
                    start_ts=start_ts,
                    end_ts=end_ts,
                    limit=min(max(int(sample_limit) * 4, 2400), 20000),
                    newest_first=True,
                )
                sample_rows = []
                for item in safe_rows:
                    msg_type = _normalize_msg_type((item or {}).get("local_type", 0))
                    if msg_type not in (1, 49):
                        continue
                    sample_rows.append((
                        int((item or {}).get("timestamp", 0) or 0),
                        msg_type,
                        (item or {}).get("content", ""),
                        _safe_int((item or {}).get("real_sender_id", 0), 0, 0, 0),
                        _safe_int((item or {}).get("status", 0), 0, 0, 0),
                        (item or {}).get("source", ""),
                    ))
                    if len(sample_rows) >= int(sample_limit):
                        break
            for row in sample_rows:
                ts = row[0] if len(row) > 0 and isinstance(row[0], int) else 0
                msg_type = _normalize_msg_type(row[1] if len(row) > 1 else 0)
                content = row[2] if len(row) > 2 else ""
                real_sender_id = row[3] if len(row) > 3 and isinstance(row[3], int) else 0
                status = row[4] if len(row) > 4 and isinstance(row[4], int) else 0
                source_blob = row[5] if len(row) > 5 else ""

                text = content if isinstance(content, str) else ""
                if (not text.strip()) and isinstance(content, (bytes, bytearray)):
                    text = _extract_text_from_message_blob(content, msg_type)
                if _is_text_garbled(text):
                    text = ""

                sender_username = rowid_sender_map.get(int(real_sender_id), "") if isinstance(real_sender_id, int) else ""
                if is_group and text:
                    p_sender, p_body = _parse_group_sender_prefix(text)
                    if p_sender:
                        if not sender_username:
                            sender_username = p_sender
                        text = p_body

                rendered = _render_link_or_quote_text(msg_type, text, source_blob)
                rendered = _sanitize_link_text(rendered)
                rendered = _fallback_content_by_type(msg_type, rendered)
                clean = _clean_rich_text(rendered)
                if not clean:
                    continue
                if clean in ("[文本]", "[链接/文件]", "[图片]", "[表情]", "[语音]", "[视频]"):
                    continue
                if _looks_noise_text(clean):
                    continue
                if len(clean) > 280:
                    clean = clean[:280] + "..."

                sender_id, sender_name = _analysis_sender_for_row(
                    is_group, status, sender_username, username, contact_names
                )
                if _should_skip_sender_aggregate(
                    sender_id=sender_id,
                    sender_name=sender_name,
                    text_count=(1 if msg_type == 1 else 0),
                    media_count=(1 if msg_type in (3, 47, 43, 34) else 0),
                    link_count=(1 if msg_type == 49 else 0),
                    system_count=(1 if msg_type in (10000, 10002) else 0),
                ):
                    continue
                recent_samples.append({
                    "ts": int(ts or 0),
                    "time": datetime.fromtimestamp(int(ts or 0)).strftime('%m-%d %H:%M') if ts else "",
                    "sender": sender_name,
                    "sender_id": sender_id,
                    "type": format_msg_type(msg_type),
                    "text": clean,
                })
                if len(recent_samples) >= 260:
                    break

            link_params = list(where_params)
            # Include both appmsg(49) and text(1): many share cards are rendered as plain text.
            link_where = where_sql
            if link_where:
                link_where += " AND (local_type & 4294967295) IN (49,1)"
            else:
                link_where = " WHERE (local_type & 4294967295) IN (49,1)"

            link_select = [
                "local_id",
                "(local_type & 4294967295) AS msg_type",
                "create_time",
                "message_content",
                "real_sender_id" if has_sender else "0 AS real_sender_id",
                "status" if has_status else "0 AS status",
                "content_type" if "content_type" in cols else "NULL AS content_type",
            ]
            if has_source:
                link_select.append("source")
            else:
                link_select.append("'' AS source")

            link_sql = (
                f"SELECT {', '.join(link_select)} FROM [{table_name}] "
                f"{link_where} ORDER BY create_time DESC LIMIT ?"
            )
            link_params.append(int(link_limit))
            try:
                link_rows = conn.execute(link_sql, tuple(link_params)).fetchall()
            except (sqlite3.DatabaseError, sqlite3.OperationalError) as e:
                if not _is_recoverable_message_query_error(e):
                    raise
                print(f"[analysis] link fallback due db error: {e}", flush=True)
                _, _, safe_rows = _load_message_rows_safe(
                    db_path,
                    table_name,
                    start_ts=start_ts,
                    end_ts=end_ts,
                    limit=min(max(int(link_limit or 0) * 4, 4000), 40000),
                    newest_first=True,
                )
                link_rows = []
                for item in safe_rows:
                    msg_type = _normalize_msg_type((item or {}).get("local_type", 0))
                    if msg_type not in (1, 49):
                        continue
                    link_rows.append((
                        _safe_int((item or {}).get("local_id", 0), 0, 0, 0),
                        msg_type,
                        int((item or {}).get("timestamp", 0) or 0),
                        (item or {}).get("content", ""),
                        _safe_int((item or {}).get("real_sender_id", 0), 0, 0, 0),
                        _safe_int((item or {}).get("status", 0), 0, 0, 0),
                        (item or {}).get("ct_flag", None),
                        (item or {}).get("source", ""),
                    ))
                    if len(link_rows) >= int(link_limit):
                        break

            # Prepare FTS fallback candidates for rows with missing/garbled text.
            fts_needed_rows = []
            max_fts_rows = 6000 if int(link_limit or 0) > 6000 else 3000
            for row in link_rows:
                local_id = row[0] if len(row) > 0 and isinstance(row[0], int) else 0
                msg_type = _normalize_msg_type(row[1] if len(row) > 1 else 0)
                ts = row[2] if len(row) > 2 and isinstance(row[2], int) else 0
                content = row[3] if len(row) > 3 else ""
                ct_msg = row[6] if len(row) > 6 and isinstance(row[6], int) else None

                content_text = content if isinstance(content, str) else ""
                if not content_text and isinstance(content, (bytes, bytearray)):
                    content_text = _decode_message_content(content, msg_type, ct_msg)
                content_is_blob = isinstance(content, (bytes, bytearray)) or ct_msg == 4
                text_missing = not str(content_text or "").strip()
                text_garbled = _is_text_garbled(content_text)
                if (
                    (content_is_blob or text_missing or text_garbled)
                    and len(fts_needed_rows) < max_fts_rows
                    and msg_type in (1, 49)
                    and isinstance(local_id, int)
                    and local_id >= 0
                ):
                    fts_needed_rows.append((local_id, ts))

            if fts_needed_rows:
                try:
                    _refresh_aux_db_throttled(DECRYPTED_MESSAGE_FTS, min_interval_sec=12)
                except Exception as e:
                    print(f"[analysis] fts refresh failed: {e}", flush=True)
            fts_fallback_map = _load_fts_fallback_meta(username, fts_needed_rows)

            for row in link_rows:
                local_id = row[0] if len(row) > 0 and isinstance(row[0], int) else 0
                msg_type = _normalize_msg_type(row[1] if len(row) > 1 else 0)
                ts = row[2] if len(row) > 2 and isinstance(row[2], int) else 0
                content = row[3] if len(row) > 3 else ""
                real_sender_id = row[4] if len(row) > 4 and isinstance(row[4], int) else 0
                status = row[5] if len(row) > 5 and isinstance(row[5], int) else 0
                source_blob = row[7] if len(row) > 7 else ""
                msg_type = _normalize_msg_type(msg_type)
                raw_text = content if isinstance(content, str) else ""
                if (not raw_text.strip()) and isinstance(content, (bytes, bytearray)):
                    ct_msg = row[6] if len(row) > 6 and isinstance(row[6], int) else None
                    raw_text = _decode_message_content(content, msg_type, ct_msg)
                if _is_text_garbled(raw_text):
                    raw_text = ""

                fts_cand = _pick_best_fts_candidate(
                    fts_fallback_map.get(local_id, []),
                    ts
                )

                sender_username = rowid_sender_map.get(int(real_sender_id), "") if isinstance(real_sender_id, int) else ""
                if is_group and raw_text:
                    p_sender, p_body = _parse_group_sender_prefix(raw_text)
                    if p_sender:
                        if not sender_username:
                            sender_username = p_sender
                        raw_text = p_body

                if fts_cand and isinstance(fts_cand.get('text', ''), str):
                    fts_text = _clean_rich_text(fts_cand.get('text', ''))
                    if _is_text_garbled(fts_text):
                        fts_text = ""
                    if fts_text:
                        use_fts = False
                        clean_now = _clean_rich_text(raw_text)
                        noisy_now = (
                            (not clean_now)
                            or _looks_noise_text(clean_now)
                            or _has_mojibake_fragment(clean_now)
                            or _is_probably_garbled_line(clean_now)
                        )
                        if not raw_text.strip():
                            use_fts = True
                        elif noisy_now and msg_type in (1, 49):
                            use_fts = True
                        elif len(fts_text) > len(clean_now) + 24 and msg_type in (1, 49):
                            use_fts = True
                        if use_fts:
                            if is_group:
                                p_sender, p_body = _parse_group_sender_prefix(fts_text)
                                if p_sender:
                                    if not sender_username:
                                        sender_username = p_sender
                                    raw_text = p_body
                                else:
                                    raw_text = fts_text
                            else:
                                raw_text = fts_text

                if (not sender_username) and fts_cand:
                    sender_username = str(fts_cand.get('sender_username', '') or '').strip()

                rendered = _render_link_or_quote_text(msg_type, raw_text, source_blob)
                rendered = _sanitize_link_text(rendered)
                rendered = _fallback_content_by_type(msg_type, rendered)
                src, url = _extract_link_meta(msg_type, rendered, source_blob)
                if not src and not url:
                    continue
                src = _normalize_link_source_name(src, url=url) or "外部网站"
                # Quote-heavy chats can drown out actionable sources, so exclude them
                # from source distribution by default.
                if src != "引用消息":
                    source_counter[src] += 1

                sender_id, sender_name = _analysis_sender_for_row(
                    is_group, status, sender_username, username, contact_names
                )
                if _should_skip_sender_aggregate(
                    sender_id=sender_id,
                    sender_name=sender_name,
                    text_count=(1 if msg_type == 1 else 0),
                    media_count=(1 if msg_type in (3, 47, 43, 34) else 0),
                    link_count=(1 if msg_type == 49 else 0),
                    system_count=(1 if msg_type in (10000, 10002) else 0),
                ):
                    continue

                title = rendered.strip().split("\n", 1)[0].strip() if rendered else ""
                if title.startswith("分享了一个链接："):
                    title = title.split("：", 1)[1].strip()
                if not title:
                    title = "链接消息"
                if len(title) > 120:
                    title = title[:120] + "..."

                # Drop non-actionable generic placeholders from hot links.
                if not url and title in ("[链接/文件]", "链接消息", "[文件]", "[图片]", "[语音]", "[视频]", "[表情]"):
                    continue
                if src == "其他" and not url and len(title) <= 10:
                    continue

                # Quote messages do not enter "hot links".
                if src == "引用消息" and not url:
                    continue

                key = (url or title).strip()
                if not key:
                    continue
                if key not in hot_links_map:
                    hot_links_map[key] = {
                        "title": title,
                        "source": _normalize_link_source_name(src, url=url) or "外部网站",
                        "url": url or "",
                        "count": 0,
                        "last_ts": int(ts or 0),
                        "sender": sender_name,
                        "sender_id": sender_id,
                    }
                rec = hot_links_map[key]
                rec["count"] += 1
                if int(ts or 0) >= int(rec.get("last_ts", 0)):
                    rec["last_ts"] = int(ts or 0)
                    rec["sender"] = sender_name
                    rec["sender_id"] = sender_id
                    rec["source"] = _normalize_link_source_name(src, url=url) or "外部网站"
                    if url:
                        rec["url"] = url

    finally:
        conn.close()

    media_counts = {
        "text": 0,
        "media": 0,
        "link": 0,
        "system": 0,
        "other": 0,
    }
    for item in by_type:
        b = item.get("bucket", "other")
        c = int(item.get("count", 0))
        if b == "text":
            media_counts["text"] += c
        elif b in ("media", "video", "audio"):
            media_counts["media"] += c
        elif b == "link":
            media_counts["link"] += c
        elif b == "system":
            media_counts["system"] += c
        else:
            media_counts["other"] += c

    link_sources = [
        {"source": k, "count": int(v)}
        for k, v in source_counter.most_common(12)
    ]
    hot_links = sorted(
        hot_links_map.values(),
        key=lambda x: (int(x.get("count", 0)), int(x.get("last_ts", 0))),
        reverse=True
    )[:30]

    members_sorted = sorted(
        members,
        key=lambda x: (int(x.get("count", 0)), int(x.get("last_ts", 0))),
        reverse=True
    )
    top_senders_sorted = members_sorted[:20] if is_group else top_senders

    return {
        "username": username,
        "chat": _display_name_for_username(username, contact_names),
        "is_group": bool(is_group),
        "range": {"start_ts": int(start_ts or 0), "end_ts": int(end_ts or 0)},
        "summary": {
            "total_messages": int(total or 0),
            "active_senders": int(len([m for m in members_sorted if int(m.get("count", 0)) > 0])),
            "first_ts": first_ts,
            "last_ts": last_ts,
            "link_messages": int(media_counts["link"]),
            "media_messages": int(media_counts["media"]),
            "text_messages": int(media_counts["text"]),
            "system_messages": int(media_counts["system"]),
            "other_messages": int(media_counts["other"]),
        },
        "trend": trend,
        "by_type": by_type,
        "top_senders": top_senders_sorted,
        "members": members_sorted[:200],
        "heatmap": heatmap,
        "link_sources": link_sources,
        "hot_links": hot_links,
        "recent_samples": recent_samples,
    }


def _day_str_from_ts(ts):
    n = int(ts or 0)
    if n <= 0:
        return ""
    return datetime.fromtimestamp(n).strftime("%Y-%m-%d")


def _week_start_str(day_str):
    try:
        d = datetime.strptime(day_str, "%Y-%m-%d")
        s = d - timedelta(days=d.weekday())
        return s.strftime("%Y-%m-%d")
    except Exception:
        return ""


def _parse_day_date(day_str):
    try:
        return datetime.strptime(str(day_str or "").strip(), "%Y-%m-%d").date()
    except Exception:
        return None


def _month_start_str(day_str):
    d = _parse_day_date(day_str)
    if not d:
        return ""
    return d.replace(day=1).strftime("%Y-%m-%d")


def _build_activity_trend_views(trend_rows, sender_rows, start_ts=0, end_ts=0):
    trend_rows = trend_rows if isinstance(trend_rows, list) else []
    sender_rows = sender_rows if isinstance(sender_rows, list) else []

    day_messages = {}
    day_members = {}
    week_members = {}
    month_members = {}
    all_days = []

    for row in trend_rows:
        day_key = str((row or {}).get("date", "") or "").strip()
        day_obj = _parse_day_date(day_key)
        if not day_obj:
            continue
        all_days.append(day_obj)
        day_messages[day_key] = int(day_messages.get(day_key, 0)) + int((row or {}).get("total", 0) or 0)

    for sender in sender_rows:
        sender_id = str((sender or {}).get("sender_id", "") or "").strip()
        if not sender_id:
            continue
        daily_map = (sender or {}).get("daily", {}) if isinstance((sender or {}).get("daily", {}), dict) else {}
        for day_key, count in daily_map.items():
            if int(count or 0) <= 0:
                continue
            day_key = str(day_key or "").strip()
            day_obj = _parse_day_date(day_key)
            if not day_obj:
                continue
            all_days.append(day_obj)
            day_members.setdefault(day_key, set()).add(sender_id)
            week_members.setdefault(_week_start_str(day_key), set()).add(sender_id)
            month_members.setdefault(_month_start_str(day_key), set()).add(sender_id)

    if start_ts:
        start_day = datetime.fromtimestamp(int(start_ts)).date()
    else:
        start_day = min(all_days) if all_days else None
    if end_ts:
        end_day = datetime.fromtimestamp(int(end_ts)).date()
    else:
        end_day = max(all_days) if all_days else None
    if start_day and end_day and start_day > end_day:
        start_day, end_day = end_day, start_day

    if not start_day or not end_day:
        return {"day": [], "week": [], "month": []}

    daily = []
    cur_day = start_day
    while cur_day <= end_day:
        day_key = cur_day.strftime("%Y-%m-%d")
        daily.append({
            "label": day_key,
            "date": day_key,
            "messages": int(day_messages.get(day_key, 0)),
            "active_members": int(len(day_members.get(day_key, set()))),
        })
        cur_day += timedelta(days=1)

    week_messages = {}
    for day_key, total in day_messages.items():
        week_key = _week_start_str(day_key)
        if not week_key:
            continue
        week_messages[week_key] = int(week_messages.get(week_key, 0)) + int(total or 0)

    weekly = []
    cur_week = start_day - timedelta(days=start_day.weekday())
    end_week = end_day - timedelta(days=end_day.weekday())
    while cur_week <= end_week:
        week_key = cur_week.strftime("%Y-%m-%d")
        weekly.append({
            "label": cur_week.strftime("%m-%d"),
            "week_start": week_key,
            "messages": int(week_messages.get(week_key, 0)),
            "active_members": int(len(week_members.get(week_key, set()))),
        })
        cur_week += timedelta(days=7)

    month_messages = {}
    for day_key, total in day_messages.items():
        month_key = _month_start_str(day_key)
        if not month_key:
            continue
        month_messages[month_key] = int(month_messages.get(month_key, 0)) + int(total or 0)

    monthly = []
    cur_year, cur_month = start_day.year, start_day.month
    end_year, end_month = end_day.year, end_day.month
    while (cur_year, cur_month) <= (end_year, end_month):
        month_key = f"{cur_year:04d}-{cur_month:02d}-01"
        monthly.append({
            "label": f"{cur_year:04d}-{cur_month:02d}",
            "month_start": month_key,
            "messages": int(month_messages.get(month_key, 0)),
            "active_members": int(len(month_members.get(month_key, set()))),
        })
        if cur_month == 12:
            cur_year += 1
            cur_month = 1
        else:
            cur_month += 1

    return {
        "day": daily,
        "week": weekly,
        "month": monthly,
    }


def _calc_longest_streak(day_keys):
    days = []
    for d in day_keys or []:
        try:
            days.append(datetime.strptime(str(d), "%Y-%m-%d").date())
        except Exception:
            pass
    if not days:
        return 0
    days = sorted(set(days))
    best = 1
    cur = 1
    prev = days[0]
    for d in days[1:]:
        diff = (d - prev).days
        if diff == 1:
            cur += 1
        elif diff == 0:
            pass
        else:
            cur = 1
        if cur > best:
            best = cur
        prev = d
    return int(best)


def _percentile_value(nums, p):
    vals = sorted(float(x) for x in nums if float(x) >= 0)
    if not vals:
        return 0.0
    p = max(0.0, min(1.0, float(p)))
    if len(vals) == 1:
        return float(vals[0])
    pos = p * (len(vals) - 1)
    lo = int(pos)
    hi = min(len(vals) - 1, lo + 1)
    frac = pos - lo
    return float(vals[lo] * (1.0 - frac) + vals[hi] * frac)


def _activity_level_logic(sender_rows, range_days=30):
    rows = []
    range_days = max(1, int(range_days or 1))
    for s in sender_rows or []:
        count = int(s.get("count", 0) or 0)
        if count <= 0:
            continue
        active_days = int(s.get("active_days", 0) or 0)
        link_c = int(s.get("link_count", 0) or 0)
        media_c = int(s.get("media_count", 0) or 0)
        msg_per_day = float(count) / float(range_days)
        active_ratio = float(active_days) / float(range_days)
        link_per_day = float(link_c) / float(range_days)
        media_per_day = float(media_c) / float(range_days)
        # Normalize by selected range to avoid "longer range -> more KOL".
        score = round(
            msg_per_day * 21.0
            + active_ratio * 46.0
            + link_per_day * 9.0
            + media_per_day * 7.0,
            4,
        )
        rows.append({
            "sender_id": str(s.get("sender_id", "") or ""),
            "count": count,
            "active_days": active_days,
            "score": score,
        })

    total = len(rows)
    if total <= 0:
        return {
            "level_by_sender": {},
            "score_by_sender": {},
            "thresholds": {"kol_score": 0, "core_score": 0, "normal_score": 0},
            "counts": {"total": 0, "active": 0, "normal_plus": 0, "core_plus": 0, "kol": 0},
            "desc": "暂无可用成员数据",
        }

    rows.sort(key=lambda x: (float(x.get("score", 0)), int(x.get("count", 0))), reverse=True)
    scores = [float(r.get("score", 0)) for r in rows]
    active_days_all = [int(r.get("active_days", 0) or 0) for r in rows]
    counts_all = [int(r.get("count", 0) or 0) for r in rows]
    kol_score = _percentile_value(scores, 0.92)
    core_score = _percentile_value(scores, 0.75)
    normal_score = _percentile_value(scores, 0.38)

    # Hard caps: small groups cannot have too many KOL.
    if total <= 12:
        kol_cap = 1
    elif total <= 24:
        kol_cap = 2
    else:
        kol_cap = max(2, min(8, int(round(total * 0.12))))
    core_cap = max(kol_cap + 1, min(total, max(3, int(round(total * 0.36)))))
    normal_cap = max(core_cap + 1, min(total, max(4, int(round(total * 0.74)))))

    min_count_kol = max(6, int(_percentile_value(counts_all, 0.75)))
    min_days_kol = max(4, int(_percentile_value(active_days_all, 0.55)))
    min_count_core = max(3, int(_percentile_value(counts_all, 0.45)))
    min_days_core = max(2, int(_percentile_value(active_days_all, 0.35)))
    min_count_normal = max(1, int(_percentile_value(counts_all, 0.2)))

    level_by_sender = {}
    score_by_sender = {}
    kol_n = 0
    core_n = 0
    normal_n = 0
    rank = 0
    for r in rows:
        rank += 1
        sid = str(r.get("sender_id", "") or "")
        cnt = int(r.get("count", 0))
        adays = int(r.get("active_days", 0) or 0)
        sc = float(r.get("score", 0))
        score_by_sender[sid] = int(round(sc))

        if (
            kol_n < kol_cap
            and sc >= kol_score
            and cnt >= min_count_kol
            and adays >= min_days_kol
        ):
            level = ("KOL", "kol")
            kol_n += 1
        elif (
            core_n < core_cap
            and sc >= core_score
            and cnt >= min_count_core
            and adays >= min_days_core
        ):
            level = ("核心活跃", "core")
            core_n += 1
        elif (
            normal_n < normal_cap
            and (sc >= normal_score or cnt >= min_count_normal or adays >= min_days_core)
        ):
            level = ("普通活跃", "normal")
            normal_n += 1
        else:
            level = ("低参与", "low")
        level_by_sender[sid] = level

    # Optional backfill: if a medium/large group has no KOL at all, promote top 1.
    if kol_n <= 0 and total >= 8 and rows:
        sid_top = str(rows[0].get("sender_id", "") or "")
        if sid_top:
            prev = level_by_sender.get(sid_top, ("低参与", "low"))[1]
            level_by_sender[sid_top] = ("KOL", "kol")
            kol_n = 1
            if prev == "core":
                core_n = max(0, core_n - 1)
            elif prev == "normal":
                normal_n = max(0, normal_n - 1)

    low_n = sum(1 for lv in level_by_sender.values() if lv[1] == "low")
    active_n = kol_n + core_n + normal_n + low_n

    desc = (
        f"分层规则：按日均发言、活跃天数和内容贡献综合评分。"
        f"KOL 上限 {kol_cap} 人，小群默认 1-2 人，避免全员 KOL。"
    )
    return {
        "level_by_sender": level_by_sender,
        "score_by_sender": score_by_sender,
        "thresholds": {
            "kol_score": round(kol_score, 2),
            "core_score": round(core_score, 2),
            "normal_score": round(normal_score, 2),
            "min_count_kol": int(min_count_kol),
            "min_days_kol": int(min_days_kol),
            "min_count_core": int(min_count_core),
            "min_days_core": int(min_days_core),
            "min_count_normal": int(min_count_normal),
            "kol_cap": int(kol_cap),
            "core_cap": int(core_cap),
            "normal_cap": int(normal_cap),
        },
        "counts": {
            "total": int(total),
            "active": int(active_n),
            "low": int(low_n),
            "normal": int(normal_n),
            "core": int(core_n),
            "normal_plus": int(kol_n + core_n + normal_n),
            "core_plus": int(kol_n + core_n),
            "kol": int(kol_n),
        },
        "desc": desc,
    }


def _build_interaction_network(username, sender_rows, start_ts=0, end_ts=0, max_rows=26000, max_nodes=34):
    username = str(username or "").strip()
    if not username or "@chatroom" not in username:
        return {"nodes": [], "edges": [], "summary": {"node_count": 0, "edge_count": 0}}

    db_path, table_name = _find_msg_table_for_user(username, ensure_fresh=True)
    if not db_path or not table_name:
        return {"nodes": [], "edges": [], "summary": {"node_count": 0, "edge_count": 0}}
    try:
        refresh_decrypted_message_db(db_path)
    except Exception as e:
        print(f"[analysis] interaction refresh failed: {e}", flush=True)

    contact_names = load_contact_names()
    where_clauses = []
    where_params = []
    if start_ts:
        where_clauses.append("create_time >= ?")
        where_params.append(int(start_ts))
    if end_ts:
        where_clauses.append("create_time <= ?")
        where_params.append(int(end_ts))
    where_sql = (" WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

    rows = []
    rowid_sender_map = {}
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        try:
            cols = {
                str(r[1]).lower()
                for r in conn.execute(f"PRAGMA table_info([{table_name}])").fetchall()
                if len(r) >= 2
            }
            if "real_sender_id" not in cols:
                return {"nodes": [], "edges": [], "summary": {"node_count": 0, "edge_count": 0}}
            has_status = "status" in cols
            status_expr = "status" if has_status else "0"
            rowid_sender_map = _load_name2id_rowid_map(conn)
            rows = conn.execute(
                f"""
                SELECT
                  create_time,
                  real_sender_id,
                  {status_expr} AS status,
                  (local_type & 4294967295) AS msg_type,
                  message_content
                FROM [{table_name}]
                {where_sql}
                ORDER BY create_time ASC
                LIMIT ?
                """,
                tuple(where_params + [int(max_rows)]),
            ).fetchall()
        finally:
            conn.close()
    except sqlite3.DatabaseError as e:
        if not _is_recoverable_message_query_error(e):
            raise
        print(f"[analysis] interaction fallback due db error: {e}", flush=True)
        cols, rowid_sender_map, safe_rows = _load_message_rows_safe(
            db_path,
            table_name,
            start_ts=start_ts,
            end_ts=end_ts,
            limit=int(max_rows),
            newest_first=False,
        )
        if "real_sender_id" not in cols:
            return {"nodes": [], "edges": [], "summary": {"node_count": 0, "edge_count": 0}}
        rows = [
            (
                int((row or {}).get("timestamp", 0) or 0),
                _safe_int((row or {}).get("real_sender_id", 0), 0, 0, 0),
                _safe_int((row or {}).get("status", 0), 0, 0, 0),
                _normalize_msg_type((row or {}).get("local_type", 0)),
                (row or {}).get("content", ""),
            )
            for row in safe_rows
        ]

    if not rows:
        return {"nodes": [], "edges": [], "summary": {"node_count": 0, "edge_count": 0}}

    def _norm_name(v):
        s = str(v or "").strip().lower()
        if not s:
            return ""
        return re.sub(r"[\W_]+", "", s, flags=re.UNICODE)

    hot_sender_ids = set()
    for s in (sender_rows or [])[:100]:
        sid = str(s.get("sender_id", "") or "").strip()
        if sid:
            hot_sender_ids.add(sid)

    sender_name_by_id = {}
    for s in sender_rows or []:
        sid = str(s.get("sender_id", "") or "").strip()
        nm = str(s.get("sender", sid) or sid).strip()
        if sid and nm:
            sender_name_by_id[sid] = nm

    lookup = {}
    for sid, nm in sender_name_by_id.items():
        key = _norm_name(nm)
        if key and len(key) >= 2:
            lookup[key] = sid

    node_msg = defaultdict(int)
    node_last = defaultdict(int)
    pair_w = defaultdict(float)
    prev_sender = ""
    prev_ts = 0
    for ts, rid, status, msg_type, content in rows:
        ts = int(ts or 0)
        sender_username = rowid_sender_map.get(int(rid), "") if isinstance(rid, int) else ""
        if sender_username:
            sid = sender_username
            sname = contact_names.get(sender_username, sender_username)
            if sid == username or sid.endswith("@chatroom"):
                prev_sender = ""
                prev_ts = ts
                continue
        else:
            if int(status or 0) == 2:
                sid = "__self__"
                sname = "?"
            else:
                sid = "__peer__"
                sname = "瀵规柟"
        if hot_sender_ids and sid not in hot_sender_ids:
            prev_sender = sid
            prev_ts = ts
            continue
        sender_name_by_id[sid] = sname
        node_msg[sid] += 1
        node_last[sid] = max(node_last[sid], ts)

        text = content if isinstance(content, str) else ""
        if (not text.strip()) and isinstance(content, (bytes, bytearray)):
            text = _extract_text_from_message_blob(content, int(msg_type or 0))
        text = _clean_rich_text(text)

        if text:
            for m in re.findall(r"@([^\s@,:锛屻€傦紱;锛?锛?]{1,24})", text):
                mk = _norm_name(m)
                if not mk or len(mk) < 2:
                    continue
                target_sid = lookup.get(mk, "")
                if (not target_sid) and len(mk) >= 2:
                    for lk, lsid in lookup.items():
                        if mk in lk or lk in mk:
                            target_sid = lsid
                            break
                if target_sid and target_sid != sid:
                    k = tuple(sorted((sid, target_sid)))
                    pair_w[k] += 2.0

        if prev_sender and prev_sender != sid and ts > 0 and prev_ts > 0 and (ts - prev_ts) <= 300:
            k = tuple(sorted((sid, prev_sender)))
            pair_w[k] += 1.0
        prev_sender = sid
        prev_ts = ts

    if not node_msg:
        return {"nodes": [], "edges": [], "summary": {"node_count": 0, "edge_count": 0}}

    degree = defaultdict(float)
    for (a, b), w in pair_w.items():
        degree[a] += float(w)
        degree[b] += float(w)

    node_rank = sorted(
        node_msg.keys(),
        key=lambda sid: (float(node_msg.get(sid, 0)) + float(degree.get(sid, 0)) * 1.35, float(degree.get(sid, 0))),
        reverse=True,
    )
    keep = set(node_rank[:max_nodes])

    nodes = []
    for sid in node_rank[:max_nodes]:
        msg_c = int(node_msg.get(sid, 0))
        dgr = float(degree.get(sid, 0))
        nodes.append({
            "id": sid,
            "name": sender_name_by_id.get(sid, sid),
            "messages": msg_c,
            "degree": round(dgr, 2),
            "value": round(msg_c * 0.55 + dgr * 1.8, 2),
            "last_ts": int(node_last.get(sid, 0)),
        })

    edges = []
    for (a, b), w in sorted(pair_w.items(), key=lambda kv: kv[1], reverse=True):
        if a not in keep or b not in keep:
            continue
        if w <= 0:
            continue
        edges.append({
            "source": a,
            "target": b,
            "weight": round(float(w), 2),
        })
        if len(edges) >= max(56, int(max_nodes * 1.8)):
            break

    return {
        "nodes": nodes,
        "edges": edges,
        "summary": {
            "node_count": int(len(nodes)),
            "edge_count": int(len(edges)),
        },
    }


def _collect_sender_first_seen_all(username):
    username = str(username or "").strip()
    if not username:
        return {}
    cached = _sender_first_seen_cache_get(username)
    if isinstance(cached, dict):
        return cached

    db_path, table_name = _find_msg_table_for_user(username, ensure_fresh=True)
    if not db_path or not table_name:
        return {}
    try:
        refresh_decrypted_message_db(db_path)
    except Exception:
        pass

    contact_names = load_contact_names()
    is_group = "@chatroom" in username
    out = {}

    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        try:
            cols = {
                str(r[1]).lower()
                for r in conn.execute(f"PRAGMA table_info([{table_name}])").fetchall()
                if len(r) >= 2
            }
            has_sender = "real_sender_id" in cols
            has_status = "status" in cols
            status_expr = "status" if has_status else "0"
            rowid_sender_map = _load_name2id_rowid_map(conn) if (is_group and has_sender) else {}

            if is_group and has_sender:
                rows = conn.execute(
                    f"""
                    SELECT CAST(real_sender_id AS INTEGER) AS rid,
                           MIN(create_time) AS first_ts,
                           MAX(create_time) AS last_ts
                    FROM [{table_name}]
                    GROUP BY rid
                    """
                ).fetchall()
                for rid, first_ts, last_ts in rows:
                    sid = rowid_sender_map.get(int(rid or 0), "")
                    if not sid:
                        continue
                    if sid == username or sid.endswith("@chatroom"):
                        continue
                    out[sid] = {
                        "sender": contact_names.get(sid, sid),
                        "first_ts_all": int(first_ts or 0),
                        "last_ts_all": int(last_ts or 0),
                    }
            else:
                rows = conn.execute(
                    f"""
                    SELECT CASE WHEN {status_expr}=2 THEN '__self__' ELSE '__peer__' END AS sid,
                           MIN(create_time) AS first_ts,
                           MAX(create_time) AS last_ts
                    FROM [{table_name}]
                    GROUP BY sid
                    """
                ).fetchall()
                for sid, first_ts, last_ts in rows:
                    sid = str(sid or "").strip()
                    if not sid:
                        continue
                    show = "?" if sid == "__self__" else contact_names.get(username, username)
                    out[sid] = {
                        "sender": show,
                        "first_ts_all": int(first_ts or 0),
                        "last_ts_all": int(last_ts or 0),
                    }
        finally:
            conn.close()
    except sqlite3.DatabaseError as e:
        if not _is_recoverable_message_query_error(e):
            raise
        print(f"[analysis] first-seen fallback due db error: {e}", flush=True)
        _, _, safe_rows = _load_message_rows_safe(db_path, table_name, 0, 0, 0, False)
        for row in safe_rows:
            sender_username = str((row or {}).get("sender_username", "") or "").strip()
            status = _safe_int((row or {}).get("status", 0), 0, 0, 0)
            ts = int((row or {}).get("timestamp", 0) or 0)
            if is_group:
                sid = sender_username
                if not sid or sid == username or sid.endswith("@chatroom"):
                    continue
                show = contact_names.get(sid, sid)
            else:
                sid = "__self__" if status == 2 else "__peer__"
                show = "?" if sid == "__self__" else contact_names.get(username, username)
            obj = out.get(sid)
            if not obj:
                out[sid] = {
                    "sender": show,
                    "first_ts_all": ts,
                    "last_ts_all": ts,
                }
                continue
            if ts and (obj.get("first_ts_all", 0) <= 0 or ts < int(obj.get("first_ts_all", 0) or 0)):
                obj["first_ts_all"] = ts
            if ts and ts > int(obj.get("last_ts_all", 0) or 0):
                obj["last_ts_all"] = ts

    _sender_first_seen_cache_set(username, out)
    return out


def _collect_sender_activity(username, start_ts=0, end_ts=0):
    username = str(username or "").strip()
    if not username:
        return []

    db_path, table_name = _find_msg_table_for_user(username, ensure_fresh=True)
    if not db_path or not table_name:
        return []
    try:
        refresh_decrypted_message_db(db_path)
    except Exception as e:
        print(f"[analysis] sender refresh failed: {e}", flush=True)

    contact_names = load_contact_names()
    is_group = "@chatroom" in username
    where_clauses = []
    where_params = []
    if start_ts:
        where_clauses.append("create_time >= ?")
        where_params.append(int(start_ts))
    if end_ts:
        where_clauses.append("create_time <= ?")
        where_params.append(int(end_ts))
    where_sql = (" WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

    daily_rows = []
    type_rows = []
    rowid_sender_map = {}
    safe_rows = None
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        try:
            cols = {
                str(r[1]).lower()
                for r in conn.execute(f"PRAGMA table_info([{table_name}])").fetchall()
                if len(r) >= 2
            }
            has_sender = "real_sender_id" in cols
            has_status = "status" in cols
            status_expr = "status" if has_status else "0"
            sender_expr = "CAST(real_sender_id AS TEXT)" if (is_group and has_sender) else f"CASE WHEN {status_expr}=2 THEN '__self__' ELSE '__peer__' END"
            rowid_sender_map = _load_name2id_rowid_map(conn) if (is_group and has_sender) else {}

            daily_rows = conn.execute(
                f"""
                SELECT
                  {sender_expr} AS sid,
                  strftime('%Y-%m-%d', create_time, 'unixepoch', 'localtime') AS d,
                  COUNT(1) AS c,
                  MIN(create_time) AS first_ts,
                  MAX(create_time) AS last_ts
                FROM [{table_name}]
                {where_sql}
                GROUP BY sid, d
                """,
                tuple(where_params)
            ).fetchall()

            type_rows = conn.execute(
                f"""
                SELECT
                  {sender_expr} AS sid,
                  SUM(CASE WHEN (local_type & 4294967295)=1 THEN 1 ELSE 0 END) AS text_c,
                  SUM(CASE WHEN (local_type & 4294967295) IN (3,47,43,34) THEN 1 ELSE 0 END) AS media_c,
                  SUM(CASE WHEN (local_type & 4294967295)=49 THEN 1 ELSE 0 END) AS link_c,
                  SUM(CASE WHEN (local_type & 4294967295) IN (10000,10002) THEN 1 ELSE 0 END) AS system_c
                FROM [{table_name}]
                {where_sql}
                GROUP BY sid
                """,
                tuple(where_params)
            ).fetchall()
        finally:
            conn.close()
    except sqlite3.DatabaseError as e:
        if not _is_recoverable_message_query_error(e):
            raise
        print(f"[analysis] sender fallback due db error: {e}", flush=True)
        _, rowid_sender_map, safe_rows = _load_message_rows_safe(
            db_path,
            table_name,
            start_ts=start_ts,
            end_ts=end_ts,
            limit=0,
            newest_first=False,
        )

    def resolve_sender(sid_raw):
        sid_raw = str(sid_raw or "").strip()
        if is_group and has_sender:
            rid = _safe_int(sid_raw, 0, 0, None)
            sender_username = rowid_sender_map.get(rid, "")
            if sender_username and (sender_username == username or sender_username.endswith("@chatroom")):
                return "", ""
            if sender_username:
                return sender_username, contact_names.get(sender_username, sender_username)
            if sid_raw and sid_raw != "0":
                return f"rid:{sid_raw}", f"成员#{sid_raw}"
            return "__unknown__", "未知成员"
        if sid_raw == "__self__":
            return "__self__", "?"
        return username, contact_names.get(username, username)

    if safe_rows is not None:
        daily_agg = {}
        type_agg = {}
        has_sender = is_group
        for row in safe_rows:
            rid = _safe_int((row or {}).get("real_sender_id", 0), 0, 0, 0)
            status = _safe_int((row or {}).get("status", 0), 0, 0, 0)
            msg_type = _normalize_msg_type((row or {}).get("local_type", 0))
            ts = int((row or {}).get("timestamp", 0) or 0)
            day = ""
            if ts > 0:
                try:
                    day = datetime.fromtimestamp(ts).strftime("%Y-%m-%d")
                except Exception:
                    day = ""
            sid_raw = str(rid) if is_group else ("__self__" if status == 2 else "__peer__")
            if day:
                item = daily_agg.get((sid_raw, day))
                if not item:
                    daily_agg[(sid_raw, day)] = {
                        "count": 1,
                        "first_ts": ts,
                        "last_ts": ts,
                    }
                else:
                    item["count"] += 1
                    if ts and (item["first_ts"] <= 0 or ts < item["first_ts"]):
                        item["first_ts"] = ts
                    if ts and ts > item["last_ts"]:
                        item["last_ts"] = ts
            bucket = type_agg.setdefault(sid_raw, {"text": 0, "media": 0, "link": 0, "system": 0})
            if msg_type == 1:
                bucket["text"] += 1
            elif msg_type in (3, 47, 43, 34):
                bucket["media"] += 1
            elif msg_type == 49:
                bucket["link"] += 1
            elif msg_type in (10000, 10002):
                bucket["system"] += 1
        daily_rows = [
            (sid_raw, day, item["count"], item["first_ts"], item["last_ts"])
            for (sid_raw, day), item in daily_agg.items()
        ]
        type_rows = [
            (sid_raw, item["text"], item["media"], item["link"], item["system"])
            for sid_raw, item in type_agg.items()
        ]

    by_sender = {}
    for sid_raw, day, c, first_ts, last_ts in daily_rows:
        sid, sender_name = resolve_sender(sid_raw)
        if not sid:
            continue
        obj = by_sender.get(sid)
        if not obj:
            obj = {
                "sender_id": sid,
                "sender": sender_name,
                "count": 0,
                "daily": {},
                "first_ts": 0,
                "last_ts": 0,
                "text_count": 0,
                "media_count": 0,
                "link_count": 0,
                "system_count": 0,
                "other_count": 0,
            }
            by_sender[sid] = obj
        day_key = str(day or "").strip()
        if day_key:
            obj["daily"][day_key] = int(obj["daily"].get(day_key, 0)) + int(c or 0)
        obj["count"] += int(c or 0)
        ft = int(first_ts or 0)
        lt = int(last_ts or 0)
        if ft and (obj["first_ts"] == 0 or ft < obj["first_ts"]):
            obj["first_ts"] = ft
        if lt and lt > obj["last_ts"]:
            obj["last_ts"] = lt

    for sid_raw, text_c, media_c, link_c, system_c in type_rows:
        sid, _ = resolve_sender(sid_raw)
        if not sid:
            continue
        obj = by_sender.get(sid)
        if not obj:
            obj = {
                "sender_id": sid,
                "sender": sid,
                "count": 0,
                "daily": {},
                "first_ts": 0,
                "last_ts": 0,
                "text_count": 0,
                "media_count": 0,
                "link_count": 0,
                "system_count": 0,
                "other_count": 0,
            }
            by_sender[sid] = obj
        obj["text_count"] = int(text_c or 0)
        obj["media_count"] = int(media_c or 0)
        obj["link_count"] = int(link_c or 0)
        obj["system_count"] = int(system_c or 0)

    first_seen_all = _collect_sender_first_seen_all(username)
    for sid, obj in by_sender.items():
        full = first_seen_all.get(sid) if isinstance(first_seen_all, dict) else None
        if isinstance(full, dict):
            obj["first_ts_all"] = int(full.get("first_ts_all", 0) or 0)
            obj["last_ts_all"] = int(full.get("last_ts_all", 0) or 0)
            if not obj.get("sender"):
                obj["sender"] = str(full.get("sender", sid) or sid)
        else:
            obj["first_ts_all"] = int(obj.get("first_ts", 0) or 0)
            obj["last_ts_all"] = int(obj.get("last_ts", 0) or 0)

    rows = []
    for obj in by_sender.values():
        obj["active_days"] = int(len(obj["daily"]))
        obj["daily"] = dict(sorted(obj["daily"].items(), key=lambda kv: kv[0]))
        known = (
            int(obj.get("text_count", 0))
            + int(obj.get("media_count", 0))
            + int(obj.get("link_count", 0))
            + int(obj.get("system_count", 0))
        )
        obj["other_count"] = max(0, int(obj.get("count", 0)) - known)
        if _should_skip_sender_aggregate(
            sender_id=obj.get("sender_id", ""),
            sender_name=obj.get("sender", ""),
            text_count=obj.get("text_count", 0),
            media_count=obj.get("media_count", 0),
            link_count=obj.get("link_count", 0),
            system_count=obj.get("system_count", 0),
        ):
            continue
        rows.append(obj)
    rows.sort(key=lambda x: (int(x.get("count", 0)), int(x.get("last_ts", 0))), reverse=True)
    return rows


def _collect_keyword_stats(username, start_ts=0, end_ts=0, limit=10000):
    username = str(username or "").strip()
    if not username:
        return []
    db_path, table_name = _find_msg_table_for_user(username, ensure_fresh=True)
    if not db_path or not table_name:
        return []
    try:
        refresh_decrypted_message_db(db_path)
    except Exception as e:
        print(f"[analysis] keyword refresh failed: {e}", flush=True)

    where_clauses = ["(local_type & 4294967295) IN (1,49)"]
    where_params = []
    if start_ts:
        where_clauses.append("create_time >= ?")
        where_params.append(int(start_ts))
    if end_ts:
        where_clauses.append("create_time <= ?")
        where_params.append(int(end_ts))
    where_sql = " WHERE " + " AND ".join(where_clauses)

    rows = []
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        try:
            cols = {
                str(r[1]).lower()
                for r in conn.execute(f"PRAGMA table_info([{table_name}])").fetchall()
                if len(r) >= 2
            }
            has_source = "source" in cols
            rows = conn.execute(
                f"""
                SELECT
                  (local_type & 4294967295) AS msg_type,
                  message_content,
                  {"source" if has_source else "'' AS source"}
                FROM [{table_name}]
                {where_sql}
                ORDER BY create_time DESC
                LIMIT ?
                """,
                tuple(where_params + [int(limit)])
            ).fetchall()
        finally:
            conn.close()
    except (sqlite3.DatabaseError, sqlite3.OperationalError) as e:
        if not _is_recoverable_message_query_error(e):
            raise
        print(f"[analysis] keyword fallback due db error: {e}", flush=True)
        _, _, safe_rows = _load_message_rows_safe(
            db_path,
            table_name,
            start_ts=start_ts,
            end_ts=end_ts,
            limit=min(max(int(limit or 0) * 4, 4000), 40000),
            newest_first=True,
        )
        for item in safe_rows:
            msg_type = _normalize_msg_type((item or {}).get("local_type", 0))
            if msg_type not in (1, 49):
                continue
            rows.append((
                msg_type,
                (item or {}).get("content", ""),
                (item or {}).get("source", ""),
            ))
            if len(rows) >= int(limit):
                break

    account_blacklist = set()
    try:
        cn = load_contact_names()
        for uid in (cn or {}).keys():
            low = str(uid or "").strip().lower()
            if re.match(r"^[a-z][a-z0-9_\-]{3,40}$", low):
                account_blacklist.add(low)
    except Exception:
        account_blacklist = set()

    mention_names = _build_keyword_mention_names()
    chat_member_name_blacklist = set()
    try:
        sender_rows = _collect_sender_activity(username, start_ts=start_ts, end_ts=end_ts)
        for row in (sender_rows or []):
            sender_name = re.sub(r"\s+", " ", _clean_rich_text((row or {}).get("sender", "")))
            sender_name = str(sender_name or "").strip().lower()
            if sender_name and len(sender_name) <= 32:
                chat_member_name_blacklist.add(sender_name)
    except Exception:
        chat_member_name_blacklist = set()

    counter = Counter()
    valid_rows = 0
    for msg_type, content, source_blob in rows:
        text = content if isinstance(content, str) else ""
        if (not text.strip()) and isinstance(content, (bytes, bytearray)):
            text = _extract_text_from_message_blob(content, msg_type)
        if _is_text_garbled(text):
            continue
        text = _render_link_or_quote_text(msg_type, text, source_blob)
        text = _sanitize_link_text(text)
        text = _clean_rich_text(text)
        message_mentions = _extract_keyword_mentions(text, mention_names)
        text = _strip_keyword_mentions(text, mention_names)
        if not text or _is_text_garbled(text):
            continue
        if re.search(
            r"(欢迎.*加入|邀请.*加入群聊|加入了群聊|拍了拍|撤回了一条消息|通过扫描.*加入群聊|移出了群聊)",
            text,
        ):
            continue
        valid_rows += 1

        # Count unique tokens per message to reduce one-message ngram inflation.
        seen = set()
        for tok in _extract_keyword_candidates(text):
            if not tok or tok in seen:
                continue
            if tok in account_blacklist:
                continue
            if str(tok or "").strip().lower() in chat_member_name_blacklist:
                continue
            if message_mentions and str(tok or "").strip().lower() in message_mentions:
                continue
            seen.add(tok)
            counter[tok] += 1

    min_count = 2 if valid_rows >= 100 else 1
    max_keywords = 240
    rows = []
    for k, v in counter.most_common(max_keywords * 3):
        cnt = int(v)
        if cnt < min_count or _is_noise_keyword(k):
            continue
        rows.append({"keyword": k, "count": cnt})

    # Drop short fragments when a longer keyword covers it with similar frequency.
    pruned = []
    for row in rows:
        kw = str(row.get("keyword", ""))
        cnt = int(row.get("count", 0))
        if re.search(r"[\u4e00-\u9fff]", kw):
            covered = False
            for keep in pruned:
                kk = str(keep.get("keyword", ""))
                kc = int(keep.get("count", 0))
                if len(kk) <= len(kw):
                    continue
                if kw in kk and kc >= int(cnt * 0.85):
                    covered = True
                    break
            if covered:
                continue
        pruned.append(row)
        if len(pruned) >= max_keywords:
            break

    return pruned


def _build_activity_page(base_data, sender_rows, start_ts=0, end_ts=0):
    summary = base_data.get("summary", {}) if isinstance(base_data, dict) else {}
    heatmap = base_data.get("heatmap", []) if isinstance(base_data, dict) else []
    trend = base_data.get("trend", []) if isinstance(base_data, dict) else []
    trend_views = _build_activity_trend_views(trend, sender_rows, start_ts=start_ts, end_ts=end_ts)
    daily_trend = trend_views.get("day", []) if isinstance(trend_views, dict) else []
    weekly_all = trend_views.get("week", []) if isinstance(trend_views, dict) else []
    total_messages = int(summary.get("total_messages", 0) or 0)
    active_senders = int(summary.get("active_senders", 0) or 0)

    workday_hour = [0] * 24
    weekend_hour = [0] * 24
    total_hour_weight = 0
    total_hour_count = 0
    for r in heatmap:
        wd = int(r.get("weekday", 0) or 0)
        hh = int(r.get("hour", 0) or 0)
        c = int(r.get("count", 0) or 0)
        if hh < 0 or hh >= 24:
            continue
        if wd in (0, 6):
            weekend_hour[hh] += c
        else:
            workday_hour[hh] += c
        total_hour_weight += hh * c
        total_hour_count += c
    avg_hour = round((total_hour_weight / total_hour_count), 1) if total_hour_count > 0 else 0.0

    now_ts = int(time.time())
    end_ref_raw = int(end_ts or summary.get("last_ts", 0) or now_ts)
    end_ref = min(end_ref_raw, now_ts) if end_ref_raw > 0 else now_ts
    start30 = datetime.fromtimestamp(end_ref).date() - timedelta(days=29)
    total_members = int(len(sender_rows))
    active_30d = 0
    for s in sender_rows:
        daily = s.get("daily", {}) if isinstance(s, dict) else {}
        hit = False
        for day_str in daily.keys():
            try:
                d = datetime.strptime(day_str, "%Y-%m-%d").date()
            except Exception:
                continue
            if d >= start30:
                hit = True
                break
        if hit:
            active_30d += 1
    active_rate_30 = round((active_30d * 100.0 / total_members), 1) if total_members > 0 else 0.0
    avg_msg_per_sender = round((total_messages / active_senders), 2) if active_senders > 0 else 0.0
    active_days_cnt = len([x for x in daily_trend if int(x.get("messages", 0) or 0) > 0])
    avg_depth = round((total_messages / active_days_cnt), 2) if active_days_cnt > 0 else 0.0
    dormant_members = max(0, total_members - active_30d)
    bins = {
        "1-3天": 0,
        "4-7天": 0,
        "8-14天": 0,
        "15-21天": 0,
        "22-28天": 0,
        "满勤30天": 0,
    }
    for s in sender_rows:
        dcnt = int(s.get("active_days", 0) or 0)
        if dcnt <= 0:
            continue
        if dcnt <= 3:
            bins["1-3天"] += 1
        elif dcnt <= 7:
            bins["4-7天"] += 1
        elif dcnt <= 14:
            bins["8-14天"] += 1
        elif dcnt <= 21:
            bins["15-21天"] += 1
        elif dcnt <= 28:
            bins["22-28天"] += 1
        else:
            bins["满勤30天"] += 1
    active_bins = [{"name": k, "count": int(v)} for k, v in bins.items()]

    weekly = weekly_all[-8:] if len(weekly_all) > 8 else weekly_all

    streak_rows = []
    for s in sender_rows:
        streak = _calc_longest_streak(list((s.get("daily", {}) or {}).keys()))
        if streak <= 0:
            continue
        streak_rows.append({
            "sender_id": s.get("sender_id", ""),
            "sender": s.get("sender", ""),
            "streak_days": int(streak),
            "count": int(s.get("count", 0) or 0),
        })
    streak_rows.sort(key=lambda x: (int(x.get("streak_days", 0)), int(x.get("count", 0))), reverse=True)

    msg_hours = [workday_hour[h] + weekend_hour[h] for h in range(24)]
    hot_hours = sum(1 for c in msg_hours if c > 0)
    type_cnt = len([x for x in (base_data.get("by_type", []) or []) if int(x.get("count", 0) or 0) > 0])
    growth = 50
    if len(weekly_all) >= 2:
        a = int(weekly_all[-1].get("messages", 0))
        b = int(weekly_all[-2].get("messages", 0))
        if b > 0:
            growth = max(10, min(100, int(50 + (a - b) * 50 / b)))
    top_sender_count = max((int(s.get("count", 0) or 0) for s in sender_rows), default=0)
    leader_share = (top_sender_count / max(total_messages, 1)) if total_messages > 0 else 0.0
    non_system = max(0, total_messages - int(summary.get("system_messages", 0) or 0))
    rich_ratio = (int(summary.get("link_messages", 0) or 0) + int(summary.get("media_messages", 0) or 0)) / max(non_system, 1)
    sender_participation = active_rate_30 / 100.0
    type_diversity = max(0.0, min(1.0, type_cnt / 6.0))
    depth_norm = max(0.0, min(1.0, avg_depth / 120.0))
    balance_norm = max(0.0, min(1.0, 1.0 - leader_share * 1.6))
    richness_norm = max(0.0, min(1.0, rich_ratio / 0.35))

    quality_weights = {
        "sender_participation": 0.28,
        "type_diversity": 0.22,
        "content_richness": 0.22,
        "interaction_depth": 0.16,
        "speaker_balance": 0.12,
    }
    content_quality_score = int(round(
        sender_participation * quality_weights["sender_participation"] * 100
        + type_diversity * quality_weights["type_diversity"] * 100
        + richness_norm * quality_weights["content_richness"] * 100
        + depth_norm * quality_weights["interaction_depth"] * 100
        + balance_norm * quality_weights["speaker_balance"] * 100
    ))
    content_quality_score = max(0, min(100, content_quality_score))

    radar = [
        {"name": "发言频率", "value": max(0, min(100, int(active_rate_30)))},
        {"name": "时段分布", "value": max(0, min(100, int(hot_hours * 100 / 24)))},
        {"name": "话题多样", "value": max(0, min(100, int(type_cnt * 14)))},
        {"name": "成员增长", "value": int(growth)},
        {"name": "内容质量", "value": int(content_quality_score)},
        {"name": "互动深度", "value": max(0, min(100, int(avg_depth * 12)))},
    ]

    hourly = []
    for h in range(24):
        hourly.append({
            "hour": f"{h:02d}:00",
            "workday": int(workday_hour[h]),
            "weekend": int(weekend_hour[h]),
        })

    return {
        "kpis": {
            "active_rate_30d": active_rate_30,
            "avg_speak_hour": avg_hour,
            "avg_messages_per_sender": avg_msg_per_sender,
            "avg_depth": avg_depth,
            "dormant_members": dormant_members,
            "active_members_30d": active_30d,
        },
        "hourly_distribution": hourly,
        "active_day_bins": active_bins,
        "weekly_trend": weekly,
        "activity_trend": trend_views,
        "top_streak_members": streak_rows[:30],
        "radar": radar,
        "interaction_heatmap": heatmap if isinstance(heatmap, list) else [],
        "quality_model": {
            "score": int(content_quality_score),
            "level": ("优秀" if content_quality_score >= 75 else "良好" if content_quality_score >= 55 else "待提升"),
            "formula": "评分=成员参与(28%)+类型多样(22%)+内容丰富(22%)+互动深度(16%)+发言均衡(12%)",
            "components": [
                {
                    "id": "sender_participation",
                    "name": "成员参与",
                    "weight": int(quality_weights["sender_participation"] * 100),
                    "score": int(round(sender_participation * 100)),
                    "desc": f"近30天活跃成员占比 {active_rate_30:.1f}%",
                },
                {
                    "id": "type_diversity",
                    "name": "类型多样",
                    "weight": int(quality_weights["type_diversity"] * 100),
                    "score": int(round(type_diversity * 100)),
                    "desc": f"消息类型覆盖 {type_cnt} 类",
                },
                {
                    "id": "content_richness",
                    "name": "内容丰富",
                    "weight": int(quality_weights["content_richness"] * 100),
                    "score": int(round(richness_norm * 100)),
                    "desc": f"媒体/链接占比 {rich_ratio * 100:.1f}%",
                },
                {
                    "id": "interaction_depth",
                    "name": "互动深度",
                    "weight": int(quality_weights["interaction_depth"] * 100),
                    "score": int(round(depth_norm * 100)),
                    "desc": f"平均每日消息 {avg_depth:.2f}",
                },
                {
                    "id": "speaker_balance",
                    "name": "发言均衡",
                    "weight": int(quality_weights["speaker_balance"] * 100),
                    "score": int(round(balance_norm * 100)),
                    "desc": f"头部发言占比 {leader_share * 100:.1f}%",
                },
            ],
        },
    }


def _build_members_page(base_data, sender_rows, start_ts=0, end_ts=0):
    summary = base_data.get("summary", {}) if isinstance(base_data, dict) else {}
    total_members = int(len(sender_rows))
    now_ts = int(time.time())
    end_ref_raw = int(end_ts or summary.get("last_ts", 0) or now_ts)
    end_ref = min(end_ref_raw, now_ts) if end_ref_raw > 0 else now_ts

    start_ref = int(start_ts or summary.get("first_ts", 0) or max(0, end_ref - 29 * 86400))
    if start_ref > end_ref:
        start_ref = max(0, end_ref - 29 * 86400)
    range_days = max(1, int((end_ref - start_ref) / 86400) + 1)

    logic = _activity_level_logic(sender_rows, range_days=range_days)
    level_by_sender = logic.get("level_by_sender", {}) if isinstance(logic, dict) else {}
    score_by_sender = logic.get("score_by_sender", {}) if isinstance(logic, dict) else {}

    def _level_by_sender(sender_id):
        sid = str(sender_id or "")
        if sid in level_by_sender:
            return level_by_sender[sid]
        return ("低参与", "low")

    def _format_tenure(months, first_ts):
        m = float(months or 0.0)
        if m < 1.0:
            if int(first_ts or 0) <= 0:
                return "--"
            days = max(1, int((end_ref - int(first_ts)) / 86400))
            return f"{days}天"
        if m < 12.0:
            return f"{int(round(m))}个月"
        years = int(m // 12)
        rest = int(round(m - years * 12))
        if rest <= 0:
            return f"{years}年"
        return f"{years}年{rest}个月"

    def _recent_text(last_ts):
        ts = int(last_ts or 0)
        if ts <= 0:
            return "--"
        dt = max(0, int(end_ref - ts))
        if dt < 3600:
            return "1小时内"
        if dt < 86400:
            return f"{max(1, int(dt / 3600))}小时前"
        days = int(dt / 86400)
        if days == 1:
            return "昨天"
        return f"{days}天前"

    cnt_meta = logic.get("counts", {}) if isinstance(logic, dict) else {}
    active_any = int(cnt_meta.get("active", 0) or 0)
    low_only = int(cnt_meta.get("low", 0) or 0)
    normal_only = int(cnt_meta.get("normal", 0) or 0)
    core_only = int(cnt_meta.get("core", 0) or 0)
    normal_plus = int(cnt_meta.get("normal_plus", 0) or 0)
    core_plus = int(cnt_meta.get("core_plus", 0) or 0)
    kol = int(cnt_meta.get("kol", 0) or 0)
    # Use strictly descending stages for funnel readability.
    stage_total = max(0, int(total_members))
    stage_normal_plus = max(0, min(stage_total, int(normal_plus)))
    stage_core_plus = max(0, min(stage_normal_plus, int(core_plus)))
    stage_kol = max(0, min(stage_core_plus, int(kol)))
    funnel = [
        {"name": "当前范围成员", "count": stage_total, "color": "#f5f8ff"},
        {"name": "普通及以上", "count": stage_normal_plus, "color": "#16c7da"},
        {"name": "核心及以上", "count": stage_core_plus, "color": "#7f62ff"},
        {"name": "KOL", "count": stage_kol, "color": "#ff4dbd"},
    ]

    tenure_bins = {
        "<1月": 0,
        "1-3月": 0,
        "3-6月": 0,
        "6-12月": 0,
        "1-2年": 0,
        "2年以上": 0,
    }
    for s in sender_rows:
        first_ts = int(s.get("first_ts_all", 0) or s.get("first_ts", 0) or 0)
        if first_ts <= 0:
            continue
        months = max(0.0, (end_ref - first_ts) / 2592000.0)
        if months < 1:
            tenure_bins["<1月"] += 1
        elif months < 3:
            tenure_bins["1-3月"] += 1
        elif months < 6:
            tenure_bins["3-6月"] += 1
        elif months < 12:
            tenure_bins["6-12月"] += 1
        elif months < 24:
            tenure_bins["1-2年"] += 1
        else:
            tenure_bins["2年以上"] += 1

    behavior = []
    for s in sender_rows[:80]:
        count = int(s.get("count", 0) or 0)
        active_days = int(s.get("active_days", 0) or 0)
        link_c = int(s.get("link_count", 0) or 0)
        media_c = int(s.get("media_count", 0) or 0)
        impact = round(active_days * 1.8 + link_c * 0.9 + media_c * 0.7 + count * 0.06, 2)
        size = round(min(120.0, 16.0 + (count ** 0.5) * 3.4), 2)
        behavior.append({
            "sender_id": s.get("sender_id", ""),
            "sender": s.get("sender", ""),
            "x_messages": count,
            "y_impact": impact,
            "size": size,
            "active_days": active_days,
        })

    text_total = sum(int(s.get("text_count", 0) or 0) for s in sender_rows)
    media_total = sum(int(s.get("media_count", 0) or 0) for s in sender_rows)
    link_total = sum(int(s.get("link_count", 0) or 0) for s in sender_rows)
    system_total = sum(int(s.get("system_count", 0) or 0) for s in sender_rows)
    other_total = sum(int(s.get("other_count", 0) or 0) for s in sender_rows)
    contribution = [
        {"name": "文本", "count": int(text_total)},
        {"name": "媒体", "count": int(media_total)},
        {"name": "链接", "count": int(link_total)},
        {"name": "系统", "count": int(system_total)},
        {"name": "其他", "count": int(other_total)},
    ]

    recent30_start = datetime.fromtimestamp(end_ref).date() - timedelta(days=29)
    members_table = []
    for i, s in enumerate(sender_rows[:600], start=1):
        count = int(s.get("count", 0) or 0)
        active_days = int(s.get("active_days", 0) or 0)
        first_ts = int(s.get("first_ts_all", 0) or s.get("first_ts", 0) or 0)
        last_ts = int(s.get("last_ts", 0) or 0)
        months = max(0.0, (end_ref - first_ts) / 2592000.0) if first_ts > 0 else 0.0
        sid = str(s.get("sender_id", "") or "")
        lvl, lvl_key = _level_by_sender(sid)
        daily = s.get("daily", {}) or {}
        month_messages = 0
        for day_str, c in daily.items():
            try:
                d = datetime.strptime(str(day_str), "%Y-%m-%d").date()
            except Exception:
                continue
            if d >= recent30_start:
                month_messages += int(c or 0)
        link_c = int(s.get("link_count", 0) or 0)
        media_c = int(s.get("media_count", 0) or 0)
        impact = int(round(score_by_sender.get(sid, active_days * 1.8 + link_c * 0.9 + media_c * 0.7 + count * 0.06)))
        members_table.append({
            "rank": i,
            "sender_id": sid,
            "sender": s.get("sender", ""),
            "messages": count,
            "month_messages": int(month_messages),
            "link_count": link_c,
            "media_count": media_c,
            "active_days": active_days,
            "first_ts": first_ts,
            "last_ts": last_ts,
            "tenure_months": round(months, 1),
            "tenure_label": _format_tenure(months, first_ts),
            "level": lvl,
            "level_key": lvl_key,
            "impact_score": int(max(0, impact)),
            "recent_active_text": _recent_text(last_ts),
            "recent_active_hours": int(max(0, (end_ref - last_ts) / 3600)) if last_ts > 0 else 0,
        })

    return {
        "funnel": funnel,
        "level_logic": logic,
        "tenure_distribution": [{"name": k, "count": int(v)} for k, v in tenure_bins.items()],
        "behavior_matrix": behavior,
        "contribution_share": contribution,
        "members_table": members_table,
    }


def _fun_trim_text(text, limit=92):
    raw = _clean_rich_text(text)
    raw = re.sub(r"\s+", " ", str(raw or "")).strip()
    if not raw:
        return ""
    limit = max(16, int(limit or 0))
    if len(raw) > limit:
        return raw[: max(0, limit - 3)] + "..."
    return raw


def _fun_topic_clause(text, limit=24, hints=None):
    raw = _clean_rich_text(text)
    raw = re.sub(r"https?://\S+", "", str(raw or ""), flags=re.IGNORECASE)
    raw = re.sub(r"\[[^\]]{1,12}\]", "", raw)
    raw = re.sub(r"@[^\s，。！？!?、,;；:：]{1,24}", "", raw)
    raw = re.sub(r"\s+", " ", raw).strip(" ，。！？!?、,;；:：")
    if not raw:
        return ""

    hint_list = [str(x or "").strip().lower() for x in (hints or []) if str(x or "").strip()]
    parts = [p.strip(" ，。！？!?、,;；:：") for p in re.split(r"[，。！？!?；;、\n]+", raw) if p.strip()]
    if not parts:
        parts = [raw]

    filler_re = re.compile(
        r"^(好的|收到|嗯嗯|嗯|哈+|哈哈+|ok|OK|行|安排|确实|对对|是的|好呀|我觉得|感觉|那个|这个|然后|所以)[\s，,]*",
        flags=re.IGNORECASE,
    )

    def _normalize(part):
        value = filler_re.sub("", str(part or "").strip())
        value = re.sub(r"\s+", " ", value).strip(" ，。！？!?、,;；:：")
        return value

    best = ""
    best_score = -10**9
    for part in parts:
        candidate = _normalize(part) or str(part or "").strip()
        if not candidate:
            continue
        low = candidate.lower()
        score = len(candidate)
        if any(hint and hint in low for hint in hint_list):
            score += 10
        if len(candidate) <= 2:
            score -= 12
        if re.fullmatch(r"(好的|收到|嗯嗯|嗯|哈+|哈哈+|ok|行|确实|对对)", candidate, flags=re.IGNORECASE):
            score -= 18
        if re.search(r"(http|www\.|二维码|表情包?)", candidate, flags=re.IGNORECASE):
            score -= 8
        if score > best_score:
            best = candidate
            best_score = score

    result = best or raw
    limit = max(8, int(limit or 0))
    if len(result) > limit:
        result = result[: max(0, limit - 3)] + "..."
    return result


def _fun_hour_bucket(hour_value):
    try:
        hour = int(hour_value)
    except Exception:
        return "全天"
    if 0 <= hour < 6:
        return "凌晨"
    if hour < 11:
        return "上午"
    if hour < 14:
        return "中午"
    if hour < 18:
        return "下午"
    if hour < 23:
        return "晚上"
    return "深夜"


def _build_fun_scene(samples):
    ordered = []
    for rec in reversed(samples or []):
        if not isinstance(rec, dict):
            continue
        ts = int(rec.get("ts", 0) or 0)
        text = _fun_trim_text(rec.get("text", ""), limit=86)
        if ts <= 0 or not text:
            continue
        sender = str(rec.get("sender", "") or "").strip() or "成员"
        time_text = str(rec.get("time", "") or "").strip()
        if not time_text:
            try:
                time_text = datetime.fromtimestamp(ts).strftime("%m-%d %H:%M")
            except Exception:
                time_text = ""
        ordered.append({
            "ts": ts,
            "sender": sender,
            "time": time_text,
            "text": text,
        })
    ordered.sort(key=lambda x: int(x.get("ts", 0) or 0))
    if not ordered:
        return {
            "subtitle": "当前时间范围内还没有足够的文本样本。",
            "meta": "",
            "messages": [],
            "analysis": "当前没有可用于评选的连续对话片段。",
            "note": "当前样本不足，名场面卡片先隐藏具体内容。",
        }

    scenes = []
    current = []
    for row in ordered:
        if not current:
            current = [row]
            continue
        gap = int(row.get("ts", 0) or 0) - int(current[-1].get("ts", 0) or 0)
        if gap > 600:
            scenes.append({"messages": current, "cooldown": max(0, gap)})
            current = [row]
        else:
            current.append(row)
    if current:
        scenes.append({"messages": current, "cooldown": 0})

    ranked = []
    for item in scenes:
        messages = item.get("messages", [])
        if len(messages) < 3:
            continue
        participants = len({str(m.get("sender", "") or "") for m in messages})
        turns = sum(
            1 for a, b in zip(messages, messages[1:])
            if str(a.get("sender", "")) != str(b.get("sender", ""))
        )
        duration = max(1, int(messages[-1].get("ts", 0) or 0) - int(messages[0].get("ts", 0) or 0))
        density = float(len(messages)) * 60.0 / max(60.0, float(duration))
        emotion_hits = sum(
            1 for m in messages
            if re.search(r"(哈|笑|！|!|？|\?|卧槽|离谱|绝了|寄了|emo|崩)", str(m.get("text", "")), flags=re.IGNORECASE)
        )
        score = (
            len(messages) * 3.1
            + participants * 2.6
            + turns * 1.7
            + density * 2.2
            + min(float(item.get("cooldown", 0) or 0) / 240.0, 8.0) * 0.5
            + emotion_hits * 0.45
        )
        ranked.append((score, item))

    if ranked:
        ranked.sort(key=lambda x: float(x[0]), reverse=True)
        selected_scene = ranked[0][1]
    else:
        selected_scene = {"messages": ordered[-min(6, len(ordered)):], "cooldown": 0}

    scene_messages = selected_scene.get("messages", [])
    if len(scene_messages) > 6:
        best_slice = scene_messages[:6]
        best_score = -1.0
        window_size = 6
        for i in range(0, len(scene_messages) - window_size + 1):
            win = scene_messages[i:i + window_size]
            win_participants = len({str(m.get("sender", "") or "") for m in win})
            win_turns = sum(
                1 for a, b in zip(win, win[1:])
                if str(a.get("sender", "")) != str(b.get("sender", ""))
            )
            win_score = win_participants * 2.4 + win_turns * 1.5
            if win_score > best_score:
                best_score = win_score
                best_slice = win
        scene_messages = best_slice

    speaker_side = {}
    display_messages = []
    for msg in scene_messages:
        sender = str(msg.get("sender", "") or "").strip() or "成员"
        if sender not in speaker_side:
            speaker_side[sender] = "left" if (len(speaker_side) % 2 == 0) else "right"
        display_messages.append({
            "sender": sender,
            "time": str(msg.get("time", "") or ""),
            "text": str(msg.get("text", "") or ""),
            "side": speaker_side[sender],
        })

    participants = len({str(m.get("sender", "") or "") for m in scene_messages})
    turns = sum(
        1 for a, b in zip(scene_messages, scene_messages[1:])
        if str(a.get("sender", "")) != str(b.get("sender", ""))
    )
    duration_seconds = max(
        1,
        int(scene_messages[-1].get("ts", 0) or 0) - int(scene_messages[0].get("ts", 0) or 0),
    ) if len(scene_messages) >= 2 else 60
    duration_minutes = max(1, int(round(float(duration_seconds) / 60.0)))
    dominant_sender, dominant_count = Counter(
        str(m.get("sender", "") or "") for m in scene_messages
    ).most_common(1)[0]
    style_text = "多人接梗" if participants >= 4 else ("双人对撞" if participants <= 2 else "接力抛梗")
    cooldown_minutes = int(round(float(selected_scene.get("cooldown", 0) or 0) / 60.0))
    cooldown_text = f"聊完后还冷了 {cooldown_minutes} 分钟。" if cooldown_minutes >= 12 else ""
    note = ""
    if len(ordered) < 24 or len(scene_messages) < 4:
        note = "当前样本偏少，暂用最近一段连续对话兜底。"
    subtitle = f"按连续发言密度和接话切换，自动挑出当前窗口最像“名场面”的片段。"
    meta = (
        f"{scene_messages[0].get('time', '')} - {scene_messages[-1].get('time', '')} · "
        f"{len(scene_messages)} 句 · {participants} 人接话"
    )
    analysis_parts = [
        (
            f"这段对话在 {duration_minutes} 分钟里连出 {len(scene_messages)} 句，"
            f"{dominant_sender or '核心成员'} 贡献了 {dominant_count} 句，整体更像一场 {style_text}。"
        ),
        "来回接话非常密集。" if turns >= max(2, len(scene_messages) - 2) else "节奏起伏明显。",
    ]
    if cooldown_text:
        analysis_parts.append(cooldown_text)
    analysis = " ".join(part.strip() for part in analysis_parts if str(part or "").strip())
    return {
        "subtitle": subtitle,
        "meta": meta,
        "messages": display_messages,
        "analysis": analysis,
        "note": note,
    }


def _build_fun_bonds(network):
    network = network if isinstance(network, dict) else {}
    raw_nodes = network.get("nodes", []) if isinstance(network.get("nodes", []), list) else []
    raw_edges = network.get("edges", []) if isinstance(network.get("edges", []), list) else []
    if not raw_nodes:
        return {
            "summary": "当前时间范围还没形成足够稳定的互动网络。",
            "nodes": [],
            "edges": [],
            "badges": [],
            "note": "等消息样本再多一点，这里会自动长出更清晰的连线。",
        }

    sorted_nodes = sorted(
        [x for x in raw_nodes if isinstance(x, dict)],
        key=lambda x: (
            float(x.get("value", 0) or 0),
            float(x.get("degree", 0) or 0),
            int(x.get("messages", 0) or 0),
        ),
        reverse=True,
    )
    kept_nodes = sorted_nodes[:8]
    keep_ids = {str(x.get("id", "") or "") for x in kept_nodes}
    node_name = {
        str(x.get("id", "") or ""): str(x.get("name", "") or str(x.get("id", "") or "成员"))
        for x in kept_nodes
    }
    kept_edges = []
    for edge in sorted(
        [x for x in raw_edges if isinstance(x, dict)],
        key=lambda x: float(x.get("weight", 0) or 0),
        reverse=True,
    ):
        source = str(edge.get("source", "") or "")
        target = str(edge.get("target", "") or "")
        if not source or not target or source not in keep_ids or target not in keep_ids or source == target:
            continue
        kept_edges.append({
            "source": source,
            "target": target,
            "weight": round(float(edge.get("weight", 0) or 0), 2),
        })
        if len(kept_edges) >= 12:
            break

    badges = []
    for edge in kept_edges[:4]:
        weight = float(edge.get("weight", 0) or 0)
        pair_title = f"{node_name.get(edge.get('source', ''), '成员A')} × {node_name.get(edge.get('target', ''), '成员B')}"
        if weight >= 14:
            label = "高频绑定"
        elif weight >= 9:
            label = "接梗搭子"
        else:
            label = "顺手接话"
        badges.append({
            "label": label,
            "title": pair_title,
            "detail": f"关系强度 {weight:.1f}，在当前窗口属于最粗的一批连线。",
        })

    summary = (
        f"基于互相 @ 和紧接发言，识别出 {len(kept_nodes)} 个关键节点、"
        f"{len(kept_edges)} 条主要关系。线越粗，说明彼此越容易形成接话。"
    )
    note = ""
    if len(kept_edges) < 3:
        note = "当前更多是单线程发言，明显的成对互动还不算多。"
    return {
        "summary": summary,
        "nodes": kept_nodes,
        "edges": kept_edges,
        "badges": badges,
        "note": note,
    }


def _fun_slang_desc(keyword, topic=""):
    kw = str(keyword or "").strip()
    low = kw.lower()
    topic = str(topic or "").strip()
    if any(token in low for token in ("token", "api", "prompt", "agent", "cursor", "gpt", "sdk")) or any(
        token in kw for token in ("模型", "算力", "推理")
    ):
        return (
            f"群内释义：通常不是在科普“{kw}”本身，而是在直接讨论“{topic}”里的成本、效果或方案取舍。"
            if topic else
            "群内释义：通常不是在讲概念本身，而是在顺手代指成本、能力边界或方案优劣。"
        )
    if any(token in kw for token in ("寄", "崩", "裂", "炸", "挂", "emo", "麻", "完")):
        return (
            f"群内释义：用最短的词宣布“{topic}”这事不太妙，结论和情绪一起甩出来。"
            if topic else
            "群内释义：用最短的词宣布事情不妙，顺便把情绪也一并交代。"
        )
    if any(token in kw for token in ("好的", "收到", "嗯嗯", "安排", "ok", "OK", "行")):
        return (
            f"群内释义：表面是在回复“收到”，实际是在给“{topic}”这件事点头、接单或确认继续往下走。"
            if topic else
            "群内释义：看起来只是礼貌回复，实际是在快速确认上下文、接住任务或表示继续推进。"
        )
    if any(token in kw for token in ("对对", "确实", "哈哈", "牛", "稳", "6", "绝了")):
        return (
            f"群内释义：看着像顺手附和，其实是在给“{topic}”捧场、续梗或者表示强认同。"
            if topic else
            "群内释义：典型低成本接话词，既能捧场，也能帮讨论不断线。"
        )
    return (
        f"群内释义：它更像一句默认共享上下文的内部简称，一出现大家就知道在说“{topic}”。"
        if topic else
        "群内释义：更像内部 shorthand，一出现就默认大家共享上下文，不需要从头解释。"
    )


def _build_fun_slang(keyword_rows, samples):
    sample_rows = []
    for rec in samples or []:
        if not isinstance(rec, dict):
            continue
        ts = int(rec.get("ts", 0) or 0)
        text = _fun_trim_text(rec.get("text", ""), limit=110)
        if not text:
            continue
        sample_rows.append({
            "ts": ts,
            "sender": str(rec.get("sender", "") or "").strip() or "成员",
            "text": text,
        })

    candidates = []
    for row in keyword_rows or []:
        if not isinstance(row, dict):
            continue
        kw = str(row.get("keyword", "") or "").strip()
        cnt = int(row.get("count", 0) or 0)
        if not kw or cnt <= 1:
            continue
        if len(kw) > 14:
            continue
        if re.fullmatch(r"[\d\W_]+", kw):
            continue
        if re.match(r"^(http|www\.)", kw, flags=re.IGNORECASE):
            continue
        if len(kw) <= 1 and not re.search(r"[A-Za-z]{2,}", kw):
            continue
        candidates.append({"keyword": kw, "count": cnt})
        if len(candidates) >= 10:
            break

    items = []
    seen = set()
    for row in candidates:
        kw = str(row.get("keyword", "") or "").strip()
        low = kw.lower()
        if not kw or low in seen:
            continue
        seen.add(low)
        hits = []
        for sample in sample_rows:
            if low in str(sample.get("text", "") or "").lower():
                hits.append(sample)
        if not hits and len(items) >= 2:
            continue
        topic = ""
        for hit in hits[:6]:
            topic = _fun_topic_clause(hit.get("text", ""), limit=22, hints=[kw])
            if topic and topic.lower() != low and len(topic) >= max(4, min(len(kw) + 1, 8)):
                break
        if topic.lower() == low:
            topic = ""
        hour_counter = Counter()
        sender_counter = Counter()
        for hit in hits[:18]:
            ts = int(hit.get("ts", 0) or 0)
            if ts > 0:
                try:
                    hour_counter[datetime.fromtimestamp(ts).hour] += 1
                except Exception:
                    pass
            sender_counter[str(hit.get("sender", "") or "").strip() or "成员"] += 1
        top_hour = hour_counter.most_common(1)[0][0] if hour_counter else None
        top_sender = sender_counter.most_common(1)[0][0] if sender_counter else ""
        meta_bits = [f"提及 {int(row.get('count', 0) or 0)} 次"]
        if top_hour is not None:
            meta_bits.append(f"高发于{_fun_hour_bucket(top_hour)}")
        if top_sender:
            meta_bits.append(f"样本里常见于 {top_sender}")
        if topic:
            meta_bits.append(f"多半在聊“{topic}”")
        context = hits[0].get("text", "") if hits else ""
        examples = []
        for hit in hits[:2]:
            text = _fun_trim_text(hit.get("text", ""), limit=68)
            if text and text not in examples:
                examples.append(text)
        tone = "neutral"
        if any(token in kw for token in ("寄", "崩", "裂", "emo", "炸")):
            tone = "danger"
        elif any(token in low for token in ("token", "api", "prompt", "agent", "sdk")):
            tone = "warn"
        elif any(token in kw for token in ("确实", "对对", "哈哈", "稳", "牛")):
            tone = "positive"
        items.append({
            "term": kw,
            "count": int(row.get("count", 0) or 0),
            "desc": _fun_slang_desc(kw, topic),
            "topic": topic,
            "context": context,
            "examples": examples,
            "meta": " · ".join(meta_bits),
            "tone": tone,
        })
        if len(items) >= 4:
            break

    note = (
        "这些词条优先解释“在这个群里它到底指什么事”，不是只做词面翻译。"
        if items else
        "当前样本不足，还没拼出稳定的群内黑话。"
    )
    return {"items": items, "note": note}


def _build_fun_awards(samples, network, members_data):
    sample_rows = []
    for rec in reversed(samples or []):
        if not isinstance(rec, dict):
            continue
        ts = int(rec.get("ts", 0) or 0)
        text = _fun_trim_text(rec.get("text", ""), limit=96)
        sender = str(rec.get("sender", "") or "").strip() or "成员"
        if ts <= 0 or not text:
            continue
        try:
            hour = datetime.fromtimestamp(ts).hour
        except Exception:
            hour = -1
        sample_rows.append({"ts": ts, "sender": sender, "text": text, "hour": hour, "type": str(rec.get("type", "") or "")})
    sample_rows.sort(key=lambda x: int(x.get("ts", 0) or 0))

    awards = []
    if sample_rows:
        trigger_score = defaultdict(float)
        trigger_hits = defaultdict(int)
        trigger_rounds = defaultdict(int)
        support_score = defaultdict(float)
        support_hits = defaultdict(int)
        night_score = defaultdict(int)
        message_count = Counter(str(row.get("sender", "") or "") for row in sample_rows)
        agreement_re = re.compile(r"(确实|对对|哈哈|笑死|牛|稳|6+|绝了|可以啊|有道理)")
        for idx, row in enumerate(sample_rows):
            sender = str(row.get("sender", "") or "").strip() or "成员"
            text = str(row.get("text", "") or "")
            hour = int(row.get("hour", -1) or -1)
            if 0 <= hour <= 5:
                night_score[sender] += 1
            if agreement_re.search(text):
                support_score[sender] += 1.4
                support_hits[sender] += 1
                if idx > 0:
                    prev = sample_rows[idx - 1]
                    prev_sender = str(prev.get("sender", "") or "").strip() or "成员"
                    gap_prev = int(row.get("ts", 0) or 0) - int(prev.get("ts", 0) or 0)
                    if prev_sender != sender and 0 <= gap_prev <= 180:
                        support_score[sender] += 1.6
            replies = 0
            uniq = set()
            for nxt in sample_rows[idx + 1:]:
                gap = int(nxt.get("ts", 0) or 0) - int(row.get("ts", 0) or 0)
                if gap > 300:
                    break
                nxt_sender = str(nxt.get("sender", "") or "").strip() or "成员"
                if nxt_sender == sender:
                    continue
                replies += 1
                uniq.add(nxt_sender)
            if replies >= 2:
                trigger_score[sender] += float(replies) + float(len(uniq)) * 0.8
                trigger_hits[sender] += replies
                trigger_rounds[sender] += 1
        if trigger_score:
            winner = max(trigger_score.keys(), key=lambda x: (trigger_score[x], trigger_hits[x], message_count[x]))
            awards.append({
                "title": "话题制造机",
                "icon": "🔥",
                "winner": winner,
                "detail": f"抛出 {int(trigger_rounds[winner])} 次高跟帖话头，累计带来 {int(trigger_hits[winner])} 条接话。",
                "tone": "warn",
            })

        gaps_by_sender = defaultdict(list)
        for row, nxt in zip(sample_rows, sample_rows[1:]):
            sender = str(row.get("sender", "") or "").strip() or "成员"
            gap = max(0, int(nxt.get("ts", 0) or 0) - int(row.get("ts", 0) or 0))
            if gap > 0:
                gaps_by_sender[sender].append(gap)
        best_sender = ""
        best_gap = 0.0
        for sender, gaps in gaps_by_sender.items():
            if len(gaps) < 2:
                continue
            long_gaps = sorted(gaps, reverse=True)[: min(3, len(gaps))]
            avg_gap = sum(long_gaps) / float(len(long_gaps))
            if avg_gap > best_gap:
                best_gap = avg_gap
                best_sender = sender
        if best_sender:
            awards.append({
                "title": "金牌话题终结者",
                "icon": "🧊",
                "winner": best_sender,
                "detail": f"发言后的平均静默时间约 {int(round(best_gap / 60.0))} 分钟，收尾能力相当稳定。",
                "tone": "danger",
            })

        if support_score:
            support_winner = max(
                support_score.keys(),
                key=lambda x: (support_score[x], support_hits[x], message_count[x]),
            )
            if support_hits[support_winner] >= 2:
                awards.append({
                    "title": "首席捧哏官",
                    "icon": "👏",
                    "winner": support_winner,
                    "detail": f"高频接住“确实 / 哈哈 / 有道理”这类情绪球，窗口内命中 {int(support_hits[support_winner])} 次。",
                    "tone": "positive",
                })

        if night_score:
            night_winner = max(night_score.keys(), key=lambda x: (night_score[x], message_count[x]))
            if night_score[night_winner] >= 2:
                awards.append({
                    "title": "夜班值守员",
                    "icon": "🌙",
                    "winner": night_winner,
                    "detail": f"凌晨 0-5 点仍在群里留下 {int(night_score[night_winner])} 条消息，像在给群聊值夜班。",
                    "tone": "neutral",
                })

    network = network if isinstance(network, dict) else {}
    nodes = network.get("nodes", []) if isinstance(network.get("nodes", []), list) else []
    if nodes:
        hub = max(
            [x for x in nodes if isinstance(x, dict)],
            key=lambda x: (float(x.get("degree", 0) or 0), float(x.get("messages", 0) or 0)),
        )
        awards.append({
            "title": "地下联络员",
            "icon": "🕸️",
            "winner": str(hub.get("name", "") or "成员"),
            "detail": f"互动度 {float(hub.get('degree', 0) or 0):.1f}，在羁绊网里连接了最多有效关系。",
            "tone": "positive",
        })

    members_table = members_data.get("members_table", []) if isinstance(members_data, dict) else []
    if isinstance(members_table, list) and members_table:
        deep_candidates = []
        curator_candidates = []
        for row in members_table:
            if not isinstance(row, dict):
                continue
            messages = int(row.get("messages", 0) or 0)
            recent_hours = int(row.get("recent_active_hours", 0) or 0)
            link_count = int(row.get("link_count", 0) or 0)
            media_count = int(row.get("media_count", 0) or 0)
            if messages <= 0:
                continue
            score = float(recent_hours) + max(0, 6 - min(messages, 6)) * 10.0
            deep_candidates.append((score, row))
            curator_score = float(link_count) * 2.6 + float(media_count) * 1.2 + min(messages, 80) * 0.05
            if curator_score > 0:
                curator_candidates.append((curator_score, row))
        deep_candidates.sort(key=lambda x: float(x[0]), reverse=True)
        if deep_candidates:
            _, row = deep_candidates[0]
            awards.append({
                "title": "深海巡游者",
                "icon": "🌊",
                "winner": str(row.get("sender", "") or "成员"),
                "detail": f"当前窗口只留下 {int(row.get('messages', 0) or 0)} 条消息，最近一次露面是 {row.get('recent_active_text', '较早之前')}。",
                "tone": "neutral",
            })
        curator_candidates.sort(key=lambda x: float(x[0]), reverse=True)
        if curator_candidates:
            _, row = curator_candidates[0]
            link_count = int(row.get("link_count", 0) or 0)
            media_count = int(row.get("media_count", 0) or 0)
            if link_count > 0 or media_count > 2:
                awards.append({
                    "title": "情报投喂官",
                    "icon": "🛰️",
                    "winner": str(row.get("sender", "") or "成员"),
                    "detail": f"本窗口发出 {link_count} 条链接、{media_count} 条媒体消息，像在群里持续补给新情报。",
                    "tone": "warn",
                })

    deduped = []
    seen_title = set()
    for item in awards:
        title = str((item or {}).get("title", "") or "")
        winner = str((item or {}).get("winner", "") or "")
        if not title or not winner or title in seen_title:
            continue
        seen_title.add(title)
        deduped.append(item)
    return {
        "items": deduped[:6],
        "note": "按当前时间范围自动评选，切换日期后结果会同步变化；奖项会随着消息结构和发言风格一起换人。",
    }


def _build_fun_insights(base_data, activity_data, members_data, keyword_rows):
    base_data = base_data if isinstance(base_data, dict) else {}
    activity_data = activity_data if isinstance(activity_data, dict) else {}
    members_data = members_data if isinstance(members_data, dict) else {}
    samples = base_data.get("recent_samples", []) if isinstance(base_data.get("recent_samples", []), list) else []
    network = activity_data.get("interaction_network", {}) if isinstance(activity_data.get("interaction_network", {}), dict) else {}
    return {
        "scene": _build_fun_scene(samples),
        "bonds": _build_fun_bonds(network),
        "slang": _build_fun_slang(keyword_rows, samples),
        "awards": _build_fun_awards(samples, network, members_data),
    }


ACTIVITY_FUN_BUCKET_META = {
    "carb": {
        "label": "纯水 / 斗图",
        "sub": "碳水",
        "emoji": "🥳",
        "color": "#fb923c",
        "desc": "纯接梗、寒暄和无信息量互动",
    },
    "protein": {
        "label": "技术探讨",
        "sub": "蛋白质",
        "emoji": "💻",
        "color": "#60a5fa",
        "desc": "偏有信息密度的正经讨论",
    },
    "fat": {
        "label": "行业八卦",
        "sub": "脂肪",
        "emoji": "🍉",
        "color": "#a78bfa",
        "desc": "八卦、人格测试和轻社交内容",
    },
    "toxin": {
        "label": "情绪发泄",
        "sub": "毒素",
        "emoji": "🥵",
        "color": "#fb7185",
        "desc": "抱怨、吐槽和情绪排放",
    },
    "vitamin": {
        "label": "大佬丢链接",
        "sub": "维生素",
        "emoji": "🔗",
        "color": "#34d399",
        "desc": "外部资料和参考链接补给",
    },
}


def _activity_fun_sender_quote(samples, sender):
    target = str(sender or "").strip()
    if not target:
        return ""
    for row in samples or []:
        if not isinstance(row, dict):
            continue
        if str(row.get("sender", "") or "").strip() != target:
            continue
        text = _fun_trim_text(row.get("text", ""), limit=90)
        if text:
            return text
    return ""


def _activity_fun_bucket(text):
    raw = _clean_rich_text(text)
    low = str(raw or "").lower()
    if not low:
        return "carb"
    if re.search(r"(烦|崩|裂开|无语|离谱|服了|吐槽|救命|加班|痛苦|骂|气死|难受|破防|班味)", raw):
        return "toxin"
    if re.search(r"(api|sdk|token|模型|部署|发布|修复|回放|直播|排期|需求|方案|文档|链接|教程|复盘|数据|sql|python|claude|codebuddy|agent|bug|线上|服务器|告警|脚本|版本)", low):
        return "protein"
    if re.search(r"(http|www\.|链接|文档|附件|回放|资料|飞书|notion|github|pdf|网页)", low):
        return "vitamin"
    if re.search(r"(八卦|吃瓜|老板|同事|瓜|绯闻|cp|魅惑|男低音|mbti|人格|测试)", low):
        return "fat"
    if re.search(r"(哈哈|笑死|表情|斗图|早|晚安|收到|ok|嗯嗯|嘿嘿|在吗|摸鱼|午饭|吃啥|排骨|猪脚|奶茶|咖啡|夜宵|火锅)", raw):
        return "carb"
    return "protein" if len(raw) >= 26 else "carb"


def _activity_fun_short_label(text, keyword_rows):
    hints = []
    for row in keyword_rows or []:
        kw = str((row or {}).get("keyword", "") or "").strip()
        if kw:
            hints.append(kw)
        if len(hints) >= 6:
            break
    return _fun_topic_clause(text, limit=20, hints=hints) or "当前话题"


def _activity_fun_build_derailment(samples, keyword_rows):
    ordered = []
    for row in reversed(samples or []):
        if not isinstance(row, dict):
            continue
        ts = int(row.get("ts", 0) or 0)
        text = _fun_trim_text(row.get("text", ""), limit=42)
        if ts <= 0 or not text:
            continue
        ordered.append({
            "ts": ts,
            "sender": str(row.get("sender", "") or "").strip() or "成员",
            "time": str(row.get("time", "") or "").strip(),
            "text": text,
        })
    ordered.sort(key=lambda x: int(x.get("ts", 0) or 0))
    if not ordered:
        return {"note": "暂无漂移样本", "baseline": "", "points": [], "culprit": {}}

    baseline = ""
    for row in keyword_rows or []:
        kw = str((row or {}).get("keyword", "") or "").strip()
        if kw:
            baseline = kw
            break
    if not baseline:
        baseline = _activity_fun_short_label(ordered[0].get("text", ""), keyword_rows)

    point_count = min(6, max(4, len(ordered)))
    picked = []
    if len(ordered) <= point_count:
        picked = ordered[:]
    else:
        for idx in range(point_count):
            pos = int(round(idx * (len(ordered) - 1) / max(1, point_count - 1)))
            picked.append(ordered[pos])

    points = []
    last_score = None
    culprit = {}
    max_jump = 0.0
    for row in picked:
        text = str(row.get("text", "") or "")
        bucket = _activity_fun_bucket(text)
        score = 12.0
        if baseline and baseline.lower() in text.lower():
            score -= 10.0
        if re.search(r"(api|sdk|部署|服务器|修复|需求|排期|回放|直播|文档|问题|方案)", text, flags=re.IGNORECASE):
            score -= 7.0
        if bucket == "protein":
            score += 7.0
        elif bucket == "vitamin":
            score += 18.0
        elif bucket == "fat":
            score += 37.0
        elif bucket == "carb":
            score += 48.0
        elif bucket == "toxin":
            score += 44.0
        if re.search(r"(吃|午饭|奶茶|火锅|咖啡|排骨|猪脚|夜宵)", text):
            score += 20.0
        if re.search(r"(哈哈|笑死|表情|😂|🤣|😭|😅|🙃|🤡)", text):
            score += 10.0
        score = max(4.0, min(98.0, score))
        item = {
            "label": _activity_fun_short_label(text, keyword_rows),
            "score": round(score, 1),
            "sender": str(row.get("sender", "") or "").strip() or "成员",
            "time": str(row.get("time", "") or "").strip(),
            "text": text,
        }
        if last_score is not None:
            jump = score - last_score
            if jump > max_jump:
                max_jump = jump
                culprit = {
                    "sender": item["sender"],
                    "time": item["time"],
                    "label": item["label"],
                    "text": item["text"],
                    "jump": round(jump, 1),
                }
        last_score = score
        points.append(item)
    note = (
        f"{culprit.get('sender', '某成员')} 把话题往外拐了 {int(round(float(culprit.get('jump', 0) or 0)))} 分"
        if culprit else
        f"主线围绕“{baseline}”缓慢漂移"
    )
    return {
        "note": note,
        "baseline": baseline,
        "points": points,
        "culprit": culprit,
    }


def _activity_fun_build_nutrition(samples):
    rows = [x for x in (samples or []) if isinstance(x, dict)]
    if not rows:
        return {"note": "暂无成分统计", "total": 0, "items": []}
    limit_rows = rows[:160]
    counter = Counter()
    for row in limit_rows:
        counter[_activity_fun_bucket(row.get("text", ""))] += 1
    total = max(1, sum(counter.values()))
    items = []
    for key in ("carb", "protein", "vitamin", "toxin", "fat"):
        meta = ACTIVITY_FUN_BUCKET_META[key]
        count = int(counter.get(key, 0))
        items.append({
            "key": key,
            "label": meta["label"],
            "sub": meta["sub"],
            "emoji": meta["emoji"],
            "color": meta["color"],
            "desc": meta["desc"],
            "count": count,
            "pct": round(count * 100.0 / total, 1),
        })
    items.sort(key=lambda x: (int(x.get("count", 0) or 0), float(x.get("pct", 0.0) or 0.0)), reverse=True)
    top = items[0] if items else {}
    note = f"最近抽样 {len(limit_rows)} 条消息，{top.get('label', '暂无类别')} 占比最高"
    return {"note": note, "total": len(limit_rows), "items": items}


def _activity_fun_build_wingman(network):
    bonds = _build_fun_bonds(network)
    nodes = bonds.get("nodes", []) if isinstance(bonds, dict) else []
    edges = bonds.get("edges", []) if isinstance(bonds, dict) else []
    node_name = {
        str(x.get("id", "") or ""): str(x.get("name", "") or "成员")
        for x in nodes if isinstance(x, dict)
    }
    if not nodes or not edges:
        return {"note": "暂无接话样本", "nodes": [], "top_pair": {}}
    top_edge = edges[0] if isinstance(edges[0], dict) else {}
    source = node_name.get(str(top_edge.get("source", "") or ""), "成员 A")
    target = node_name.get(str(top_edge.get("target", "") or ""), "成员 B")
    return {
        "note": f"最强暗线：{source} ⇄ {target} · 接话强度 {float(top_edge.get('weight', 0) or 0):.1f}",
        "nodes": [
            {
                "id": str(row.get("id", "") or ""),
                "name": str(row.get("name", "") or "成员"),
                "value": float(row.get("value", 0) or 0),
            }
            for row in nodes[:5] if isinstance(row, dict)
        ],
        "top_pair": {
            "source": source,
            "target": target,
            "weight": round(float(top_edge.get("weight", 0) or 0), 1),
            "summary": f"{source} 一抛球，{target} 就更容易接住往下续。这条线比单纯 @ 更像长期形成的群聊默契。",
        },
    }


def _activity_fun_emoji_tokens(text):
    tokens = []
    raw = str(text or "")
    tokens.extend(re.findall(r"\[[^\]]{1,8}\]", raw))
    try:
        tokens.extend(re.findall(r"[😀-🙏🌀-🗿🤌-🫶]", raw))
    except re.error:
        pass
    return tokens[:3]


def _activity_fun_emoji_official(token):
    mapping = {
        "[微笑]": "礼貌微笑，默认表示友好回应",
        "[呲牙]": "咧嘴一笑，通常用于热场",
        "[抱拳]": "感谢 / 拜托 / 辛苦了",
        "[捂脸]": "无奈、尴尬或先认栽",
        "[偷笑]": "我在憋笑或轻微调侃",
        "[旺柴]": "调侃、阴阳或半开玩笑",
        "[裂开]": "事情有点崩",
        "[叹气]": "无奈、失望或轻度疲惫",
        "[发呆]": "短暂无语",
        "🙂": "礼貌微笑",
        "😂": "真的很好笑",
        "😭": "我崩了 / 情绪很满",
        "🙏": "拜托 / 感谢",
        "🤔": "思考、犹豫或试探",
    }
    return mapping.get(str(token or "").strip(), "礼貌回应或情绪补充")


def _activity_fun_emoji_subtext(token, context, influence=0):
    text = str(context or "")
    token = str(token or "").strip()
    if token in ("🤔", "[思考]"):
        if re.search(r"(能|可以|好像|可行|支持|试试|如果)", text):
            return "“这事看起来能做，但我还在脑内试算成本和可行性。”"
        return "“我不是单纯发问号，是在委婉表达‘这事先让我想一下’。”"
    if token in ("[叹气]", "😮‍💨"):
        if re.search(r"(不知道|不会|没法|没招|干啥)", text):
            return "“这事暂时没解，我现在更多是无奈，不是单纯卖惨。”"
        return "“我已经有点累了，这句话里其实带着轻度放弃治疗。”"
    if token in ("[微笑]", "🙂"):
        if influence >= 600:
            return "“我先礼貌一下，但你最好已经意识到这事不太对。”"
        return "“表面在微笑，实际是在尽量把意见说得不那么冲。”"
    if token in ("[旺柴]", "[偷笑]", "😏"):
        return "“我在阴阳，但懒得把那句更直白的话真的打出来。”"
    if token in ("[捂脸]",):
        return "“这事又来了，我已经想把显示器扣上了。”"
    if token in ("[裂开]", "😭"):
        return "“别问，问就是这活又要多返一轮。”"
    return "“表面是个表情，实际是在替这句话补上没说出口的语气。”"


def _activity_fun_build_emoji_decoder(samples, members_table):
    member_map = {
        str(row.get("sender", "") or "").strip(): row
        for row in (members_table or []) if isinstance(row, dict)
    }
    items = []
    seen = set()
    for row in samples or []:
        if not isinstance(row, dict):
            continue
        text = _clean_rich_text(row.get("text", ""))
        if not text:
            continue
        tokens = _activity_fun_emoji_tokens(text)
        if not tokens:
            continue
        sender = str(row.get("sender", "") or "").strip() or "成员"
        token = str(tokens[0] or "").strip()
        key = (sender, token)
        if key in seen:
            continue
        seen.add(key)
        member = member_map.get(sender, {})
        influence = int(member.get("impact_score", 0) or 0)
        items.append({
            "sender": sender,
            "token": token,
            "context": _fun_trim_text(text, limit=56),
            "official": _activity_fun_emoji_official(token),
            "subtext": _activity_fun_emoji_subtext(token, text, influence=influence),
            "confidence": max(82, min(97, 86 + len(token) * 3 + min(influence // 350, 6))),
        })
        if len(items) >= 2:
            break
    note = f"已抓到 {len(items)} 个高语境表情场景" if items else "暂无表情语境"
    return {"note": note, "items": items}


def _activity_fun_build_roles(members_table):
    rows = [x for x in (members_table or []) if isinstance(x, dict)]
    if not rows:
        return {"note": "暂无角色样本", "items": []}
    sorted_rows = sorted(
        rows,
        key=lambda x: (
            int(x.get("impact_score", 0) or 0),
            int(x.get("messages", 0) or 0),
            int(x.get("active_days", 0) or 0),
        ),
        reverse=True,
    )

    def make_card(row, role_key):
        sender = str(row.get("sender", "") or "成员")
        messages = int(row.get("messages", 0) or 0)
        active_days = int(row.get("active_days", 0) or 0)
        impact = int(row.get("impact_score", 0) or 0)
        recent = str(row.get("recent_active_text", "") or "最近有露面")
        link_count = int(row.get("link_count", 0) or 0)
        media_count = int(row.get("media_count", 0) or 0)
        if role_key == "judge":
            return {
                "tone": "cheer",
                "icon": "👏",
                "title": "结果拍板手",
                "member": f"@{sender} 最容易在关键处定调",
                "desc": f"发言不一定最多，但更容易在争议点上给出一句判断，让别人顺着他的口径继续往下聊。",
                "tagline": f"影响力 {impact}，最近 {recent}。",
            }
        if role_key == "linker":
            return {
                "tone": "steady",
                "icon": "🔗",
                "title": "情报投喂官",
                "member": f"@{sender} 在群里负责补链接和补背景",
                "desc": f"本窗口发出 {link_count} 条链接、{media_count} 条媒体消息，像在不断往群里续燃料，而不是单纯跟着刷存在感。",
                "tagline": f"活跃 {active_days} 天，更像稳定补位型成员。",
            }
        if role_key == "steady":
            return {
                "tone": "steady",
                "icon": "🧱",
                "title": "稳定补位王",
                "member": f"@{sender} 更像维持底盘不断线的人",
                "desc": "不是最炸的那个，但只要他在，群聊就不太容易突然塌掉；别人冒完头后，常由他把讨论接平。",
                "tagline": f"活跃 {active_days} 天，累计发言 {messages} 条。",
            }
        return {
            "tone": "melon",
            "icon": "🍉",
            "title": "围观吐槽位",
            "member": f"@{sender} 平时不常说，真有热闹就会上线",
            "desc": "大多数时间像观察员，一旦出现能站队、能吐槽、能接梗的节点，就会精准浮出水面补一句。",
            "tagline": f"最近 {recent}，当前窗口发言 {messages} 条。",
        }

    selected = []
    used_sender = set()
    role_plan = [
        ("judge", lambda r: int(r.get("impact_score", 0) or 0)),
        ("linker", lambda r: int(r.get("link_count", 0) or 0) * 3 + int(r.get("media_count", 0) or 0)),
        ("steady", lambda r: int(r.get("active_days", 0) or 0) * 8 + int(r.get("messages", 0) or 0)),
        ("melon", lambda r: int(r.get("messages", 0) or 0) - int(r.get("impact_score", 0) or 0) // 12),
    ]
    for role_key, score_fn in role_plan:
        candidates = sorted(rows, key=score_fn, reverse=True)
        picked = None
        for row in candidates:
            sender = str(row.get("sender", "") or "").strip()
            if not sender or sender in used_sender:
                continue
            if role_key == "linker" and int(row.get("link_count", 0) or 0) <= 0 and int(row.get("media_count", 0) or 0) <= 1:
                continue
            if role_key == "melon" and int(row.get("recent_active_hours", 0) or 0) < 24:
                continue
            picked = row
            break
        if picked:
            used_sender.add(str(picked.get("sender", "") or "").strip())
            selected.append(make_card(picked, role_key))
    note = f"已识别 {len(selected)} 种群聊角色" if selected else "暂无角色样本"
    return {"note": note, "items": selected[:4]}


def _activity_fun_build_wake(members_table, samples, keyword_rows):
    rows = [x for x in (members_table or []) if isinstance(x, dict)]
    if not rows:
        return {"note": "暂无潜水员样本", "items": []}
    focus_kw = ""
    for row in keyword_rows or []:
        kw = str((row or {}).get("keyword", "") or "").strip()
        if kw:
            focus_kw = kw
            break
    if not focus_kw:
        focus_kw = "当前主线"

    candidates = [
        row for row in rows
        if int(row.get("messages", 0) or 0) >= 6 and int(row.get("recent_active_hours", 0) or 0) >= 48
    ]
    if not candidates:
        candidates = [
            row for row in rows
            if int(row.get("messages", 0) or 0) >= 6
        ]
    candidates.sort(
        key=lambda x: (
            int(x.get("recent_active_hours", 0) or 0),
            int(x.get("impact_score", 0) or 0),
            int(x.get("messages", 0) or 0),
        ),
        reverse=True,
    )
    items = []
    for row in candidates:
        sender = str(row.get("sender", "") or "").strip() or "成员"
        messages = int(row.get("messages", 0) or 0)
        active_days = int(row.get("active_days", 0) or 0)
        recent_hours = int(row.get("recent_active_hours", 0) or 0)
        impact = int(row.get("impact_score", 0) or 0)
        link_count = int(row.get("link_count", 0) or 0)
        media_count = int(row.get("media_count", 0) or 0)
        level = str(row.get("level", "") or "成员")
        if impact >= 600:
            title = "给一个判断题，让他顺手定调"
            strategy = f"直接问“{focus_kw} 这条线现在还值不值得继续做”，比泛泛问近况更容易把他拉回来。"
        elif link_count > 0:
            title = "丢一条新链接，请他补背景"
            strategy = f"给 {sender} 丢一条和“{focus_kw}”相关的新链接，顺手问一句“这条你怎么看”，更容易触发他补资料。"
        elif media_count > 1:
            title = "发一个截图案例，请他点评"
            strategy = f"别空问，把最近一个和“{focus_kw}”相关的截图或案例扔过去，让他做轻点评，响应门槛更低。"
        elif active_days >= 10:
            title = "拿半成品去找他补一刀"
            strategy = f"把还没讲透的“{focus_kw}”半成品甩过去，让他补一句细节，比从 0 开聊更容易把人叫出来。"
        else:
            title = "先抛一个轻问题"
            strategy = f"从“{focus_kw}”切入，给 {sender} 一个只要 1 句话就能回的开口位，不要一上来就让他长篇解释。"
        quote = _activity_fun_sender_quote(samples, sender)
        items.append({
            "name": sender,
            "avatar": sender[:1] or "成",
            "dormant": f"已潜水 {max(1, int(round(recent_hours / 24.0)))} 天" if recent_hours >= 24 else "最近互动偏少",
            "title": title,
            "suggestion": strategy,
            "proof": quote or f"{sender} 当前窗口发言 {messages} 条，最近一次露面是 {row.get('recent_active_text', '较早之前')}。",
            "score": max(48, min(96, 38 + min(impact // 18, 42) + min(recent_hours // 24, 18))),
            "tags": [level, f"活跃 {active_days} 天", f"影响力 {impact}"],
        })
        if len(items) >= 3:
            break
    note = f"已识别 {len(items)} 个优先唤醒对象" if items else "暂无潜水员样本"
    return {"note": note, "items": items}


def _build_activity_fun_cards(base_data, activity_data, members_data, keyword_rows):
    base_data = base_data if isinstance(base_data, dict) else {}
    activity_data = activity_data if isinstance(activity_data, dict) else {}
    members_data = members_data if isinstance(members_data, dict) else {}
    samples = base_data.get("recent_samples", []) if isinstance(base_data.get("recent_samples", []), list) else []
    keyword_rows = keyword_rows if isinstance(keyword_rows, list) else []
    members_table = members_data.get("members_table", []) if isinstance(members_data.get("members_table", []), list) else []
    network = activity_data.get("interaction_network", {}) if isinstance(activity_data.get("interaction_network", {}), dict) else {}
    return {
        "wake": _activity_fun_build_wake(members_table, samples, keyword_rows),
        "roles": _activity_fun_build_roles(members_table),
        "derailment": _activity_fun_build_derailment(samples, keyword_rows),
        "nutrition": _activity_fun_build_nutrition(samples),
        "wingman": _activity_fun_build_wingman(network),
        "emoji_decoder": _activity_fun_build_emoji_decoder(samples, members_table),
    }


def _build_insight_page(base_data, activity_data, members_data, keyword_rows, emoji_pref=None):
    link_sources = base_data.get("link_sources", []) if isinstance(base_data, dict) else []
    normalized_sources = []
    for r in (link_sources or []):
        if not isinstance(r, dict):
            continue
        src_name = _normalize_link_source_name(r.get("source", ""))
        normalized_sources.append({
            "source": src_name or "澶栭儴缃戠珯",
            "count": int(r.get("count", 0) or 0),
            "last_ts": int(r.get("last_ts", 0) or 0),
        })
    normalized_sources.sort(key=lambda x: int(x.get("count", 0) or 0), reverse=True)
    link_sources = normalized_sources
    hot_links = base_data.get("hot_links", []) if isinstance(base_data, dict) else []
    top_senders = base_data.get("top_senders", []) if isinstance(base_data, dict) else []
    summary = base_data.get("summary", {}) if isinstance(base_data, dict) else {}
    trend = base_data.get("trend", []) if isinstance(base_data, dict) else []
    total_messages = int(summary.get("total_messages", 0) or 0)
    active_senders = int(summary.get("active_senders", 0) or 0)
    link_messages = int(summary.get("link_messages", 0) or 0)
    media_messages = int(summary.get("media_messages", 0) or 0)
    system_messages = int(summary.get("system_messages", 0) or 0)
    non_system_messages = max(0, total_messages - system_messages)

    peak_hour = ""
    low_hour = ""
    try:
        hourly = activity_data.get("hourly_distribution", [])
        if hourly:
            row = max(hourly, key=lambda x: int(x.get("workday", 0)) + int(x.get("weekend", 0)))
            peak_hour = str(row.get("hour", ""))
            nz = [
                x for x in hourly
                if (int(x.get("workday", 0)) + int(x.get("weekend", 0))) > 0
            ]
            if nz:
                low = min(nz, key=lambda x: int(x.get("workday", 0)) + int(x.get("weekend", 0)))
                low_hour = str(low.get("hour", ""))
    except Exception:
        peak_hour = ""
        low_hour = ""

    weekly = activity_data.get("weekly_trend", []) if isinstance(activity_data, dict) else []
    wow_desc = ""
    if isinstance(weekly, list) and len(weekly) >= 2:
        a = int(weekly[-1].get("messages", 0) or 0)
        b = int(weekly[-2].get("messages", 0) or 0)
        if b > 0:
            rate = (a - b) * 100.0 / b
            wow_desc = f"最近一周消息量较前一周{'增长' if rate >= 0 else '下降'} {abs(rate):.1f}%（{a}/{b}）。"

    kpis = activity_data.get("kpis", {}) if isinstance(activity_data, dict) else {}
    active_rate_30 = float(kpis.get("active_rate_30d", 0.0) or 0.0)
    dormant_members = int(kpis.get("dormant_members", 0) or 0)

    top3_share = 0.0
    if total_messages > 0 and isinstance(top_senders, list):
        top3 = sum(int((x or {}).get("count", 0) or 0) for x in top_senders[:3])
        top3_share = top3 * 100.0 / max(total_messages, 1)

    rich_ratio = 0.0
    if non_system_messages > 0:
        rich_ratio = (link_messages + media_messages) * 100.0 / non_system_messages

    quality_model = activity_data.get("quality_model", {}) if isinstance(activity_data, dict) else {}
    q_score = int((quality_model or {}).get("score", 0) or 0)
    q_level = str((quality_model or {}).get("level", "") or "").strip()

    bullets = []
    if top_senders:
        t = top_senders[0]
        bullets.append(f"核心发言人：{t.get('sender', '未知')}，当前范围发言 {int(t.get('count', 0))} 条。")
    if active_senders > 0 and total_messages > 0:
        bullets.append(f"整体规模：共 {total_messages} 条消息，活跃发言成员 {active_senders} 人。")
    if active_rate_30 > 0:
        bullets.append(f"成员参与：近30天活跃率 {active_rate_30:.1f}%，沉默成员 {dormant_members} 人。")
    if peak_hour:
        if low_hour and low_hour != peak_hour:
            bullets.append(f"时段节奏：高峰在 {peak_hour}，低谷在 {low_hour}，可据此安排重点互动。")
        else:
            bullets.append(f"高峰时段：{peak_hour} 左右消息最密集，可用于安排重点话题。")
    if top3_share > 0:
        bullets.append(f"发言集中度：TOP3 成员贡献 {top3_share:.1f}% 消息。")
    if rich_ratio > 0:
        bullets.append(f"内容形态：媒体+链接消息占非系统消息 {rich_ratio:.1f}%。")
    if wow_desc:
        bullets.append(wow_desc)
    if link_sources:
        known_src = next(
            (
                x for x in link_sources
                if _normalize_link_source_name(x.get("source", "")).strip() not in ("其他",)
            ),
            None,
        )
        if known_src:
            src_name = _normalize_link_source_name(known_src.get("source", "")) or "外部网站"
            bullets.append(f"链接来源偏好：{src_name} 占比最高（{int(known_src.get('count', 0))} 条）。")
    clean_keywords = [
        k for k in (keyword_rows or [])
        if not _is_noise_keyword(str(k.get("keyword", "")))
    ]
    emoji_pref = emoji_pref if isinstance(emoji_pref, dict) else {}
    emoji_cloud = emoji_pref.get("cloud", []) if isinstance(emoji_pref.get("cloud", []), list) else []
    emoji_stickers = emoji_pref.get("stickers", []) if isinstance(emoji_pref.get("stickers", []), list) else []
    if clean_keywords:
        kw = clean_keywords[0]
        bullets.append(f"近期高频关键词：{kw.get('keyword', '')}（{int(kw.get('count', 0))} 次）。")
    if emoji_cloud:
        emo = emoji_cloud[0]
        bullets.append(f"常用表情：[{emo.get('label', '')}] 出现 {int(emo.get('count', 0))} 次。")
    if q_score > 0:
        bullets.append(f"内容质量评分：{q_score} 分（{q_level or '待评估'}）。")
    if not bullets:
        bullets.append("当前时间范围数据较少，建议放宽日期后再分析。")

    type_trend = []
    if isinstance(trend, list):
        for r in trend:
            text_c = int((r or {}).get("text", 0) or 0)
            media_c = int((r or {}).get("media", 0) or 0)
            link_c = int((r or {}).get("link", 0) or 0)
            system_c = int((r or {}).get("system", 0) or 0)
            total_c = int((r or {}).get("total", 0) or 0)
            other_c = max(0, total_c - text_c - media_c - link_c - system_c)
            type_trend.append({
                "date": str((r or {}).get("date", "") or ""),
                "text": text_c,
                "media": media_c,
                "link": link_c,
                "system": system_c,
                "other": other_c,
                "total": total_c,
            })

    contributor_top = []
    if isinstance(top_senders, list):
        for idx, row in enumerate(top_senders[:12], start=1):
            c = int((row or {}).get("count", 0) or 0)
            if c <= 0:
                continue
            share = (c * 100.0 / max(total_messages, 1)) if total_messages > 0 else 0.0
            contributor_top.append({
                "rank": idx,
                "sender": str((row or {}).get("sender", "") or "未知成员"),
                "count": c,
                "share": round(share, 2),
            })

    fun_insights = _build_fun_insights(base_data, activity_data, members_data, clean_keywords)

    return {
        "bullets": bullets[:10],
        "keywords": clean_keywords[:120] if isinstance(clean_keywords, list) else [],
        "emoji_cloud": emoji_cloud[:80],
        "emoji_stickers": emoji_stickers[:24],
        "quality_model": quality_model if isinstance(quality_model, dict) else {},
        "link_sources": link_sources[:20] if isinstance(link_sources, list) else [],
        "hot_links": hot_links[:50] if isinstance(hot_links, list) else [],
        "summary": {
            "total_messages": total_messages,
            "link_messages": link_messages,
            "media_messages": media_messages,
            "active_senders": active_senders,
            "active_rate_30d": round(active_rate_30, 1),
            "rich_ratio": round(rich_ratio, 2),
            "top3_share": round(top3_share, 2),
        },
        "top_senders": top_senders[:20] if isinstance(top_senders, list) else [],
        "trend": trend if isinstance(trend, list) else [],
        "type_trend": type_trend,
        "contributor_top": contributor_top,
        "weekly_trend": weekly if isinstance(weekly, list) else [],
        "fun_insights": fun_insights,
    }


def _build_score_page(username, start_ts, end_ts, sender_rows):
    username = str(username or "").strip()
    rule_map = {str(r.get("id", "")): r for r in ANALYSIS_SCORE_RULES}
    manual_rows = _manual_score_list(username=username, start_ts=start_ts, end_ts=end_ts)

    by_sender = {}
    for s in sender_rows:
        sid = str(s.get("sender_id", "") or "").strip()
        if not sid:
            continue
        daily_counts = list((s.get("daily", {}) or {}).values())
        msg_once_points = sum(min(int(c or 0), 5) for c in daily_counts)
        day_ge5_points = sum(1 for c in daily_counts if int(c or 0) >= 5) * 5
        active_days = int(s.get("active_days", 0) or 0)
        month_points = 20 if active_days >= 12 else 0
        year_points = 30 if active_days >= 120 else 0
        auto_total = int(msg_once_points + day_ge5_points + month_points + year_points)
        by_sender[sid] = {
            "sender_id": sid,
            "sender": s.get("sender", sid),
            "messages": int(s.get("count", 0) or 0),
            "active_days": active_days,
            "last_ts": int(s.get("last_ts", 0) or 0),
            "auto_points": auto_total,
            "manual_points": 0,
            "total_points": auto_total,
            "auto_breakdown": [
                {"rule_id": "r_msg_once", "label": "发言 1 次（日封顶）", "points": int(msg_once_points)},
                {"rule_id": "r_day_ge5", "label": "单日发言 >= 5 次", "points": int(day_ge5_points)},
                {"rule_id": "r_month_ge12", "label": "30天发言天数 >= 12", "points": int(month_points)},
                {"rule_id": "r_year_ge120", "label": "365天发言天数 >= 120", "points": int(year_points)},
            ],
            "manual_items": [],
        }

    manual_by_rule = Counter()
    for m in manual_rows:
        sid = str(m.get("sender_id", "") or "").strip()
        if not sid:
            continue
        obj = by_sender.get(sid)
        if not obj:
            obj = {
                "sender_id": sid,
                "sender": str(m.get("sender", sid) or sid),
                "messages": 0,
                "active_days": 0,
                "last_ts": int(m.get("ts", 0) or 0),
                "auto_points": 0,
                "manual_points": 0,
                "total_points": 0,
                "auto_breakdown": [],
                "manual_items": [],
            }
            by_sender[sid] = obj
        pts = int(m.get("points", 0) or 0)
        obj["manual_points"] = int(obj.get("manual_points", 0) or 0) + pts
        obj["total_points"] = int(obj.get("total_points", 0) or 0) + pts
        ts = int(m.get("ts", 0) or 0)
        if ts > int(obj.get("last_ts", 0) or 0):
            obj["last_ts"] = ts
        rule_id = str(m.get("rule_id", "") or "").strip()
        manual_by_rule[rule_id] += pts
        rule_obj = rule_map.get(rule_id, {})
        obj["manual_items"].append({
            "id": m.get("id", ""),
            "rule_id": rule_id,
            "rule_name": rule_obj.get("name", rule_id),
            "points": pts,
            "note": m.get("note", ""),
            "ts": ts,
            "created_at": int(m.get("created_at", 0) or 0),
        })

    leaderboard = list(by_sender.values())
    leaderboard.sort(
        key=lambda x: (
            int(x.get("total_points", 0) or 0),
            int(x.get("manual_points", 0) or 0),
            int(x.get("messages", 0) or 0),
        ),
        reverse=True
    )
    for i, row in enumerate(leaderboard, start=1):
        row["rank"] = i

    return {
        "rules": ANALYSIS_SCORE_RULES,
        "leaderboard": leaderboard[:300],
        "manual_entries": manual_rows[:5000],
        "manual_rule_points": [
            {
                "rule_id": k,
                "rule_name": rule_map.get(k, {}).get("name", k),
                "points": int(v),
            }
            for k, v in manual_by_rule.most_common()
        ],
    }


def _build_analysis_full(username, start_ts=0, end_ts=0, link_limit=12000):
    username = str(username or "").strip()
    if not username:
        raise RuntimeError("missing username")

    # Version suffix to avoid serving stale data after classification-rule updates.
    cache_key = f"full:v15:{username}:{int(start_ts or 0)}:{int(end_ts or 0)}:{int(link_limit or 0)}"
    cached = _analysis_cache_get(cache_key)
    if cached:
        return cached

    base = _build_chat_analysis(
        username=username,
        start_ts=start_ts,
        end_ts=end_ts,
        link_limit=link_limit,
    )
    sender_rows = _collect_sender_activity(username=username, start_ts=start_ts, end_ts=end_ts)
    keyword_rows = _collect_keyword_stats(username=username, start_ts=start_ts, end_ts=end_ts, limit=min(max(int(link_limit or 10000), 3000), 20000))
    emoji_pref = _collect_emoji_preferences(username=username, start_ts=start_ts, end_ts=end_ts, limit=min(max(int(link_limit or 10000), 4000), 24000))

    activity_page = _build_activity_page(base, sender_rows, start_ts=start_ts, end_ts=end_ts)
    members_page = _build_members_page(base, sender_rows, start_ts=start_ts, end_ts=end_ts)
    interaction_network = _build_interaction_network(
        username=username,
        sender_rows=sender_rows,
        start_ts=start_ts,
        end_ts=end_ts,
    )
    if isinstance(activity_page, dict):
        activity_page["interaction_network"] = interaction_network
        activity_page["fun_cards"] = _build_activity_fun_cards(base, activity_page, members_page, keyword_rows)
    insight_page = _build_insight_page(base, activity_page, members_page, keyword_rows, emoji_pref=emoji_pref)
    score_page = _build_score_page(username, start_ts, end_ts, sender_rows)

    data = {
        "analysis_version": "v15",
        "generated_at": int(time.time()),
        "username": base.get("username", username),
        "chat": base.get("chat", username),
        "is_group": bool(base.get("is_group", False)),
        "range": base.get("range", {"start_ts": int(start_ts or 0), "end_ts": int(end_ts or 0)}),
        "overview": {
            "summary": base.get("summary", {}),
            "trend": base.get("trend", []),
            "by_type": base.get("by_type", []),
            "top_senders": base.get("top_senders", []),
            "heatmap": base.get("heatmap", []),
            "link_sources": base.get("link_sources", []),
            "hot_links": base.get("hot_links", []),
            "members": base.get("members", []),
            "recent_samples": base.get("recent_samples", []),
        },
        "activity": activity_page,
        "members": members_page,
        "insight": insight_page,
        "score": score_page,
        "ai": {
            "hint": "使用当前 AI 配置，可针对当前会话和时间范围直接提问。",
            "context": {
                "username": base.get("username", username),
                "chat": base.get("chat", username),
                "start_ts": int(base.get("range", {}).get("start_ts", 0) or 0),
                "end_ts": int(base.get("range", {}).get("end_ts", 0) or 0),
            },
        },
    }
    _analysis_cache_set(cache_key, data)
    return data


MEMBER_TAROT_MAJOR_ARCANA = [
    ("愚者", "The Fool"),
    ("魔术师", "The Magician"),
    ("女祭司", "The High Priestess"),
    ("皇后", "The Empress"),
    ("皇帝", "The Emperor"),
    ("教皇", "The Hierophant"),
    ("恋人", "The Lovers"),
    ("战车", "The Chariot"),
    ("力量", "Strength"),
    ("隐者", "The Hermit"),
    ("命运之轮", "Wheel of Fortune"),
    ("正义", "Justice"),
    ("倒吊人", "The Hanged Man"),
    ("死神", "Death"),
    ("节制", "Temperance"),
    ("恶魔", "The Devil"),
    ("高塔", "The Tower"),
    ("星星", "The Star"),
    ("月亮", "The Moon"),
    ("太阳", "The Sun"),
    ("审判", "Judgement"),
    ("世界", "The World"),
]


def _resolve_member_target(full_data, sender_id="", sender_name=""):
    members = (((full_data or {}).get("members", {}) or {}).get("members_table", []))
    if not isinstance(members, list):
        members = []
    sid = str(sender_id or "").strip()
    sname = str(sender_name or "").strip()
    if sid:
        for row in members:
            if not isinstance(row, dict):
                continue
            if str(row.get("sender_id", "") or "").strip() == sid:
                return row
        for row in members:
            if not isinstance(row, dict):
                continue
            if str(row.get("sender", "") or "").strip() == sid:
                return row
    if sname:
        for row in members:
            if not isinstance(row, dict):
                continue
            if str(row.get("sender", "") or "").strip() == sname:
                return row
        low = sname.lower()
        for row in members:
            if not isinstance(row, dict):
                continue
            name = str(row.get("sender", "") or "").strip()
            if low and low in name.lower():
                return row
    return members[0] if members else {}


def _draw_member_tarot(seed_value="", ref_ts=0):
    now_dt = datetime.fromtimestamp(int(ref_ts or time.time()))
    iso_year, iso_week, _ = now_dt.isocalendar()
    scope = f"{seed_value}|{iso_year}-W{iso_week}"
    digest = hashlib.sha1(scope.encode("utf-8")).hexdigest()
    idx = int(digest[:8], 16) % len(MEMBER_TAROT_MAJOR_ARCANA)
    orientation = "逆位" if (int(digest[8:12], 16) % 2) else "正位"
    name_cn, name_en = MEMBER_TAROT_MAJOR_ARCANA[idx]
    return {
        "week_key": f"{iso_year}-W{iso_week}",
        "name": name_cn,
        "name_en": name_en,
        "orientation": orientation,
    }


MEMBER_DOMAIN_TERM_MAP = {
    "tech": [
        "api", "sdk", "token", "prompt", "bug", "fix", "python", "java", "js",
        "前端", "后端", "接口", "部署", "模型", "代码", "脚本", "数据库", "测试", "版本",
        "兼容", "服务器", "训练", "推理", "算法", "工程", "开发",
    ],
    "ops": [
        "报名", "活动", "直播", "预约", "社群", "海报", "素材", "拉群", "转发",
        "排期", "发布", "预告", "主持", "嘉宾", "运营", "群发", "宣发",
    ],
    "business": [
        "客户", "甲方", "老板", "需求", "方案", "报价", "预算", "合同", "项目",
        "对接", "回款", "商务", "交付", "排期", "上线", "汇报", "复盘",
    ],
    "study": [
        "论文", "实验", "导师", "老师", "研究", "课题", "华科", "实验室",
        "复现", "作业", "数据集", "答辩", "学长", "学姐", "保研", "研究生",
    ],
    "content": [
        "公众号", "推文", "文章", "文案", "标题", "封面", "视频", "剪辑",
        "小红书", "b站", "截图", "链接", "笔记", "分享",
    ],
    "social": [
        "哈哈", "笑死", "离谱", "抽象", "奶龙", "摸鱼", "八卦", "吃饭",
        "聚餐", "下班", "emo", "无语", "崩了", "寄了",
    ],
}


MEMBER_MBTI_LABELS = {
    "INTJ": "战略控场型",
    "INTP": "冷面分析型",
    "ENTJ": "推进指挥型",
    "ENTP": "拆招起哄型",
    "INFJ": "洞察定调型",
    "INFP": "情绪共振型",
    "ENFJ": "场面统筹型",
    "ENFP": "氛围点火型",
    "ISTJ": "执行清单型",
    "ISFJ": "稳定补位型",
    "ESTJ": "结果总管型",
    "ESFJ": "关系润滑型",
    "ISTP": "问题修补型",
    "ISFP": "慢热表达型",
    "ESTP": "现场冲锋型",
    "ESFP": "热场输出型",
}


def _member_hash_pick(options, seed_value="", salt=""):
    seq = [item for item in (options or []) if item not in (None, "", [], {})]
    if not seq:
        return None
    raw = f"{seed_value}|{salt}"
    digest = hashlib.sha1(raw.encode("utf-8")).hexdigest()
    idx = int(digest[:8], 16) % len(seq)
    return seq[idx]


def _is_generic_member_phrase(text):
    seg = re.sub(r"\s+", "", str(text or "").strip())
    if not seg:
        return True
    low = seg.lower()
    if _is_noise_keyword(seg):
        return True
    if re.fullmatch(r"\[[^\]]{1,10}\]", seg):
        return True
    if re.fullmatch(r"[\W_]+", seg):
        return True
    if re.fullmatch(r"(哈|哈哈|哈哈哈|哈哈哈哈|呵|嘿|哇|啊|呀|嗯|哦|喔|欸|诶|呃|额|啦|嘛)+", seg):
        return True
    if re.fullmatch(r"(ha)+|h{2,}|233+|6{3,}|yyds|ok+|wow+", low):
        return True
    if len(set(seg)) <= 2 and len(seg) >= 5:
        return True
    if seg in {
        "收到", "好的", "可以", "行", "行吧", "没问题", "是的", "对", "对对对",
        "确实", "哈哈", "哈哈哈", "笑死", "牛", "牛啊", "绝了", "好家伙",
        "有道理", "懂了", "明白", "嗯嗯", "哦哦", "ok", "OK", "位置",
        "图片", "表情", "语音", "视频", "链接", "文件",
    }:
        return True
    return False


def _member_domain_scores(keywords, quotes):
    key_rows = [str(x or "").strip() for x in (keywords or []) if str(x or "").strip()]
    quote_rows = [str(x or "").strip() for x in (quotes or []) if str(x or "").strip()]
    scores = {k: 0 for k in MEMBER_DOMAIN_TERM_MAP.keys()}
    for token in key_rows:
        low = token.lower()
        for domain, terms in MEMBER_DOMAIN_TERM_MAP.items():
            if any(term in low or term in token for term in terms):
                scores[domain] += 3
    quote_blob = " ".join(quote_rows)
    quote_low = quote_blob.lower()
    for domain, terms in MEMBER_DOMAIN_TERM_MAP.items():
        for term in terms:
            if term in quote_low or term in quote_blob:
                scores[domain] += 1
    return scores


def _collect_member_feature_pack(username, sender_id="", sender_name="", start_ts=0, end_ts=0, limit=2600):
    username = str(username or "").strip()
    sender_id = str(sender_id or "").strip()
    sender_name = str(sender_name or "").strip()
    out = {
        "sender_id": sender_id,
        "sender": sender_name or sender_id or "成员",
        "messages": 0,
        "text_messages": 0,
        "link_messages": 0,
        "media_messages": 0,
        "active_days": 0,
        "avg_length": 0.0,
        "question_ratio": 0.0,
        "exclamation_ratio": 0.0,
        "night_ratio": 0.0,
        "link_ratio": 0.0,
        "media_ratio": 0.0,
        "mention_ratio": 0.0,
        "laugh_ratio": 0.0,
        "long_text_ratio": 0.0,
        "peak_hour": -1,
        "hourly": [{"hour": h, "count": 0} for h in range(24)],
        "keywords": [],
        "catchphrases": [],
        "sample_quotes": [],
        "samples": [],
        "activity_buckets": {"late_night": 0, "morning": 0, "afternoon": 0, "evening": 0},
        "stats": {},
    }
    if not username:
        return out

    db_path, table_name = _find_msg_table_for_user(username, ensure_fresh=True)
    if not db_path or not table_name:
        return out
    try:
        refresh_decrypted_message_db(db_path)
    except Exception as e:
        print(f"[member-profile] refresh failed: {e}", flush=True)

    contact_names = load_contact_names()
    is_group = "@chatroom" in username
    rows = []
    rowid_sender_map = {}
    rid_target = None
    safe_rows = None
    query_limit = min(max(int(limit or 0), 900), 6000)
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        try:
            cols = {
                str(r[1]).lower()
                for r in conn.execute(f"PRAGMA table_info([{table_name}])").fetchall()
                if len(r) >= 2
            }
            has_sender = "real_sender_id" in cols
            has_status = "status" in cols
            has_source = "source" in cols
            status_expr = "status" if has_status else "0"
            rowid_sender_map = _load_name2id_rowid_map(conn) if (is_group and has_sender) else {}
            reverse_sender_map = {uname: rid for rid, uname in rowid_sender_map.items()}
            if is_group and has_sender:
                if sender_id.startswith("rid:"):
                    try:
                        rid_target = int(sender_id.split(":", 1)[1])
                    except Exception:
                        rid_target = None
                elif sender_id and sender_id in reverse_sender_map:
                    rid_target = reverse_sender_map.get(sender_id)

            where_clauses = []
            where_params = []
            if start_ts:
                where_clauses.append("create_time >= ?")
                where_params.append(int(start_ts))
            if end_ts:
                where_clauses.append("create_time <= ?")
                where_params.append(int(end_ts))
            if rid_target is not None:
                where_clauses.append("real_sender_id = ?")
                where_params.append(int(rid_target))
            elif (not is_group) and sender_id == "__self__":
                where_clauses.append(f"{status_expr} = 2")
            where_sql = (" WHERE " + " AND ".join(where_clauses)) if where_clauses else ""
            rows = conn.execute(
                f"""
                SELECT
                  create_time,
                  (local_type & 4294967295) AS msg_type,
                  message_content,
                  {"real_sender_id" if has_sender else "0 AS real_sender_id"},
                  {status_expr} AS status,
                  {"source" if has_source else "'' AS source"}
                FROM [{table_name}]
                {where_sql}
                ORDER BY create_time DESC
                LIMIT ?
                """,
                tuple(where_params + [int(query_limit)]),
            ).fetchall()
        finally:
            conn.close()
    except (sqlite3.DatabaseError, sqlite3.OperationalError) as e:
        if not _is_recoverable_message_query_error(e):
            raise
        print(f"[member-profile] safe fallback due db error: {e}", flush=True)
        _, rowid_sender_map, safe_rows = _load_message_rows_safe(
            db_path,
            table_name,
            start_ts=start_ts,
            end_ts=end_ts,
            limit=min(max(query_limit * 3, 3600), 24000),
            newest_first=True,
        )

    processed = []
    iterable_rows = rows
    if safe_rows is not None:
        iterable_rows = [
            (
                int((row or {}).get("timestamp", 0) or 0),
                _normalize_msg_type((row or {}).get("local_type", 0)),
                (row or {}).get("content", ""),
                _safe_int((row or {}).get("real_sender_id", 0), 0, 0, 0),
                _safe_int((row or {}).get("status", 0), 0, 0, 0),
                (row or {}).get("source", ""),
            )
            for row in safe_rows
        ]

    keyword_counter = Counter()
    phrase_counter = Counter()
    unique_texts = set()
    question_hits = 0
    exclamation_hits = 0
    command_hits = 0
    blame_hits = 0
    soft_hits = 0
    emo_hits = 0
    laugh_hits = 0
    mention_hits = 0
    hesitation_hits = 0
    deadline_hits = 0
    self_drive_hits = 0
    agreement_hits = 0
    long_hits = 0
    total_length = 0
    total_text_rows = 0
    hourly = [0] * 24
    active_days = set()
    bucket_counts = {"late_night": 0, "morning": 0, "afternoon": 0, "evening": 0}
    all_user_messages = 0
    text_messages = 0
    link_messages = 0
    media_messages = 0

    for ts, msg_type, content, real_sender_id, status, source_blob in iterable_rows:
        ts = int(ts or 0)
        msg_type = _normalize_msg_type(msg_type)
        sender_username = rowid_sender_map.get(int(real_sender_id), "") if isinstance(real_sender_id, int) else ""
        text = content if isinstance(content, str) else ""
        if (not text.strip()) and isinstance(content, (bytes, bytearray)):
            text = _extract_text_from_message_blob(content, msg_type)
        if is_group and text:
            p_sender, p_body = _parse_group_sender_prefix(text)
            if p_sender:
                if not sender_username:
                    sender_username = p_sender
                text = p_body
        sender_id_resolved, sender_name_resolved = _analysis_sender_for_row(
            is_group, status, sender_username, username, contact_names
        )
        if sender_id:
            if str(sender_id_resolved or "").strip() != sender_id and str(sender_name_resolved or "").strip() != sender_name:
                continue
        elif sender_name and str(sender_name_resolved or "").strip() != sender_name:
            continue

        if msg_type in (10000, 10002):
            continue
        if ts > 0:
            dt = datetime.fromtimestamp(ts)
            hour = int(dt.hour)
            hourly[hour] += 1
            active_days.add(dt.strftime("%Y-%m-%d"))
            if 0 <= hour < 6:
                bucket_counts["late_night"] += 1
            elif hour < 12:
                bucket_counts["morning"] += 1
            elif hour < 18:
                bucket_counts["afternoon"] += 1
            else:
                bucket_counts["evening"] += 1
        all_user_messages += 1
        if msg_type == 1:
            text_messages += 1
        elif msg_type == 49:
            link_messages += 1
        elif msg_type in (3, 47, 43, 34):
            media_messages += 1

        rendered = _render_link_or_quote_text(msg_type, text, source_blob)
        rendered = _sanitize_link_text(rendered)
        rendered = _fallback_content_by_type(msg_type, rendered)
        clean = _clean_rich_text(rendered)
        if not clean or _is_text_garbled(clean):
            continue
        if clean in ("[文本]", "[链接/文件]", "[图片]", "[表情]", "[语音]", "[视频]"):
            continue
        if _looks_noise_text(clean):
            continue
        if len(clean) > 320:
            clean = clean[:320] + "..."

        row_obj = {
            "ts": ts,
            "time": datetime.fromtimestamp(ts).strftime("%m-%d %H:%M") if ts else "",
            "text": clean,
            "type": format_msg_type(msg_type),
        }
        processed.append(row_obj)
        text_key = clean.strip()
        if text_key and text_key not in unique_texts:
            unique_texts.add(text_key)

        total_text_rows += 1
        total_length += len(clean)
        if "?" in clean or "？" in clean:
            question_hits += 1
        if "!" in clean or "！" in clean:
            exclamation_hits += 1
        if len(clean) >= 36:
            long_hits += 1
        if re.search(r"(尽快|直接|马上|先|同步|安排|给我|需要|必须|就按|先别|先把)", clean):
            command_hits += 1
        if re.search(r"(为什么还没|这个怎么还|不是说了|谁来背|这锅|先解释一下)", clean):
            blame_hits += 1
        if re.search(r"(谢谢|辛苦|哈哈|确实|可以|好的|收到|麻烦)", clean):
            soft_hits += 1
        if re.search(r"(崩|裂|寄了|离谱|emo|无语|疯了|麻了)", clean, flags=re.IGNORECASE):
            emo_hits += 1
        if re.search(r"(哈哈+|233+|hhh+|笑死|绷不住|笑疯|乐死|笑麻了)", clean, flags=re.IGNORECASE):
            laugh_hits += 1
        if "@" in clean:
            mention_hits += len(re.findall(r"@[^@\s\u2005]{1,16}", clean))
        if re.search(r"(要不|是不是|感觉|可能|也许|大概|先看看|我猜)", clean):
            hesitation_hits += 1
        if re.search(r"(今天|今晚|明天|本周|这周|尽快|截止|ddl|deadline|下午|上午|这个月)", clean, flags=re.IGNORECASE):
            deadline_hits += 1
        if re.search(r"(我来|我先|我补|我处理|我跟进|我发|我改|我看看|我去对一下)", clean):
            self_drive_hits += 1
        if re.search(r"(确实|对对对|是的|收到|ok|好的|可以|没问题|行|明白)", clean, flags=re.IGNORECASE):
            agreement_hits += 1

        seen_keywords = set()
        for token in _extract_keyword_candidates(clean):
            tok = str(token or "").strip()
            if not tok or tok in seen_keywords or _is_noise_keyword(tok):
                continue
            seen_keywords.add(tok)
            keyword_counter[tok] += 1

        for piece in re.split(r"[，。！？!?；;、…\n]+", clean):
            seg = re.sub(r"\s+", " ", str(piece or "")).strip(" 　")
            if not seg or len(seg) < 2 or len(seg) > 18:
                continue
            if re.fullmatch(r"[\d\W_]+", seg):
                continue
            if _is_noise_keyword(seg) or _is_generic_member_phrase(seg):
                continue
            phrase_counter[seg] += 1

    processed.sort(key=lambda x: int(x.get("ts", 0) or 0))
    total_messages = max(all_user_messages, len(processed))
    peak_hour = 0
    if any(hourly):
        peak_hour = max(range(24), key=lambda h: hourly[h])
    sample_rows = []
    if processed:
        limit_samples = min(72, len(processed))
        if len(processed) <= limit_samples:
            sample_rows = processed[:]
        else:
            used = set()
            for i in range(limit_samples):
                idx = int(round(i * (len(processed) - 1) / max(1, limit_samples - 1)))
                used.add(idx)
            sample_rows = [processed[i] for i in sorted(used)]

    keyword_rows = []
    for token, count in keyword_counter.most_common(18):
        keyword_rows.append({"keyword": token, "count": int(count)})
    keyword_refs = [str(x.get("keyword", "") or "") for x in keyword_rows[:8] if isinstance(x, dict)]
    phrase_rows = []
    min_phrase = 2 if len(processed) >= 24 else 1
    phrase_candidates = []
    for token, count in phrase_counter.items():
        tok = str(token or "").strip()
        if int(count) < min_phrase or _is_generic_member_phrase(tok):
            continue
        score = int(count) * 6 + min(len(tok), 14)
        if any(ref and ref in tok for ref in keyword_refs):
            score += 4
        phrase_candidates.append((score, int(count), tok))
    phrase_candidates.sort(key=lambda x: (x[0], x[1], len(x[2])), reverse=True)
    for _score, count, token in phrase_candidates[:12]:
        phrase_rows.append({"text": token, "count": int(count)})

    quote_rows = []
    quote_seen = set()
    quote_candidates = []
    for idx, row in enumerate(processed):
        text = str(row.get("text", "") or "").strip()
        if not text or text in quote_seen or len(text) < 6:
            continue
        score = 0
        if 8 <= len(text) <= 72:
            score += 5
        elif len(text) <= 120:
            score += 3
        score += min(2, sum(1 for ref in keyword_refs if ref and ref in text)) * 3
        if re.search(r"(哈哈+|笑死|离谱|为什么|怎么|必须|尽快|先|我来|我补|报名|客户|方案|接口|bug|论文|实验)", text, flags=re.IGNORECASE):
            score += 3
        if any(mark in text for mark in ("？", "?", "！", "!", "。")):
            score += 1
        score += min(idx / max(len(processed), 1), 1.0)
        quote_candidates.append((score, int(row.get("ts", 0) or 0), row))
    quote_candidates.sort(key=lambda x: (x[0], x[1]), reverse=True)
    for _score, _ts, row in quote_candidates:
        text = str(row.get("text", "") or "").strip()
        if text in quote_seen:
            continue
        quote_seen.add(text)
        quote_rows.append({"time": row.get("time", ""), "text": text})
        if len(quote_rows) >= 8:
            break

    out.update({
        "messages": int(total_messages),
        "text_messages": int(text_messages),
        "link_messages": int(link_messages),
        "media_messages": int(media_messages),
        "active_days": int(len(active_days)),
        "avg_length": round((float(total_length) / max(1, total_text_rows)), 2),
        "question_ratio": round(float(question_hits) / max(1, total_text_rows), 4),
        "exclamation_ratio": round(float(exclamation_hits) / max(1, total_text_rows), 4),
        "night_ratio": round(float(bucket_counts["late_night"]) / max(1, total_messages), 4),
        "link_ratio": round(float(link_messages) / max(1, total_messages), 4),
        "media_ratio": round(float(media_messages) / max(1, total_messages), 4),
        "mention_ratio": round(float(mention_hits) / max(1, total_text_rows), 4),
        "laugh_ratio": round(float(laugh_hits) / max(1, total_text_rows), 4),
        "long_text_ratio": round(float(long_hits) / max(1, total_text_rows), 4),
        "peak_hour": int(peak_hour),
        "hourly": [{"hour": h, "count": int(hourly[h])} for h in range(24)],
        "keywords": keyword_rows,
        "catchphrases": phrase_rows,
        "sample_quotes": quote_rows,
        "samples": sample_rows,
        "activity_buckets": {k: int(v) for k, v in bucket_counts.items()},
        "stats": {
            "command_hits": int(command_hits),
            "blame_hits": int(blame_hits),
            "soft_hits": int(soft_hits),
            "emo_hits": int(emo_hits),
            "question_hits": int(question_hits),
            "exclamation_hits": int(exclamation_hits),
            "laugh_hits": int(laugh_hits),
            "mention_hits": int(mention_hits),
            "hesitation_hits": int(hesitation_hits),
            "deadline_hits": int(deadline_hits),
            "self_drive_hits": int(self_drive_hits),
            "agreement_hits": int(agreement_hits),
            "long_hits": int(long_hits),
        },
    })
    return out


def _build_member_deep_profile_fallback(full_data, member_row, feature_pack):
    member_row = member_row if isinstance(member_row, dict) else {}
    feature_pack = feature_pack if isinstance(feature_pack, dict) else {}
    sender_name = str(member_row.get("sender", "") or feature_pack.get("sender", "") or "成员").strip() or "成员"
    sender_id = str(member_row.get("sender_id", "") or feature_pack.get("sender_id", "") or sender_name).strip()
    impact = int(member_row.get("impact_score", 0) or 0)
    active_days = int(member_row.get("active_days", 0) or feature_pack.get("active_days", 0) or 0)
    messages = int(member_row.get("month_messages", member_row.get("messages", 0)) or feature_pack.get("messages", 0) or 0)
    recent_text = str(member_row.get("recent_active_text", "") or "").strip() or "近期未捕捉到明显动作"
    recent_hours = int(member_row.get("recent_active_hours", 0) or 0)
    level_label = str(member_row.get("level", "") or "").strip() or "成员"
    peak_hour = int(feature_pack.get("peak_hour", -1) or -1)
    peak_hour = peak_hour if peak_hour >= 0 else 15
    question_ratio = float(feature_pack.get("question_ratio", 0.0) or 0.0)
    exclamation_ratio = float(feature_pack.get("exclamation_ratio", 0.0) or 0.0)
    night_ratio = float(feature_pack.get("night_ratio", 0.0) or 0.0)
    link_ratio = float(feature_pack.get("link_ratio", 0.0) or 0.0)
    media_ratio = float(feature_pack.get("media_ratio", 0.0) or 0.0)
    mention_ratio = float(feature_pack.get("mention_ratio", 0.0) or 0.0)
    laugh_ratio = float(feature_pack.get("laugh_ratio", 0.0) or 0.0)
    long_text_ratio = float(feature_pack.get("long_text_ratio", 0.0) or 0.0)
    avg_length = float(feature_pack.get("avg_length", 0.0) or 0.0)
    stats = feature_pack.get("stats", {}) if isinstance(feature_pack.get("stats", {}), dict) else {}
    command_hits = int(stats.get("command_hits", 0) or 0)
    blame_hits = int(stats.get("blame_hits", 0) or 0)
    soft_hits = int(stats.get("soft_hits", 0) or 0)
    emo_hits = int(stats.get("emo_hits", 0) or 0)
    question_hits = int(stats.get("question_hits", 0) or 0)
    exclamation_hits = int(stats.get("exclamation_hits", 0) or 0)
    laugh_hits = int(stats.get("laugh_hits", 0) or 0)
    mention_hits = int(stats.get("mention_hits", 0) or 0)
    hesitation_hits = int(stats.get("hesitation_hits", 0) or 0)
    deadline_hits = int(stats.get("deadline_hits", 0) or 0)
    self_drive_hits = int(stats.get("self_drive_hits", 0) or 0)
    agreement_hits = int(stats.get("agreement_hits", 0) or 0)
    long_hits = int(stats.get("long_hits", 0) or 0)
    catchphrases = [str(x.get("text", "") or "") for x in feature_pack.get("catchphrases", [])[:8] if isinstance(x, dict)]
    catchphrases = [x for x in catchphrases if x and not _is_generic_member_phrase(x)]
    top_keywords = [str(x.get("keyword", "") or "") for x in feature_pack.get("keywords", [])[:10] if isinstance(x, dict)]
    top_keywords = [x for x in top_keywords if x]
    quotes = [str(x.get("text", "") or "") for x in feature_pack.get("sample_quotes", [])[:6] if isinstance(x, dict)]
    quotes = [x for x in quotes if x]
    tarot = _draw_member_tarot(sender_id or sender_name, int(time.time()))
    focus_keyword = next((x for x in top_keywords if len(str(x or "").strip()) >= 2), "")
    focus_quote = next((x for x in quotes if len(str(x or "").strip()) >= 8), "")
    catchphrase_seed = catchphrases[0] if catchphrases else (focus_quote[:18] if focus_quote else (focus_keyword or "那个弄完了吗"))
    domain_scores = _member_domain_scores(top_keywords[:10], quotes[:6])
    domain_key = "social"
    if any(domain_scores.values()):
        domain_key = max(domain_scores.items(), key=lambda kv: (kv[1], kv[0]))[0]
    domain_label_map = {
        "tech": "技术/产品",
        "ops": "运营/活动",
        "business": "客户/项目",
        "study": "研究/学业",
        "content": "内容/分发",
        "social": "情绪/社交",
    }
    domain_label = domain_label_map.get(domain_key, "群聊互动")
    clamp = lambda value, lo=8, hi=98: int(max(lo, min(hi, round(float(value)))))

    leadership = clamp(impact * 0.55 + command_hits * 4.8 + self_drive_hits * 4.0 + deadline_hits * 3.4 + active_days * 1.5, 16, 98)
    big_talk = clamp(avg_length * 1.35 + question_ratio * 165 + link_ratio * 120 + laugh_ratio * 46 + 24, 12, 96)
    night_mania = clamp(night_ratio * 320 + emo_hits * 9.0 + laugh_hits * 3.5 + (18 if peak_hour in (0, 1, 2, 3) else 0), 8, 99)
    gossip = clamp(question_ratio * 120 + laugh_hits * 7.0 + mention_hits * 4.2 + domain_scores.get("social", 0) * 2.6 + 16, 10, 92)
    hardcore = clamp(len(top_keywords) * 4.8 + avg_length * 1.4 + link_ratio * 100 + long_text_ratio * 62 + domain_scores.get("tech", 0) * 3.2 + domain_scores.get("study", 0) * 2.8 + 10, 18, 97)
    affinity = clamp(soft_hits * 4.2 + agreement_hits * 4.0 + mention_hits * 2.9 + active_days * 1.1 + max(0, 62 - blame_hits * 5.5 - emo_hits * 4.0), 12, 95)

    style_scores = {
        "driver": leadership * 0.78 + deadline_hits * 4.4 + self_drive_hits * 4.0 + command_hits * 3.0,
        "analyst": hardcore * 0.84 + long_text_ratio * 60 + len(top_keywords) * 2.8,
        "connector": affinity * 0.82 + mention_hits * 4.4 + agreement_hits * 4.0 + soft_hits * 3.6,
        "spark": big_talk * 0.74 + laugh_hits * 4.6 + question_hits * 3.4 + exclamation_hits * 2.0,
        "nightowl": night_mania * 0.92 + emo_hits * 5.8 + peak_hour * 0.2,
        "curator": link_ratio * 145 + media_ratio * 82 + feature_pack.get("link_messages", 0) * 2.8 + domain_scores.get("content", 0) * 4.2,
    }
    sorted_styles = sorted(style_scores.items(), key=lambda kv: (kv[1], kv[0]), reverse=True)
    style_key = sorted_styles[0][0] if sorted_styles else "analyst"
    secondary_style = sorted_styles[1][0] if len(sorted_styles) > 1 else style_key
    style_label_map = {
        "driver": "推进收口型",
        "analyst": "拆解分析型",
        "connector": "接球润滑型",
        "spark": "点火起哄型",
        "nightowl": "夜间放大型",
        "curator": "情报投喂型",
    }
    style_label = style_label_map.get(style_key, "混合风格")

    e_score = messages * 0.32 + active_days * 1.8 + mention_hits * 4.0 + laugh_hits * 2.4 + question_hits * 1.8
    i_score = avg_length * 2.0 + long_hits * 2.4 + max(0, 56 - messages) * 0.85 + max(0, impact - messages * 0.18)
    n_score = len(top_keywords) * 4.2 + feature_pack.get("link_messages", 0) * 1.8 + question_hits * 2.5 + domain_scores.get("tech", 0) * 3.2 + domain_scores.get("content", 0) * 2.2
    s_score = deadline_hits * 4.8 + active_days * 1.7 + agreement_hits * 2.6 + domain_scores.get("ops", 0) * 3.0 + domain_scores.get("study", 0) * 2.6
    t_score = command_hits * 5.4 + blame_hits * 4.6 + impact * 0.58 + domain_scores.get("tech", 0) * 2.6 + domain_scores.get("business", 0) * 2.4
    f_score = soft_hits * 5.0 + agreement_hits * 4.4 + mention_hits * 2.8 + domain_scores.get("social", 0) * 2.8 + laugh_hits * 2.0
    j_score = deadline_hits * 5.0 + self_drive_hits * 4.8 + command_hits * 3.2 + active_days * 1.5
    p_score = question_hits * 4.5 + laugh_hits * 3.4 + exclamation_hits * 2.4 + night_ratio * 38 + hesitation_hits * 2.8
    mbti_guess = "".join([
        "E" if e_score >= i_score else "I",
        "N" if n_score >= s_score else "S",
        "T" if t_score >= f_score else "F",
        "J" if j_score >= p_score else "P",
    ])
    mbti_label = MEMBER_MBTI_LABELS.get(mbti_guess, "混合风格型")
    reason_bits = []
    if deadline_hits + self_drive_hits + command_hits >= 5:
        reason_bits.append("推进节点和收口欲都偏强")
    if mention_hits + agreement_hits + soft_hits >= 5:
        reason_bits.append("很在意别人有没有接住他的语气")
    if long_text_ratio >= 0.28 or avg_length >= 26:
        reason_bits.append("一开口就会把上下文和逻辑链补得很全")
    if night_ratio >= 0.22 or peak_hour in (0, 1, 2, 3):
        reason_bits.append("越到夜里越容易显露真实风格")
    if link_ratio >= 0.16 or domain_key == "content":
        reason_bits.append("经常拿外部链接和材料给群聊续命")
    if laugh_ratio >= 0.16 and question_ratio >= 0.10:
        reason_bits.append("会用玩笑和反问把场子重新点着")
    if not reason_bits:
        reason_bits.append("表达节奏比较稳，个性更多藏在长期细节里")
    mbti_reason = "；".join(reason_bits[:2]) + (f"。最近常围着“{focus_keyword}”这类点发力。" if focus_keyword else "。")

    animal_pool_map = {
        "driver": ["边牧", "狼", "隼", "狐狸"],
        "analyst": ["猫头鹰", "章鱼", "海狸", "狐狸"],
        "connector": ["水獭", "海豚", "金毛", "羊驼"],
        "spark": ["蜜蜂", "松鼠", "海豚", "浣熊"],
        "nightowl": ["猫头鹰", "浣熊", "海豹", "狼"],
        "curator": ["松鼠", "海狸", "章鱼", "狐狸"],
    }
    if domain_key == "tech":
        animal_pool = ["猫头鹰", "章鱼", "隼", "狐狸"] if style_key in {"analyst", "driver"} else animal_pool_map.get(style_key, ["狐狸", "猫头鹰"])
    elif domain_key == "ops":
        animal_pool = ["边牧", "金毛", "蜜蜂", "海狸"]
    elif domain_key == "business":
        animal_pool = ["狼", "狐狸", "边牧", "金毛"]
    elif domain_key == "study":
        animal_pool = ["隼", "猫头鹰", "章鱼", "海豹"]
    elif domain_key == "content":
        animal_pool = ["松鼠", "海狸", "海豚", "狐狸"]
    else:
        animal_pool = animal_pool_map.get(style_key, ["狐狸", "猫咪", "水獭", "海豚"])
    animal = _member_hash_pick(animal_pool, sender_id or sender_name, f"{style_key}|{domain_key}") or "狐狸"
    animal_reason_map = {
        "边牧": "天然会追着话题往前跑，看见散开的讨论就想收回主线。",
        "狼": "对拖延和失控很敏感，一闻到风险味就会开始逼近结果。",
        "隼": "习惯先在高处看局势，一旦锁定问题就直冲结论，不怎么绕弯。",
        "狐狸": "反应很快，擅长从弯弯绕绕里捞出最有价值的那条信息。",
        "猫头鹰": "白天不一定最吵，但一到关键节点就会给出冷静又锋利的判断。",
        "章鱼": "能同时盯好几条线，信息一多反而容易进入工作状态。",
        "海狸": "喜欢一点点把结构搭好，最后让别人发现这事居然真的被收拾顺了。",
        "水獭": "看着轻松，但其实很会把尴尬和生硬场面往顺滑方向带。",
        "海豚": "擅长接球和抛球，别人一失速他就会把节奏重新顶起来。",
        "金毛": "能把硬任务说得没那么硬，让人更愿意继续跟着往前走。",
        "羊驼": "表面松弛，实则很懂怎么拦住场面的毛躁和情绪刺。",
        "蜜蜂": "在不同线程之间来回接球很快，现场热度常靠他续上。",
        "松鼠": "会到处搬线索和材料，最后把零碎讨论拼成一条能看的线。",
        "浣熊": "夜深之后反而更活跃，越混乱越容易兴奋地翻出新东西。",
        "海豹": "平时显得懒洋洋，但真要沉下去处理时能憋很久不浮上来。",
        "猫咪": "不一定主动占麦，但挑对时机伸一爪往往就能拍中重点。",
    }
    animal_reason = animal_reason_map.get(animal, "群聊里有自己的一套出场节奏，不太像标准模板人物。")
    if focus_keyword:
        animal_reason += f" 一旦聊到“{focus_keyword}”，本体感会更明显。"

    role_title_pools = {
        ("driver", "tech"): ["把群聊当冲刺板的人", "结果导向型推进器", "技术线 deadline 点火器"],
        ("driver", "business"): ["需求收口型总控", "对接推进器", "项目线结果催化剂"],
        ("driver", "study"): ["实验室进度点火器", "课题推进型选手", "研究线收口人"],
        ("analyst", "tech"): ["冷面拆解器", "技术细节放大镜", "把模糊问题拆开的那个人"],
        ("analyst", "study"): ["研究型拆招手", "实验室问题解剖刀", "论文语气侦测器"],
        ("connector", "ops"): ["活动场面润滑剂", "群内主持型选手", "会把人重新拉回来的连接器"],
        ("connector", "social"): ["关系缓冲垫", "群聊接球手", "会把刺耳语气磨平的人"],
        ("spark", "social"): ["热场起哄机", "群聊火花制造者", "靠一句话点着全场的人"],
        ("spark", "content"): ["梗感点火器", "内容话题引爆点", "把链接聊出戏的人"],
        ("nightowl", "tech"): ["深夜值班型脑回路", "凌晨上线的技术脑", "夜间高能选手"],
        ("nightowl", "social"): ["午夜放大器", "深夜情绪放映机", "越晚越有戏的人"],
        ("curator", "content"): ["链接投喂型情报鸟", "素材搬运调度台", "把外部世界往群里拽的人"],
        ("curator", "ops"): ["情报收纳员", "素材集散中心", "把零碎信息打包回群的人"],
    }
    role_title = _member_hash_pick(
        role_title_pools.get((style_key, domain_key), [])
        or role_title_pools.get((style_key, "social"), [])
        or [f"{domain_label}里的{style_label}", f"{style_label}选手", "值得单独观察的人"],
        sender_id or sender_name,
        "role-title"
    ) or "值得单独观察的人"

    if peak_hour in (0, 1, 2, 3) or night_ratio >= 0.22:
        food_pool_a = ["便利店冰可乐", "双份美式", "深夜泡面", "冰镇乌龙茶"]
        food_pool_b = ["烧烤拼盘", "辣炒年糕", "炸鸡桶", "掌中宝"]
    elif domain_key == "tech":
        food_pool_a = ["冰美式", "无糖气泡水", "手冲咖啡", "能量饮料"]
        food_pool_b = ["重辣拌饭", "鸡腿便当", "烤肉饭", "牛肉粉"]
    elif domain_key == "study":
        food_pool_a = ["苦咖啡", "豆浆美式", "双倍浓茶", "低糖酸奶"]
        food_pool_b = ["鸡蛋灌饼", "烤冷面", "热汤面", "煎饼果子"]
    elif style_key == "connector":
        food_pool_a = ["芋泥奶茶", "柠檬气泡茶", "果咖", "冰豆乳"]
        food_pool_b = ["麻辣烫", "寿喜锅", "卤味拼盘", "韩式炸鸡"]
    elif style_key == "curator":
        food_pool_a = ["冷萃咖啡", "无糖乌龙", "冰拿铁", "椰子水"]
        food_pool_b = ["轻食卷", "三明治", "烤鸡沙拉", "热压吐司"]
    else:
        food_pool_a = ["气泡美式", "冰柠檬茶", "奶盖乌龙", "可乐冰"]
        food_pool_b = ["重口味盖饭", "冒菜", "辣子鸡", "芝士焗饭"]
    food_a = _member_hash_pick(food_pool_a, sender_id or sender_name, "food-a") or food_pool_a[0]
    food_b_pool = [x for x in food_pool_b if x != food_a] or food_pool_b
    food_b = _member_hash_pick(food_b_pool, sender_id or sender_name, "food-b") or food_b_pool[0]
    foods = [food_a, food_b]

    guide_seed_map = {
        "driver": [
            "汇报时先给结论，再补 A/B 方案，他更容易接住。",
            "如果他连续两次追问，说明他在找阻塞点，不是在找情绪价值。",
        ],
        "analyst": [
            "别只丢结论，最好把你已经验证过的上下文一起摆出来。",
            "模糊词越少越好，他更吃有边界、有证据的表达。",
        ],
        "connector": [
            "先接住他的语气，再抛任务点，沟通阻力会小很多。",
            "场面冷掉时可以先借他的话续一句，比强行转话题有效。",
        ],
        "spark": [
            "别急着压他的跳跃发散，先让他把火点起来，再收口。",
            "如果他开始连抛梗和反问，说明群里刚好需要一点热度。",
        ],
        "nightowl": [
            "重要事别只在白天等他反应，晚上可能反而更容易回魂。",
            "深夜别跟他硬碰硬，顺着他此刻的节奏给一个明确落点更有用。",
        ],
        "curator": [
            "找他要资料时直接说主题和用途，不然你会收到一串开放链接。",
            "别只问“有没有”，要问“最值得先看哪一个”，效率会高很多。",
        ],
    }
    guide_lines = list(guide_seed_map.get(style_key, [
        "直接说重点和预期结果，比铺太多背景更高效。",
        "如果他开始追问细节，说明已经进入认真模式了。",
    ]))
    if catchphrase_seed:
        guide_lines.append(f"当他开始抛“{catchphrase_seed[:16]}”这类句式时，最好直接回应结论、时间点或下一步。")

    roast_templates = {
        "driver": [
            "像把群聊当冲刺板的{animal}：开口不是为了参与热闹，而是为了把散掉的话题拖回“{topic}”这条线。只要“{seed}”一出来，大家就会下意识检查自己还有没有漏项。",
            "别人把聊天聊成茶话会，他会顺手改造成推进会。最有辨识度的不是情绪，而是“{seed}”这种听着像站会结论的句式。",
            "他不是在群里说话，更像在群里收口。尤其一旦围着“{topic}”发力，聊天记录就会立刻长出 deadline 的味道。",
        ],
        "analyst": [
            "像蹲在群角落写 review 的{animal}：平时未必最吵，但一旦围着“{topic}”开口，就会把模糊地带照得太亮，让别人没法继续糊弄过去。",
            "他的杀伤力不靠音量，靠信息密度。别人说完一句，他常能用更长的一句把“{topic}”掰回清晰版本。",
            "看起来像在旁听，实际上一直在做内心批注。等“{seed}”这类句式出现时，通常意味着他已经忍不住要开始拆问题了。",
        ],
        "connector": [
            "像会把群聊缝起来的{animal}：最会做的事不是抢镜，而是在气氛快散的时候把人重新接回同一页。连“{seed}”这种句式都能被他说得没那么刺。",
            "他的存在感不一定最吵，但常出现在场子快硬掉的节点。别人一旦卡住，他会把“{topic}”聊成大家都还能继续接的版本。",
            "像群里的缓冲垫，能把尖锐语气磨平一层，再把任务往前推一格。看似松弛，其实对场子很有控制力。",
        ],
        "spark": [
            "像会自带火花的{animal}：最常干的事不是补充信息，而是拿“{seed}”这种句式把已经要凉掉的话题重新点亮。群里一热起来，通常都有他的一脚油门。",
            "他对讨论的贡献，经常不是答案本身，而是把别人憋着没说出口的那点情绪先炸出来。尤其一围着“{topic}”开玩笑，场子就容易活。",
            "属于那种会把平铺直叙聊出起伏的人。别人讲事实，他负责让事实看起来终于值得继续聊下去。",
        ],
        "nightowl": [
            "像夜里才真正开机的{animal}：白天可能看着克制，一到晚点就会把“{topic}”放大成个人主线，顺手带出一连串真实情绪。",
            "他的画风很吃时间点。越靠近深夜，“{seed}”这种句式越像情绪和判断一起上线，群聊浓度也会跟着变高。",
            "不是没有锋芒，只是大多留到别人都快收工时才亮出来。夜里一热起来，整个场子的色温都会被他带偏。",
        ],
        "curator": [
            "像把外部世界往群里搬运的{animal}：他的出场方式常常不是一句观点，而是一条链接、一个截图，或者一串围着“{topic}”展开的素材包。",
            "他很少空手进场。只要开始聊“{topic}”，很快就会看到资料、案例或引用往群里一件件落。",
            "别人靠情绪维持存在感，他更像靠信息密度。最典型的时刻，是“{seed}”后面接着甩出一整串可点开的东西。",
        ],
    }
    roast = _member_hash_pick(
        roast_templates.get(style_key, roast_templates["analyst"]),
        sender_id or sender_name,
        "roast"
    ) or roast_templates["analyst"][0]
    roast = roast.format(
        animal=animal,
        seed=catchphrase_seed[:18] or "那个弄完了吗",
        topic=focus_keyword or domain_label,
    )
    if focus_quote and focus_quote[:18] not in roast:
        roast += f" 最近最有辨识度的原话，往往也带着“{focus_quote[:18]}”这种出场方式。"
    elif catchphrase_seed and catchphrase_seed[:18] not in roast:
        roast += f" 最近最有辨识度的句式，通常也和“{catchphrase_seed[:18]}”有关。"
    if secondary_style and secondary_style != style_key:
        roast += f" 底色里还掺着一点{style_label_map.get(secondary_style, secondary_style)}。"

    tarot_templates = {
        "driver": "本周抽到【{card}·{orientation}】。控制面和推进欲会更明显，尤其容易把“{seed}”说成最后通牒；越想立刻把局面扳正，越要小心把聊天聊成点名会。",
        "analyst": "本周抽到【{card}·{orientation}】。你会更想把“{topic}”这类问题拆到见骨，优势是清醒，代价是容易让别人觉得自己被当场做了 review。",
        "connector": "本周抽到【{card}·{orientation}】。你会本能地去接住场面，但也容易把别人的情绪一起背上身；围着“{seed}”回合太多时，记得给自己留一点边界。",
        "spark": "本周抽到【{card}·{orientation}】。语言火花会很旺，尤其适合把沉闷话题点着；但玩笑一旦踩到“{topic}”的高压区，也可能把局面推得比预期更热。",
        "nightowl": "本周抽到【{card}·{orientation}】。晚间能量会被放大，深夜说出口的话比白天更像真心话；如果“{seed}”频率上来，说明你已经进入情绪放大镜模式。",
        "curator": "本周抽到【{card}·{orientation}】。你会更想用资料和链接给局面找依据，围着“{topic}”时尤其明显；但材料越多，越要提防自己把别人淹没在信息洪水里。",
    }
    tarot_line = (tarot_templates.get(style_key, tarot_templates["analyst"]) or "").format(
        card=tarot["name"],
        orientation=tarot["orientation"],
        seed=catchphrase_seed[:18] or "那个弄完了吗",
        topic=focus_keyword or domain_label,
    )

    combat_stats = [
        {"label": "发号施令", "score": leadership, "tone": "pink"},
        {"label": "甩锅闪避", "score": clamp(blame_hits * 10 + hesitation_hits * 8 + big_talk * 0.42 + 18, 12, 96), "tone": "violet"},
        {"label": "情绪稳定", "score": clamp(92 - emo_hits * 9 - exclamation_ratio * 110 - laugh_ratio * 16, 12, 95), "tone": "amber"},
    ]
    radar_scores = [
        {"label": "领导力", "score": leadership},
        {"label": "深夜发狂", "score": night_mania},
        {"label": "八卦水平", "score": gossip},
        {"label": "专业硬核", "score": hardcore},
        {"label": "亲和力", "score": affinity},
        {"label": "画大饼", "score": big_talk},
    ]
    fortune = [
        {"label": "事业/画饼运", "score": int(max(1, min(5, round((leadership + big_talk) / 40.0))))},
        {"label": "团队好感度", "score": int(max(1, min(5, round((affinity + agreement_hits * 3) / 22.0))))},
        {"label": "摸鱼暴击率", "score": int(max(1, min(5, round((night_mania + max(0, 78 - leadership)) / 36.0))))},
        {"label": "财运（报销）", "score": int(max(1, min(5, round((hardcore + affinity + domain_scores.get('business', 0) * 6) / 44.0))))},
    ]

    return {
        "sender": sender_name,
        "sender_id": sender_id,
        "level": level_label,
        "title": f"{sender_name} · {role_title}",
        "subtitle": f"基于最近 {int(feature_pack.get('messages', 0) or 0)} 条个人消息、{active_days} 个活跃日和抽样语料生成的趣味画像，主场更偏 {domain_label}。",
        "tagline": f"{role_title} / {animal}",
        "mbti_guess": mbti_guess,
        "mbti_label": mbti_label,
        "mbti_reason": mbti_reason,
        "spirit_animal": animal,
        "animal_reason": animal_reason,
        "tarot": {
            "name": tarot["name"],
            "name_en": tarot["name_en"],
            "orientation": tarot["orientation"],
            "summary": tarot_line,
        },
        "radar_scores": radar_scores,
        "combat_stats": combat_stats,
        "roast": roast,
        "foods": foods,
        "guide_lines": guide_lines,
        "fortune": fortune,
        "catchphrases": catchphrases[:6] if catchphrases else quotes[:4],
        "keywords": top_keywords[:10],
        "sample_quotes": quotes[:6],
        "activity_note": f"最活跃时段在 {peak_hour:02d}:00 左右，最近活跃：{recent_text}；当前更像 {domain_label}里的{style_label}。",
        "analysis_note": "当前为增强版本地画像；已经按特征簇、话题域和成员稳定哈希做了差异化，点击按钮后仍可切换到大模型深描。",
        "dominant_domain": domain_label,
        "dominant_style": style_label,
    }


def _normalize_member_deep_profile_result(parsed_data, fallback_data):
    parsed = parsed_data if isinstance(parsed_data, dict) else {}
    fallback = fallback_data if isinstance(fallback_data, dict) else {}
    out = dict(fallback)
    for key, value in parsed.items():
        if value in (None, "", [], {}):
            continue
        out[key] = value
    list_specs = {
        "radar_scores": fallback.get("radar_scores", []),
        "combat_stats": fallback.get("combat_stats", []),
        "foods": fallback.get("foods", []),
        "guide_lines": fallback.get("guide_lines", []),
        "fortune": fallback.get("fortune", []),
        "catchphrases": fallback.get("catchphrases", []),
        "keywords": fallback.get("keywords", []),
        "sample_quotes": fallback.get("sample_quotes", []),
    }
    for key, fb in list_specs.items():
        if not isinstance(out.get(key, None), list) or not out.get(key):
            out[key] = fb
    if not isinstance(out.get("tarot", None), dict):
        out["tarot"] = fallback.get("tarot", {})
    else:
        tarot = dict(fallback.get("tarot", {}))
        tarot.update({k: v for k, v in dict(out.get("tarot", {})).items() if v not in (None, "", [], {})})
        out["tarot"] = tarot
    return out


def _run_member_deep_profile_analysis(username, sender_id="", sender_name="", start_ts=0, end_ts=0, use_ai=False, force=False, cfg_override=None):
    username = str(username or "").strip()
    if not username:
        raise RuntimeError("missing username")

    full_data = _build_analysis_full(username=username, start_ts=start_ts, end_ts=end_ts, link_limit=12000)
    member_row = _resolve_member_target(full_data, sender_id=sender_id, sender_name=sender_name)
    if not isinstance(member_row, dict) or not member_row:
        raise RuntimeError("未找到目标成员")
    sender_id = str(member_row.get("sender_id", "") or sender_id or "").strip()
    sender_name = str(member_row.get("sender", "") or sender_name or "").strip()
    feature_pack = _collect_member_feature_pack(
        username=username,
        sender_id=sender_id,
        sender_name=sender_name,
        start_ts=start_ts,
        end_ts=end_ts,
        limit=2600,
    )
    fallback = _build_member_deep_profile_fallback(full_data, member_row, feature_pack)
    week_key = str((fallback.get("tarot", {}) or {}).get("name", "")) + "|" + str((fallback.get("tarot", {}) or {}).get("orientation", ""))
    provider_cfg = _resolve_ai_provider_config_for_surface("insight", cfg_override)
    provider = _normalize_provider_name(provider_cfg.get("provider", "openai_compat"))
    model_name = str(provider_cfg.get("model", "") or "").strip()
    ai_ready = False
    ai_reason = ""
    if use_ai:
        if provider == "claude_cli":
            ai_ready = True
        elif not str(provider_cfg.get("base_url", "") or "").strip():
            ai_reason = "未配置 Base URL，已回退到本地画像。"
        elif not str(provider_cfg.get("api_key", "") or "").strip():
            ai_reason = "未配置 API Key，已回退到本地画像。"
        elif not model_name:
            ai_reason = "未配置模型，已回退到本地画像。"
        else:
            ai_ready = True

    cache_key = (
        f"memberdeep:{'ai' if (use_ai and ai_ready) else 'fallback'}:{provider}:{model_name}:"
        f"{username}:{int(start_ts or 0)}:{int(end_ts or 0)}:{sender_id}:{week_key}"
    )
    if not force:
        cached = _analysis_cache_get(cache_key)
        if cached:
            return cached

    data = dict(fallback)
    mode = "fallback"
    if use_ai and ai_ready:
        schema_hint = (
            '{"title":"","subtitle":"","tagline":"","mbti_guess":"","mbti_label":"","mbti_reason":"",'
            '"spirit_animal":"","animal_reason":"",'
            '"tarot":{"name":"","name_en":"","orientation":"","summary":""},'
            '"radar_scores":[{"label":"","score":0}],'
            '"combat_stats":[{"label":"","score":0,"tone":"pink|violet|amber|cyan"}],'
            '"roast":"","foods":["",""],"guide_lines":["",""],'
            '"fortune":[{"label":"","score":1-5}],'
            '"catchphrases":[""],"keywords":[""],"sample_quotes":[""],'
            '"activity_note":"","analysis_note":""}'
        )
        system_prompt = (
            "你是擅长写“人物深度图鉴”的社群分析师。"
            "你只能基于给定的人物特征语料包输出单个 JSON 对象，不能输出 markdown 代码块。"
            "MBTI、精神动物、塔罗都只能写成趣味猜测，绝不能写成确定事实。"
            "文风要求：犀利、具体、像真的读过聊天记录，但不能胡编不存在的口头禅和事件。"
        )
        user_prompt = (
            "请根据下面的人物特征包，输出可直接渲染到前端页面的人物深度画像 JSON。\n"
            f"输出 schema: {schema_hint}\n"
            "写作规则：\n"
            "1. roast 必须毒舌但别空泛，最好点出这个人最常见的聊天动作。\n"
            "2. guide_lines 要像生存说明书，直接给可执行建议。\n"
            "3. tarot.summary 必须强行把塔罗牌意和聊天习惯关联起来。\n"
            "4. catchphrases 只保留短句，不要整段长文。\n"
            "5. 所有分值范围严格在 0-100 或 1-5 内。\n"
            f"Data JSON:\n{json.dumps({'member': member_row, 'feature_pack': feature_pack, 'fallback': fallback}, ensure_ascii=False)}"
        )
        try:
            text, usage = _llm_complete_by_provider(provider_cfg, system_prompt, user_prompt)
            parsed = _try_parse_json_obj(text)
            data = _normalize_member_deep_profile_result(parsed, fallback)
            mode = "ai"
            data["analysis_note"] = "当前为大模型深描版，已基于特征语料包补足戏剧化表达。"
        except Exception as e:
            ai_reason = f"模型分析失败，已回退到本地画像：{e}"
            data = dict(fallback)
            data["analysis_note"] = ai_reason
            mode = "fallback"
            usage = {}
    else:
        usage = {}
        if ai_reason:
            data["analysis_note"] = ai_reason

    result = {
        "ok": True,
        "mode": mode,
        "generated_at": int(time.time()),
        "target": {
            "sender": sender_name,
            "sender_id": sender_id,
        },
        "feature_pack": {
            "messages": int(feature_pack.get("messages", 0) or 0),
            "active_days": int(feature_pack.get("active_days", 0) or 0),
            "peak_hour": int(feature_pack.get("peak_hour", -1) or -1),
            "keywords": feature_pack.get("keywords", [])[:10],
            "catchphrases": feature_pack.get("catchphrases", [])[:10],
            "sample_quotes": feature_pack.get("sample_quotes", [])[:6],
        },
        "data": data,
        "usage": usage if isinstance(usage, dict) else {},
    }
    _analysis_cache_set(cache_key, result)
    return result


def broadcast_sse(msg_data):
    payload = f"data: {json.dumps(msg_data, ensure_ascii=False)}\n\n"
    with sse_lock:
        dead = []
        for q in sse_clients:
            try:
                q.put_nowait(payload)
            except:
                dead.append(q)
        for q in dead:
            sse_clients.remove(q)


# ============ 閻╂垵鎯夐崳?============

class SessionMonitor:
    def __init__(self, enc_key, session_db, contact_names):
        self.enc_key = enc_key
        self.session_db = session_db
        self.wal_path = session_db + "-wal"
        self.contact_names = contact_names
        self.contact_names_refresh_last = 0.0
        self.prev_state = {}
        self.decrypt_ms = 0
        self.patched_pages = 0
        self._username_db_map_lock = threading.Lock()
        try:
            self.username_db_map = _build_username_db_map()
        except Exception:
            self.username_db_map = {}

    def query_state(self):
        """Query current state from decrypted session DB."""
        if not _looks_like_sqlite_file(DECRYPTED_SESSION):
            raise sqlite3.DatabaseError("decrypted session db is not ready")
        state = {}
        with session_db_lock:
            conn = sqlite3.connect(f"file:{DECRYPTED_SESSION}?mode=ro", uri=True)
            for r in conn.execute("""
                SELECT username, unread_count, summary, last_timestamp,
                       last_msg_type, last_msg_sender, last_sender_display_name
                FROM SessionTable WHERE last_timestamp > 0
            """).fetchall():
                state[r[0]] = {
                    'unread': r[1], 'summary': r[2] or '', 'timestamp': r[3],
                    'msg_type': r[4], 'sender': r[5] or '', 'sender_name': r[6] or '',
                }
            conn.close()
        return state

    def do_full_refresh(self):
        """閸忋劑鍣虹憴锝呯槕DB + 閸忋劑鍣篧AL patch"""
        with session_db_lock:
            # 閸忓牐袙鐎靛棔瀵孌B
            pages, ms = full_decrypt(self.session_db, DECRYPTED_SESSION, self.enc_key)
            total_ms = ms
            wal_patched = 0

            # 閸愬潮atch閹碘偓閺堝AL frames
            if os.path.exists(self.wal_path):
                wal_patched, ms2 = decrypt_wal_full(self.wal_path, DECRYPTED_SESSION, self.enc_key)
                total_ms += ms2

        self.decrypt_ms = total_ms
        self.patched_pages = pages + wal_patched
        return self.patched_pages

    def _candidate_message_dbs(self, username):
        with self._username_db_map_lock:
            cached = list(self.username_db_map.get(username, []))
        if cached:
            return cached
        paths, _ = _find_all_msg_tables_for_user(username, ensure_fresh=False)
        if not paths:
            paths, _ = _find_all_msg_tables_for_user(username, ensure_fresh=True)
        if paths:
            with self._username_db_map_lock:
                self.username_db_map[username] = list(paths)
        return list(paths or [])

    def _query_message_rows(self, username, start_ts, end_ts):
        start_ts = int(start_ts or 0)
        end_ts = int(end_ts or 0)
        if not username or not start_ts or not end_ts:
            return []
        if end_ts < start_ts:
            start_ts, end_ts = end_ts, start_ts

        table_name = f"Msg_{hashlib.md5(username.encode()).hexdigest()}"
        rows_out = []
        seen = set()
        for db_path in self._candidate_message_dbs(username):
            if not db_path:
                continue
            try:
                refresh_decrypted_message_db(db_path)
            except Exception:
                pass
            if not _table_exists(db_path, table_name):
                continue
            try:
                _cols, _sender_map, db_rows = _load_message_rows_safe(
                    db_path=db_path,
                    table_name=table_name,
                    start_ts=start_ts,
                    end_ts=end_ts,
                    limit=0,
                    newest_first=False,
                )
                for row in db_rows:
                    local_id = int(row.get("local_id", 0) or 0)
                    ts = int(row.get("timestamp", 0) or 0)
                    local_type = int(row.get("local_type", 0) or 0)
                    server_id = int(row.get("server_id", 0) or 0)
                    sender_username = str(row.get("sender_username", "") or "")
                    sig = (ts, local_id, server_id, local_type, sender_username)
                    if sig in seen:
                        continue
                    seen.add(sig)
                    rows_out.append(dict(row))
            except Exception:
                continue

        rows_out.sort(key=lambda x: (int(x.get("timestamp", 0) or 0), int(x.get("local_id", 0) or 0)))
        return rows_out

    def _build_message_from_row(self, username, display, row, unread=0):
        ts = int(row.get("timestamp", 0) or 0)
        base_type = _normalize_msg_type(row.get("local_type", 0))
        source_blob = row.get("source", b"")
        content_blob = row.get("content", "")
        ct_flag = row.get("ct_flag", None)

        text = _decode_message_content(content_blob, base_type, ct_flag)
        sender_username = str(row.get("sender_username", "") or "").strip()
        is_group = "@chatroom" in username
        if is_group and text:
            p_sender, p_body = _parse_group_sender_prefix(text)
            if p_sender:
                if not sender_username:
                    sender_username = p_sender
                text = p_body

        text = _render_link_or_quote_text(base_type, text, source_blob)
        if base_type == 49:
            text = _sanitize_link_text(text)
        link_source, link_url = _extract_link_meta(base_type, text, source_blob)
        media_url = _resolve_media_url_for_row(
            base_type=base_type,
            username=username,
            ts=ts,
            server_id=int(row.get("server_id", 0) or 0),
            local_id=int(row.get("local_id", 0) or 0),
            source_blob=source_blob,
            content_blob=content_blob,
            ct_flag=ct_flag,
        )
        rich_media = _extract_rich_media_payload(
            base_type,
            text,
            source_blob=source_blob,
            link_source=link_source,
            link_url=link_url,
            media_url=media_url,
        )
        text = _finalize_display_content(base_type, text)

        sender = ""
        status = int(row.get("status", 0) or 0)
        is_me = _resolve_is_self_message(is_group, status, sender_username)
        if is_group:
            sender = self.contact_names.get(sender_username, sender_username) if sender_username else ""
        else:
            if is_me:
                sender = "我"
            else:
                sender = self.contact_names.get(username, username)

        msg_data = {
            "time": datetime.fromtimestamp(ts).strftime("%H:%M:%S") if ts else "",
            "timestamp": ts,
            "chat": display,
            "username": username,
            "is_group": is_group,
            "sender": sender,
            "type": _display_msg_type(base_type, content=text, source_blob=source_blob),
            "type_icon": _display_msg_type_icon(base_type, content=text, source_blob=source_blob),
            "content": text,
            "unread": int(unread or 0),
            "is_me": is_me,
            "link_source": link_source,
            "link_url": link_url,
            "decrypt_ms": round(self.decrypt_ms, 1),
            "pages": self.patched_pages,
            "local_id": int(row.get("local_id", 0) or 0),
            "server_id": int(row.get("server_id", 0) or 0),
        }
        if media_url:
            msg_data["media_url"] = media_url
        if rich_media:
            msg_data["rich_media"] = rich_media
        return msg_data

    def _check_hidden_messages(self, username, prev_ts, curr_ts, curr_msg_type, display):
        if not username or _is_placeholder_session(username):
            return
        prev_ts = int(prev_ts or 0)
        curr_ts = int(curr_ts or 0)
        if prev_ts <= 0 or curr_ts <= 0:
            return
        if curr_ts < prev_ts:
            prev_ts, curr_ts = curr_ts, prev_ts

        # Wait briefly for message db WAL flush.
        time.sleep(0.8)
        rows = self._query_message_rows(username, prev_ts, curr_ts)
        if not rows:
            return

        global messages_log
        emitted = []
        seen_sig = set()
        curr_base_type = _normalize_msg_type(curr_msg_type)
        for row in rows:
            ts = int(row.get("timestamp", 0) or 0)
            base_type = _normalize_msg_type(row.get("local_type", 0))
            if prev_ts < curr_ts and ts == prev_ts:
                continue
            # The current session summary message is already emitted in main path.
            if ts == curr_ts and base_type == curr_base_type:
                continue
            sig = (
                ts,
                int(row.get("local_id", 0) or 0),
                int(row.get("server_id", 0) or 0),
                base_type,
                str(row.get("sender_username", "") or ""),
            )
            if sig in seen_sig:
                continue
            seen_sig.add(sig)
            msg = self._build_message_from_row(username, display, row, unread=0)
            emitted.append(msg)

        if not emitted:
            return
        emitted.sort(key=lambda m: int(m.get("timestamp", 0) or 0))
        _analysis_cache_clear()
        for msg in emitted:
            with messages_lock:
                messages_log.append(msg)
                if len(messages_log) > MAX_LOG:
                    messages_log = messages_log[-MAX_LOG:]
            broadcast_sse(msg)
            _maybe_schedule_live_alert(msg, monitor_obj=self)

    def check_updates(self):
        global messages_log
        try:
            t0 = time.perf_counter()
            self.do_full_refresh()
            t1 = time.perf_counter()
            curr_state = self.query_state()
            t2 = time.perf_counter()
            now = time.time()
            if (now - float(self.contact_names_refresh_last or 0.0)) >= 8.0:
                fresh_names = load_contact_names()
                if fresh_names:
                    self.contact_names = fresh_names
                self.contact_names_refresh_last = now
            print(f"  [perf] decrypt={self.patched_pages}妞?{(t1-t0)*1000:.1f}ms, query={(t2-t1)*1000:.1f}ms", flush=True)
        except Exception as e:
            print(f"  [ERROR] check_updates: {e}", flush=True)
            return

        # 閺€鍫曟肠閹碘偓閺堝鏌婂☉鍫熶紖閿涘本瀵滈弮鍫曟？閹烘帒绨崥搴″晙閹恒劑鈧?
        new_msgs = []
        for username, curr in curr_state.items():
            if _is_placeholder_session(username):
                continue
            prev = self.prev_state.get(username)
            is_new = bool(prev) and (
                int(curr.get("timestamp", 0) or 0) > int(prev.get("timestamp", 0) or 0)
                or (
                    int(curr.get("timestamp", 0) or 0) == int(prev.get("timestamp", 0) or 0)
                    and _normalize_msg_type(curr.get("msg_type", 0)) != _normalize_msg_type(prev.get("msg_type", 0))
                )
            )
            if is_new:
                display = _display_name_for_username(username, self.contact_names)
                is_group = '@chatroom' in username
                sender = ''
                if is_group:
                    sender = self.contact_names.get(curr['sender'], curr['sender_name'] or curr['sender'])

                summary = curr['summary']
                if isinstance(summary, (bytes, bytearray)):
                    summary = _decode_message_content(summary, curr.get("msg_type", 0), None)
                if summary and ':\n' in summary:
                    summary = summary.split(':\n', 1)[1]
                summary = _render_link_or_quote_text(curr['msg_type'], summary, None)
                summary = _finalize_display_content(curr['msg_type'], summary)
                link_source, link_url = _extract_link_meta(curr['msg_type'], summary, None)

                msg_data = {
                    'time': datetime.fromtimestamp(curr['timestamp']).strftime('%H:%M:%S'),
                    'timestamp': curr['timestamp'],
                    'chat': display,
                    'username': username,
                    'is_group': is_group,
                    'sender': sender,
                    'type': format_msg_type(curr['msg_type']),
                    'type_icon': msg_type_icon(curr['msg_type']),
                    'content': summary,
                    'unread': curr['unread'],
                    'link_source': link_source,
                    'link_url': link_url,
                    'decrypt_ms': round(self.decrypt_ms, 1),
                    'pages': self.patched_pages,
                }

                # Enrich rich/media content from message db when possible.
                try:
                    near_rows = self._query_message_rows(
                        username=username,
                        start_ts=int(curr["timestamp"]) - 2,
                        end_ts=int(curr["timestamp"]) + 2,
                    )
                    curr_ts = int(curr.get("timestamp", 0) or 0)
                    want_type = _normalize_msg_type(curr.get("msg_type", 0))
                    picked = None
                    same_ts_rows = [
                        row for row in near_rows
                        if int(row.get("timestamp", 0) or 0) == curr_ts
                    ]
                    for row in same_ts_rows:
                        if _normalize_msg_type(row.get("local_type", 0)) == want_type:
                            picked = row
                            break
                    if not picked and same_ts_rows:
                        same_ts_rows.sort(
                            key=lambda row: (
                                int(row.get("local_id", 0) or 0),
                                int(row.get("server_id", 0) or 0),
                                _normalize_msg_type(row.get("local_type", 0)),
                            )
                        )
                        picked = same_ts_rows[-1]
                    if picked:
                        rich_msg = self._build_message_from_row(
                            username=username,
                            display=display,
                            row=picked,
                            unread=curr.get("unread", 0),
                        )
                        for k in (
                            "content",
                            "sender",
                            "type",
                            "type_icon",
                            "link_source",
                            "link_url",
                            "local_id",
                            "server_id",
                            "media_url",
                            "rich_media",
                        ):
                            v = rich_msg.get(k)
                            if v not in (None, ""):
                                msg_data[k] = v
                except Exception:
                    pass

                new_msgs.append(msg_data)

                prev_ts = int(prev.get("timestamp", 0) or 0)
                if prev_ts > 0:
                    _hidden_executor.submit(
                        self._check_hidden_messages,
                        username,
                        prev_ts,
                        int(curr.get("timestamp", 0) or 0),
                        curr.get("msg_type", 0),
                        display,
                    )

        # 閹稿妞傞梻瀛樺笓鎼?
        new_msgs.sort(key=lambda m: m['timestamp'])

        if new_msgs:
            _analysis_cache_clear()

        for msg in new_msgs:
            with messages_lock:
                messages_log.append(msg)
                if len(messages_log) > MAX_LOG:
                    messages_log = messages_log[-MAX_LOG:]

            broadcast_sse(msg)
            _maybe_schedule_live_alert(msg, monitor_obj=self)

            try:
                now = time.time()
                msg_age = now - msg['timestamp']
                tag = f"{self.patched_pages}pg/{self.decrypt_ms:.0f}ms"
                sender = msg['sender']
                now_str = datetime.fromtimestamp(now).strftime('%H:%M:%S')
                if sender:
                    print(f"[{msg['time']} 瀵ゆ儼绻?{msg_age:.1f}s] [{msg['chat']}] {sender}: {msg['content']}  ({tag})", flush=True)
                else:
                    print(f"[{msg['time']} 瀵ゆ儼绻?{msg_age:.1f}s] [{msg['chat']}] {msg['content']}  ({tag})", flush=True)
            except Exception:
                pass  # Windows CMD缂傛牜鐖滈梻顕€顣介敍灞肩瑝瑜板崬鎼稴SE閹恒劑鈧?

        self.prev_state = curr_state
        _set_session_state_snapshot(curr_state)

def monitor_thread(enc_key, session_db, contact_names):
    mon = SessionMonitor(enc_key, session_db, contact_names)
    try:
        mon.do_full_refresh()
        print(f"[init] snapshot {mon.patched_pages}pg/{mon.decrypt_ms:.0f}ms", flush=True)
        mon.prev_state = mon.query_state()
        _set_session_state_snapshot(mon.prev_state)
    except Exception as e:
        print(f"[fatal] init session snapshot failed: {e}", flush=True)
        return

    wal_path = mon.wal_path
    print(f"[monitor] tracking {len(mon.prev_state)} sessions", flush=True)
    print(f"[monitor] mtime polling mode ({POLL_MS}ms)", flush=True)

    # mtime-based 鏉烆喛顕? WAL閺勵垶顣╅崚鍡涘帳閸ュ搫鐣炬径褍鐨敍灞肩瑝閼崇晫鏁ize濡偓濞?
    poll_interval = POLL_MS / 1000
    prev_wal_mtime = os.path.getmtime(wal_path) if os.path.exists(wal_path) else 0
    prev_db_mtime = os.path.getmtime(session_db)

    while True:
        time.sleep(poll_interval)
        try:
            # Poll WAL/DB mtime and refresh when either file changes.
            try:
                wal_mtime = os.path.getmtime(wal_path) if os.path.exists(wal_path) else 0
                db_mtime = os.path.getmtime(session_db)
            except OSError:
                continue

            if wal_mtime == prev_wal_mtime and db_mtime == prev_db_mtime:
                continue  # 閺冪姴褰夐崠?

            t_detect = time.perf_counter()
            wal_changed = wal_mtime != prev_wal_mtime
            db_changed = db_mtime != prev_db_mtime

            mon.check_updates()

            t_done = time.perf_counter()
            try:
                detect_str = datetime.now().strftime('%H:%M:%S.%f')[:-3]
                print(
                    f"  [{detect_str}] WAL={'Y' if wal_changed else '-'} "
                    f"DB={'Y' if db_changed else '-'} total={(t_done-t_detect)*1000:.1f}ms",
                    flush=True
                )
            except Exception:
                pass

            prev_wal_mtime = wal_mtime
            prev_db_mtime = db_mtime

        except Exception as e:
            print(f"[poll] 闁挎瑨顕? {e}", flush=True)
            time.sleep(1)


# ============ Web ============


def _safe_int(value, default, min_value=None, max_value=None):
    try:
        n = int(value)
    except Exception:
        return default
    if min_value is not None and n < min_value:
        n = min_value
    if max_value is not None and n > max_value:
        n = max_value
    return n


def _parse_time_range(query):
    start_ts = _safe_int(query.get('start_ts', ['0'])[0], 0, 0, None)
    end_ts = _safe_int(query.get('end_ts', ['0'])[0], 0, 0, None)
    if start_ts and end_ts and start_ts > end_ts:
        start_ts, end_ts = end_ts, start_ts
    return start_ts, end_ts


def _normalize_keyword(keyword):
    return re.sub(r"\s+", " ", str(keyword or "")).strip()


def _history_row_matches_keyword(row, keyword):
    kw = _normalize_keyword(keyword).lower()
    if not kw:
        return True
    if not isinstance(row, dict):
        return False
    for field in ("content", "sender", "chat", "type", "link_source", "link_url"):
        text = str(row.get(field, "") or "")
        if kw in text.lower():
            return True
    rich = row.get("rich_media")
    if isinstance(rich, dict):
        for field in ("kind", "badge", "title", "desc", "source", "url", "meta", "body", "quote", "quote_author"):
            text = str(rich.get(field, "") or "")
            if kw in text.lower():
                return True
        items = rich.get("items")
        if isinstance(items, list):
            for item in items:
                if isinstance(item, dict):
                    blob = " ".join(str(item.get(k, "") or "") for k in ("name", "text"))
                else:
                    blob = str(item or "")
                if kw in blob.lower():
                    return True
    return False


def _safe_export_filename_part(text, fallback="chat"):
    name = str(text or "").strip() or str(fallback or "chat")
    name = re.sub(r"[<>:\"/\\|?*]+", "_", name)
    name = re.sub(r"[\x00-\x1f]+", "", name)
    name = name.strip(" .")
    if not name:
        name = str(fallback or "chat")
    if len(name) > 96:
        name = name[:96]
    return name


def _format_export_range_label(start_ts=0, end_ts=0):
    if start_ts and end_ts:
        return (
            f"{datetime.fromtimestamp(int(start_ts)).strftime('%Y-%m-%d')} "
            f"~ {datetime.fromtimestamp(int(end_ts)).strftime('%Y-%m-%d')}"
        )
    if start_ts:
        return f"{datetime.fromtimestamp(int(start_ts)).strftime('%Y-%m-%d')} 起"
    if end_ts:
        return f"至 {datetime.fromtimestamp(int(end_ts)).strftime('%Y-%m-%d')}"
    return "全部时间"


def _build_export_markdown(chat_title, scope_label, rows):
    title = str(chat_title or "wechat_monitor")
    scope = str(scope_label or "褰撳墠浼氳瘽")
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        f"# {title} 瀵煎嚭",
        "",
        f"瀵煎嚭鏃堕棿: {now_str}",
        f"瀵煎嚭鑼冨洿: {scope}",
        f"娑堟伅鏉℃暟: {len(rows) if isinstance(rows, list) else 0}",
        "",
        "---",
        "",
    ]
    for item in (rows or []):
        if not isinstance(item, dict):
            continue
        ts = _safe_int(item.get("timestamp", 0), 0, 0, None)
        time_text = str(item.get("time", "") or "").strip()
        if not time_text and ts:
            time_text = datetime.fromtimestamp(ts).strftime("%m-%d %H:%M:%S")
        chat_name = str(item.get("chat", "") or title)
        sender = str(item.get("sender", "") or "").strip()
        msg_type = str(item.get("type", "") or "娑堟伅").strip() or "娑堟伅"
        content = str(item.get("content", "") or "").strip()

        head = f"**[{time_text}] {chat_name}**"
        if sender:
            head += f" - {sender}"
        lines.append(head)

        if content:
            for line in content.splitlines():
                lines.append(f"> [{msg_type}] {line}")
        else:
            lines.append(f"> [{msg_type}]")

        media_url = str(item.get("media_url", "") or "").strip()
        if media_url:
            lines.append(f"> 濯掍綋: {media_url}")
            lines.append(f"![濯掍綋]({media_url})")

        link_source = str(item.get("link_source", "") or "").strip()
        link_url = str(item.get("link_url", "") or "").strip()
        if link_source:
            lines.append(f"> 鏉ユ簮: {link_source}")
        if link_url:
            lines.append(f"> 閾炬帴: {link_url}")

        lines.append("")
    return "\n".join(lines)


def _fetch_local_chat_history(username, limit=0, start_ts=0, end_ts=0, keyword=""):
    u = str(username or "").strip()
    if not u:
        return []
    params = {
        "username": u,
    }
    n_limit = _safe_int(limit, 0, 0, 2000000)
    if n_limit > 0:
        params["limit"] = str(n_limit)
    n_start = _safe_int(start_ts, 0, 0, None)
    n_end = _safe_int(end_ts, 0, 0, None)
    if n_start:
        params["start_ts"] = str(n_start)
    if n_end:
        params["end_ts"] = str(n_end)
    kw = _normalize_keyword(keyword)
    if kw:
        params["keyword"] = kw

    url = f"http://127.0.0.1:{PORT}/api/chat_history?{urllib.parse.urlencode(params)}"
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=600) as resp:
        raw = resp.read()
    obj = json.loads(raw.decode("utf-8", errors="replace") or "[]")
    return obj if isinstance(obj, list) else []


def _ai_provider_label(provider_name):
    p = str(provider_name or '').strip().lower()
    if p == 'openai_compat':
        return 'OpenAI 兼容'
    if p == 'anthropic_compat':
        return 'Anthropic 兼容'
    return 'Claude Code'


def _normalize_provider_name(provider_name):
    p = str(provider_name or '').strip().lower()
    if p in ('openai_compat', 'anthropic_compat', 'claude_cli'):
        return p
    return 'openai_compat'


def _provider_default_base_url(provider_name):
    p = _normalize_provider_name(provider_name)
    if p == 'anthropic_compat':
        return 'https://coding.dashscope.aliyuncs.com/apps/anthropic'
    if p == 'openai_compat':
        return 'https://coding.dashscope.aliyuncs.com/v1'
    return ''


def _fallback_ai_provider_seed():
    try:
        claude = _probe_claude_status()
        if bool(claude.get('claude_installed', False)):
            return {
                'provider': 'claude_cli',
                'base_url': '',
                'api_key': '',
                'model': 'claude_cli',
            }
    except Exception:
        pass
    return {}


def _normalize_ai_provider_config(data, prev_cfg=None):
    cfg = dict(AI_PROVIDER_DEFAULT)
    if isinstance(prev_cfg, dict):
        cfg.update(prev_cfg)
    if isinstance(data, dict):
        cfg.update(data)

    provider = _normalize_provider_name(cfg.get('provider', AI_PROVIDER_DEFAULT.get('provider', 'openai_compat')))
    cfg['provider'] = provider
    cfg['surface_routes'] = _normalize_ai_surface_routes(
        data if isinstance(data, dict) else {},
        prev_cfg=prev_cfg if isinstance(prev_cfg, dict) else {},
        provider=provider,
    )

    model = str(cfg.get('model', '') or '').strip()
    if provider == 'claude_cli':
        cfg['base_url'] = ''
        cfg['api_key'] = ''
        cfg['model'] = 'claude_cli'
    else:
        base_url = str(cfg.get('base_url', '') or '').strip()
        cfg['base_url'] = base_url or _provider_default_base_url(provider)
        cfg['api_key'] = str(cfg.get('api_key', '') or '').strip()
        cfg['model'] = model or str(AI_PROVIDER_DEFAULT.get('model', 'qwen3-coder-plus'))

    try:
        temp_raw = float(cfg.get('temperature', 0.2) or 0.2)
    except Exception:
        temp_raw = 0.2
    cfg['temperature'] = float(_safe_int(int(temp_raw * 100), 20, 0, 200)) / 100.0
    cfg['max_tokens'] = _safe_int(cfg.get('max_tokens', 4000), 4000, 128, 65536)
    cfg['timeout_sec'] = _safe_int(cfg.get('timeout_sec', 180), 180, 15, 600)
    cfg['anthropic_version'] = str(cfg.get('anthropic_version', '2023-06-01') or '2023-06-01').strip()
    return cfg


def _normalize_ai_surface_name(surface):
    key = str(surface or "").strip().lower()
    return key if key in AI_SURFACE_KEYS else "insight"


def _normalize_ai_surface_route(value, fallback='shared_api'):
    route = str(value or "").strip().lower()
    if route in ("claude_cli", "shared_api"):
        return route
    return str(fallback or "shared_api")


def _default_ai_surface_routes(provider='openai_compat'):
    routes = dict(AI_SURFACE_ROUTE_DEFAULTS)
    if _normalize_provider_name(provider) == 'claude_cli':
        routes['insight'] = 'claude_cli'
    return routes


def _normalize_ai_surface_routes(data=None, prev_cfg=None, provider='openai_compat'):
    routes = _default_ai_surface_routes(provider)

    prev_routes = {}
    if isinstance(prev_cfg, dict) and isinstance(prev_cfg.get('surface_routes'), dict):
        prev_routes = prev_cfg.get('surface_routes') or {}
    for key in AI_SURFACE_KEYS:
        routes[key] = _normalize_ai_surface_route(prev_routes.get(key), routes.get(key, 'shared_api'))

    raw_routes = {}
    if isinstance(data, dict) and isinstance(data.get('surface_routes'), dict):
        raw_routes = data.get('surface_routes') or {}
    elif isinstance(data, dict) and any(k in data for k in AI_SURFACE_KEYS):
        raw_routes = {k: data.get(k) for k in AI_SURFACE_KEYS if k in data}

    if not raw_routes and _normalize_provider_name(provider) == 'claude_cli' and not prev_routes:
        routes['insight'] = 'claude_cli'

    for key in AI_SURFACE_KEYS:
        if key in raw_routes:
            routes[key] = _normalize_ai_surface_route(raw_routes.get(key), routes.get(key, 'shared_api'))
    return routes


def _resolve_ai_provider_config(override=None):
    current = _load_ai_provider_config()
    merged = dict(current)
    if isinstance(override, dict):
        for key in AI_PROVIDER_OVERRIDE_KEYS:
            if key in override:
                merged[key] = override.get(key)
    return _normalize_ai_provider_config(merged, prev_cfg={})


def _resolve_ai_provider_config_for_surface(surface, override=None):
    cfg = _resolve_ai_provider_config(override)
    surface_key = _normalize_ai_surface_name(surface)
    routes = cfg.get('surface_routes') if isinstance(cfg.get('surface_routes'), dict) else {}
    route = _normalize_ai_surface_route(routes.get(surface_key), AI_SURFACE_ROUTE_DEFAULTS.get(surface_key, 'shared_api'))
    if route == 'claude_cli':
        local_cfg = dict(cfg)
        local_cfg.update({
            'provider': 'claude_cli',
            'base_url': '',
            'api_key': '',
            'model': 'claude_cli',
        })
        return _normalize_ai_provider_config(local_cfg, prev_cfg={})
    if _normalize_provider_name(cfg.get('provider', 'openai_compat')) == 'claude_cli':
        raise RuntimeError("当前共享 API 仍配置为 Claude Code，请先在设置里改成外部 API。")
    return cfg


def _load_ai_provider_config():
    global ai_provider_config
    with ai_provider_lock:
        if isinstance(ai_provider_config, dict) and ai_provider_config:
            return dict(ai_provider_config)
        loaded = None
        try:
            if os.path.exists(AI_PROVIDER_FILE):
                with open(AI_PROVIDER_FILE, 'r', encoding='utf-8') as f:
                    obj = json.load(f)
                if isinstance(obj, dict):
                    loaded = obj
        except Exception as e:
            print(f"[ai] load provider config failed: {e}", flush=True)
        seed = loaded if isinstance(loaded, dict) and loaded else _fallback_ai_provider_seed()
        cfg = _normalize_ai_provider_config(seed or {})
        ai_provider_config = dict(cfg)
        return dict(cfg)


def _save_ai_provider_config(cfg):
    with ai_provider_lock:
        final_cfg = _normalize_ai_provider_config(cfg or {}, prev_cfg={})
        ai_provider_config.clear()
        ai_provider_config.update(final_cfg)
        os.makedirs(os.path.dirname(AI_PROVIDER_FILE), exist_ok=True)
        with open(AI_PROVIDER_FILE, 'w', encoding='utf-8') as f:
            json.dump(ai_provider_config, f, ensure_ascii=False, indent=2)
        return dict(ai_provider_config)


def _get_ai_provider_config(mask_secret=False):
    cfg = _load_ai_provider_config()
    if not mask_secret:
        return cfg
    out = dict(cfg)
    raw_key = str(out.get('api_key', '') or '')
    out['has_api_key'] = bool(raw_key)
    if raw_key:
        if len(raw_key) <= 10:
            out['api_key_masked'] = '*' * len(raw_key)
        else:
            out['api_key_masked'] = raw_key[:6] + '...' + raw_key[-4:]
    else:
        out['api_key_masked'] = ''
    out['api_key'] = ''
    out['provider_label'] = _ai_provider_label(out.get('provider'))
    out['surface_routes'] = dict(cfg.get('surface_routes') or {})
    return out


def _update_ai_provider_config(payload):
    current = _load_ai_provider_config()
    merged = dict(current)
    if isinstance(payload, dict):
        for k in (
            'provider',
            'base_url',
            'api_key',
            'model',
            'temperature',
            'max_tokens',
            'timeout_sec',
            'anthropic_version',
            'surface_routes',
        ):
            if k in payload:
                merged[k] = payload.get(k)
    final_cfg = _normalize_ai_provider_config(merged, prev_cfg={})
    _save_ai_provider_config(final_cfg)
    return _get_ai_provider_config(mask_secret=True)


def _as_keyword_list(value):
    if isinstance(value, list):
        raw_items = value
    else:
        raw_items = re.split(r"[\r\n,，；;]+", str(value or ""))
    out = []
    seen = set()
    for item in raw_items:
        token = str(item or "").strip()
        if not token:
            continue
        low = token.lower()
        if low in seen:
            continue
        seen.add(low)
        out.append(token)
    return out


def _normalize_live_alert_categories(value):
    raw_items = _as_keyword_list(value)
    out = []
    seen = set()
    for item in raw_items:
        token = str(item or "").strip().lower()
        if not token or token not in LIVE_ALERT_ALLOWED_CATEGORIES or token in seen:
            continue
        seen.add(token)
        out.append(token)
    return out


def _normalize_live_alert_config(data, prev_cfg=None):
    prev = prev_cfg if isinstance(prev_cfg, dict) else {}
    merged = dict(LIVE_ALERT_DEFAULT)
    merged.update(prev)
    if isinstance(data, dict):
        merged.update(data)

    out = dict(LIVE_ALERT_DEFAULT)
    out["enabled"] = bool(merged.get("enabled", LIVE_ALERT_DEFAULT["enabled"]))
    out["browser_notifications"] = bool(merged.get("browser_notifications", LIVE_ALERT_DEFAULT["browser_notifications"]))
    out["openclaw_push_enabled"] = bool(merged.get("openclaw_push_enabled", LIVE_ALERT_DEFAULT["openclaw_push_enabled"]))
    out["openclaw_push_silent"] = bool(merged.get("openclaw_push_silent", LIVE_ALERT_DEFAULT["openclaw_push_silent"]))
    watch_mode = str(merged.get("watch_mode", LIVE_ALERT_DEFAULT["watch_mode"]) or "").strip().lower()
    if watch_mode not in ("pinned_auto", "manual"):
        watch_mode = str(LIVE_ALERT_DEFAULT["watch_mode"])
    out["watch_mode"] = watch_mode
    out["watch_usernames"] = _as_keyword_list(merged.get("watch_usernames", []))

    for key in ("product_keywords", "question_keywords", "issue_keywords", "purchase_keywords", "ignore_keywords"):
        out[key] = _as_keyword_list(merged.get(key, LIVE_ALERT_DEFAULT.get(key, [])))
    out["openclaw_push_categories"] = _normalize_live_alert_categories(
        merged.get("openclaw_push_categories", LIVE_ALERT_DEFAULT["openclaw_push_categories"])
    )

    out["ai_extra_prompt"] = str(merged.get("ai_extra_prompt", "") or "").strip()
    out["openclaw_push_chat_id"] = str(
        merged.get("openclaw_push_chat_id", LIVE_ALERT_DEFAULT["openclaw_push_chat_id"]) or ""
    ).strip()
    out["openclaw_push_topic_label"] = str(
        merged.get("openclaw_push_topic_label", LIVE_ALERT_DEFAULT["openclaw_push_topic_label"]) or ""
    ).strip() or str(LIVE_ALERT_DEFAULT["openclaw_push_topic_label"])

    def _clamp_int(key, default, lo, hi):
        try:
            value = int(merged.get(key, default) or default)
        except Exception:
            value = int(default)
        if value < lo:
            value = lo
        if value > hi:
            value = hi
        return int(value)

    out["cooldown_sec"] = _clamp_int("cooldown_sec", LIVE_ALERT_DEFAULT["cooldown_sec"], 60, 86400)
    out["context_window_sec"] = _clamp_int("context_window_sec", LIVE_ALERT_DEFAULT["context_window_sec"], 60, 3600)
    out["context_message_limit"] = _clamp_int("context_message_limit", LIVE_ALERT_DEFAULT["context_message_limit"], 2, 20)
    out["candidate_min_score"] = _clamp_int("candidate_min_score", LIVE_ALERT_DEFAULT["candidate_min_score"], 1, 12)
    out["openclaw_push_thread_id"] = _clamp_int(
        "openclaw_push_thread_id",
        LIVE_ALERT_DEFAULT["openclaw_push_thread_id"],
        1,
        100000000,
    )

    severity = str(merged.get("notify_min_severity", LIVE_ALERT_DEFAULT["notify_min_severity"]) or "").strip().lower()
    if severity not in LIVE_ALERT_SEVERITY_ORDER:
        severity = str(LIVE_ALERT_DEFAULT["notify_min_severity"])
    out["notify_min_severity"] = severity

    push_severity = str(
        merged.get("openclaw_push_min_severity", LIVE_ALERT_DEFAULT["openclaw_push_min_severity"]) or ""
    ).strip().lower()
    if push_severity not in LIVE_ALERT_SEVERITY_ORDER:
        push_severity = str(LIVE_ALERT_DEFAULT["openclaw_push_min_severity"])
    out["openclaw_push_min_severity"] = push_severity
    return out


def _load_live_alert_config():
    global live_alert_config
    with live_alert_config_lock:
        if isinstance(live_alert_config, dict) and live_alert_config:
            return dict(live_alert_config)
        loaded = None
        try:
            if os.path.exists(LIVE_ALERT_CONFIG_FILE):
                with open(LIVE_ALERT_CONFIG_FILE, "r", encoding="utf-8") as f:
                    obj = json.load(f)
                if isinstance(obj, dict):
                    loaded = obj
        except Exception as e:
            print(f"[live_alert] load config failed: {e}", flush=True)
        final_cfg = _normalize_live_alert_config(loaded or {}, prev_cfg={})
        live_alert_config = dict(final_cfg)
        return dict(final_cfg)


def _save_live_alert_config(cfg):
    with live_alert_config_lock:
        final_cfg = _normalize_live_alert_config(cfg or {}, prev_cfg={})
        live_alert_config.clear()
        live_alert_config.update(final_cfg)
        os.makedirs(os.path.dirname(LIVE_ALERT_CONFIG_FILE), exist_ok=True)
        with open(LIVE_ALERT_CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(live_alert_config, f, ensure_ascii=False, indent=2)
        return dict(live_alert_config)


def _get_live_alert_config():
    return _load_live_alert_config()


def _update_live_alert_config(payload):
    current = _load_live_alert_config()
    merged = dict(current)
    if isinstance(payload, dict):
        for key in (
            "enabled",
            "browser_notifications",
            "openclaw_push_enabled",
            "openclaw_push_silent",
            "watch_mode",
            "watch_usernames",
            "notify_min_severity",
            "openclaw_push_min_severity",
            "cooldown_sec",
            "context_window_sec",
            "context_message_limit",
            "candidate_min_score",
            "openclaw_push_chat_id",
            "openclaw_push_thread_id",
            "openclaw_push_topic_label",
            "openclaw_push_categories",
            "product_keywords",
            "question_keywords",
            "issue_keywords",
            "purchase_keywords",
            "ignore_keywords",
            "ai_extra_prompt",
        ):
            if key in payload:
                merged[key] = payload.get(key)
    return _save_live_alert_config(merged)


def _load_live_alerts():
    global live_alerts
    with live_alerts_lock:
        if isinstance(live_alerts, list) and live_alerts:
            return [dict(x) for x in live_alerts]
        loaded = []
        try:
            if os.path.exists(LIVE_ALERTS_FILE):
                with open(LIVE_ALERTS_FILE, "r", encoding="utf-8") as f:
                    obj = json.load(f)
                if isinstance(obj, list):
                    loaded = [dict(x) for x in obj if isinstance(x, dict)]
        except Exception as e:
            print(f"[live_alert] load alerts failed: {e}", flush=True)
        live_alerts = loaded[:LIVE_ALERT_MAX_ITEMS]
        return [dict(x) for x in live_alerts]


def _write_live_alerts_unlocked(rows):
    os.makedirs(os.path.dirname(LIVE_ALERTS_FILE), exist_ok=True)
    with open(LIVE_ALERTS_FILE, "w", encoding="utf-8") as f:
        json.dump(rows[:LIVE_ALERT_MAX_ITEMS], f, ensure_ascii=False, indent=2)


def _save_live_alerts():
    with live_alerts_lock:
        rows = [dict(x) for x in live_alerts[:LIVE_ALERT_MAX_ITEMS]]
        _write_live_alerts_unlocked(rows)


def _severity_rank(level):
    return int(LIVE_ALERT_SEVERITY_ORDER.get(str(level or "").strip().lower(), 0))


def _severity_meets_threshold(level, min_level):
    return _severity_rank(level) >= _severity_rank(min_level)


def _live_alert_meets_threshold(level, cfg):
    min_level = str((cfg or {}).get("notify_min_severity", LIVE_ALERT_DEFAULT["notify_min_severity"]) or "").strip().lower()
    return _severity_meets_threshold(level, min_level)


def _live_alert_category_label(category):
    key = str(category or "").strip().lower()
    return str(LIVE_ALERT_CATEGORY_LABELS.get(key, LIVE_ALERT_CATEGORY_LABELS["other"]))


def _resolve_python_executable():
    candidates = []
    if not getattr(sys, "frozen", False) and sys.executable:
        candidates.append(sys.executable)
    for name in ("python", "py"):
        path = shutil.which(name)
        if path and path not in candidates:
            candidates.append(path)
    if getattr(sys, "frozen", False) and sys.executable and sys.executable not in candidates:
        candidates.append(sys.executable)
    return candidates[0] if candidates else ""


def _should_push_live_alert_to_openclaw(alert_obj, cfg):
    if not bool((cfg or {}).get("openclaw_push_enabled", False)):
        return False, "disabled"
    chat_id = str((cfg or {}).get("openclaw_push_chat_id", "") or "").strip()
    if not chat_id:
        return False, "missing_chat_id"
    level = str((alert_obj or {}).get("severity", "low") or "low").strip().lower()
    min_level = str((cfg or {}).get("openclaw_push_min_severity", "medium") or "medium").strip().lower()
    if not _severity_meets_threshold(level, min_level):
        return False, "below_threshold"
    allowed_categories = _normalize_live_alert_categories((cfg or {}).get("openclaw_push_categories", []))
    category = str((alert_obj or {}).get("category", "other") or "other").strip().lower()
    if allowed_categories and category not in allowed_categories:
        return False, "category_filtered"
    return True, "ready"


def _format_openclaw_live_alert_message(alert_obj, cfg):
    row = alert_obj if isinstance(alert_obj, dict) else {}

    def _clip(value, limit):
        text = re.sub(r"\s+", " ", str(value or "").strip())
        if len(text) > limit:
            return text[:limit].rstrip() + "..."
        return text

    severity_label_map = {
        "low": "低",
        "medium": "中",
        "high": "高",
    }
    created_at = int(row.get("created_at", 0) or 0)
    if created_at > 0:
        time_text = datetime.fromtimestamp(created_at).strftime("%m-%d %H:%M")
    else:
        time_text = ""

    category_label = _live_alert_category_label(row.get("category"))
    title = _clip(str(row.get("title", "") or category_label).strip(), 42)
    severity_key = str(row.get("severity", "medium") or "medium").strip().lower()
    severity_label = str(severity_label_map.get(severity_key, "中"))
    confidence = int(row.get("confidence", 0) or 0)

    reason = _clip(row.get("reason", ""), 120)
    summary = _clip(row.get("summary", ""), 120)
    content = _clip(row.get("content", ""), 120)
    if summary:
        summary_text = summary
    elif reason:
        summary_text = reason
    else:
        summary_text = content

    chat = str(row.get("chat", "") or "").strip()
    sender = str(row.get("sender", "") or "").strip()
    lines = [f"【社群问题提醒】{category_label}"]
    if chat:
        lines.append(f"群聊：{chat}")
    if sender:
        lines.append(f"发送者：{sender}")
    if time_text:
        lines.append(f"时间：{time_text}")
    lines.append(f"等级：{severity_label} · 置信 {confidence}%")
    lines.extend(["", f"标题：{title}"])
    if summary_text:
        lines.append(f"摘要：{summary_text}")
    if content and content != summary_text:
        lines.append(f"原消息：{content}")
    suggested_action = str(row.get("suggested_action", "") or "").strip()
    if suggested_action:
        lines.append(f"建议：{_clip(suggested_action, 80)}")
    return "\n".join(line for line in lines if str(line or "").strip())


def _dispatch_live_alert_to_openclaw(alert_obj, cfg):
    should_push, reason = _should_push_live_alert_to_openclaw(alert_obj, cfg)
    if not bool((cfg or {}).get("openclaw_push_enabled", False)):
        return None

    meta = {
        "status": "skipped",
        "reason": reason,
        "sent": False,
        "chat_id": str((cfg or {}).get("openclaw_push_chat_id", "") or "").strip(),
        "thread_id": int((cfg or {}).get("openclaw_push_thread_id", OPENCLAW_DEFAULT_NOTES_THREAD_ID) or OPENCLAW_DEFAULT_NOTES_THREAD_ID),
        "topic_label": str((cfg or {}).get("openclaw_push_topic_label", OPENCLAW_DEFAULT_NOTES_LABEL) or OPENCLAW_DEFAULT_NOTES_LABEL).strip(),
        "at": int(time.time()),
    }
    if not should_push:
        return meta
    if not os.path.exists(OPENCLAW_ALERT_PUSH_SCRIPT):
        meta["status"] = "failed"
        meta["reason"] = "missing_skill_script"
        meta["error"] = OPENCLAW_ALERT_PUSH_SCRIPT
        return meta

    python_exe = _resolve_python_executable()
    if not python_exe:
        meta["status"] = "failed"
        meta["reason"] = "missing_python"
        meta["error"] = "python_not_found"
        return meta

    message_text = _format_openclaw_live_alert_message(alert_obj, cfg)
    args = [
        python_exe,
        OPENCLAW_ALERT_PUSH_SCRIPT,
        "--message",
        message_text,
        "--chat-id",
        meta["chat_id"],
        "--thread-id",
        str(meta["thread_id"]),
        "--topic-label",
        meta["topic_label"],
    ]
    if bool((cfg or {}).get("openclaw_push_silent", False)):
        args.append("--silent")

    code, out, err = _run_cmd(args, timeout=25)
    raw_text = str(out or err or "").strip()
    payload = None
    if out:
        try:
            payload = json.loads(out)
        except Exception:
            payload = None

    if code == 0 and isinstance(payload, dict) and bool(payload.get("ok", False)):
        meta["status"] = "sent"
        meta["reason"] = "sent"
        meta["sent"] = True
        result_obj = payload.get("result") if isinstance(payload.get("result"), dict) else {}
        if result_obj.get("message_id") is not None:
            meta["message_id"] = result_obj.get("message_id")
        return meta

    meta["status"] = "failed"
    meta["reason"] = "send_failed"
    meta["error"] = raw_text or f"exit_code={code}"
    return meta


def _live_alert_event_ts(row):
    if not isinstance(row, dict):
        return 0
    return int(row.get("message_ts", 0) or row.get("created_at", 0) or 0)


def _live_alert_sort_key(row):
    if not isinstance(row, dict):
        return (0, 0)
    return (
        int(row.get("created_at", 0) or 0),
        int(row.get("message_ts", 0) or 0),
    )


def _live_alert_status_matches(row, status):
    target = str(status or "").strip().lower()
    if target in ("", "all"):
        return True
    row_status = str((row or {}).get("status", "open") or "open").strip().lower()
    if target == "history":
        return row_status in ("acknowledged", "dismissed")
    return row_status == target


def _live_alert_search_text(row):
    if not isinstance(row, dict):
        return ""
    parts = [
        row.get("title", ""),
        row.get("summary", ""),
        row.get("reason", ""),
        row.get("content", ""),
        row.get("chat", ""),
        row.get("sender", ""),
        row.get("severity", ""),
        row.get("category", ""),
        _live_alert_category_label(row.get("category")),
    ]
    return "\n".join(str(x or "") for x in parts).strip().lower()


def _filter_live_alert_rows(rows, status="all", keyword="", category="", start_ts=0, end_ts=0):
    keyword = str(keyword or "").strip().lower()
    category = str(category or "").strip().lower()
    out = []
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        row_category = str(row.get("category", "") or "").strip().lower()
        if category and row_category != category:
            continue
        ts = _live_alert_event_ts(row)
        if start_ts and ts < int(start_ts):
            continue
        if end_ts and ts > int(end_ts):
            continue
        if keyword and keyword not in _live_alert_search_text(row):
            continue
        if not _live_alert_status_matches(row, status):
            continue
        out.append(dict(row))
    out.sort(key=_live_alert_sort_key, reverse=True)
    return out


def _count_live_alert_statuses(rows):
    counts = {
        "all": 0,
        "open": 0,
        "history": 0,
        "acknowledged": 0,
        "dismissed": 0,
    }
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        counts["all"] += 1
        status = str(row.get("status", "open") or "open").strip().lower()
        if status in counts:
            counts[status] += 1
        if status in ("acknowledged", "dismissed"):
            counts["history"] += 1
    return counts


def _list_live_alerts(limit=60, status="open", keyword="", category="", start_ts=0, end_ts=0):
    rows = _load_live_alerts()
    try:
        limit = max(1, min(int(limit or 60), LIVE_ALERT_MAX_ITEMS))
    except Exception:
        limit = 60
    rows = _filter_live_alert_rows(
        rows,
        status=status,
        keyword=keyword,
        category=category,
        start_ts=start_ts,
        end_ts=end_ts,
    )
    return rows[:limit]


def _prune_live_alert_recent(now_ts=None):
    now = float(now_ts or time.time())
    cutoff = now - float(max(LIVE_ALERT_SKIP_COOLDOWN_SEC, 3600))
    with live_alert_task_lock:
        stale = [k for k, ts in live_alert_recent.items() if float(ts or 0.0) < cutoff]
        for key in stale:
            live_alert_recent.pop(key, None)


def _make_live_alert_title(category, chat, sender, content):
    prefix_map = {
        "product_question": "产品咨询",
        "bug_report": "故障反馈",
        "purchase_intent": "购买信号",
        "negative_feedback": "负反馈",
        "repeat_question": "重复追问",
    }
    prefix = prefix_map.get(str(category or "").strip(), "群聊提醒")
    who = str(sender or "").strip()
    body = str(content or "").strip().replace("\n", " ")
    if len(body) > 28:
        body = body[:28] + "..."
    if who:
        return f"{prefix} · {who}: {body or chat}"
    return f"{prefix} · {body or chat}"


def _append_live_alert(alert_obj):
    _load_live_alerts()
    row = dict(alert_obj or {})
    if not row:
        return None
    with live_alerts_lock:
        existing = None
        dedupe_key = str(row.get("dedupe_key", "") or "").strip()
        for item in live_alerts:
            if dedupe_key and str(item.get("dedupe_key", "") or "").strip() == dedupe_key:
                existing = item
                break
        if existing is not None:
            existing.update(row)
            existing["updated_at"] = int(time.time())
            row = dict(existing)
        else:
            live_alerts.insert(0, row)
            if len(live_alerts) > LIVE_ALERT_MAX_ITEMS:
                del live_alerts[LIVE_ALERT_MAX_ITEMS:]
        _write_live_alerts_unlocked([dict(x) for x in live_alerts])
    broadcast_sse({"event": "live_alert", "alert": row})
    return row


def _update_live_alert_status(alert_id, status):
    _load_live_alerts()
    status = str(status or "").strip().lower()
    if status not in ("open", "acknowledged", "dismissed"):
        raise RuntimeError("invalid alert status")
    with live_alerts_lock:
        target = None
        for item in live_alerts:
            if str(item.get("id", "") or "") == str(alert_id or ""):
                item["status"] = status
                item["updated_at"] = int(time.time())
                target = dict(item)
                break
        if target is None:
            return None
        _write_live_alerts_unlocked([dict(x) for x in live_alerts])
    broadcast_sse({"event": "live_alert_update", "alert": target})
    return target


def _live_alert_plain_text(msg):
    text = str((msg or {}).get("content", "") or "").strip()
    text = re.sub(r"\s+", " ", text)
    return text


def _live_alert_norm_text(text):
    raw = str(text or "").strip().lower()
    if not raw:
        return ""
    raw = re.sub(r"https?://\S+", " ", raw)
    raw = re.sub(r"[\s\W_]+", "", raw, flags=re.UNICODE)
    return raw


def _live_alert_contains_any(text, keywords):
    low = str(text or "").lower()
    for token in keywords or []:
        t = str(token or "").strip().lower()
        if t and t in low:
            return True
    return False


def _build_live_alert_candidate(msg, cfg):
    if not isinstance(msg, dict):
        return None
    if not bool((cfg or {}).get("enabled", False)):
        return None
    username = str(msg.get("username", "") or "").strip()
    if not username or "@chatroom" not in username:
        return None
    watch_usernames = {str(x or "").strip() for x in (cfg or {}).get("watch_usernames", []) if str(x or "").strip()}
    if not watch_usernames:
        return None
    if username not in watch_usernames:
        return None

    msg_type = str(msg.get("type", "") or "").strip()
    type_low = msg_type.lower()
    if any(token in type_low for token in ("图片", "表情", "视频", "语音", "文件", "撤回", "系统", "红包", "转账")):
        return None

    text = _live_alert_plain_text(msg)
    text_low = text.lower()
    if not text or len(text) < 2:
        return None
    if text.startswith("[") and text.endswith("]") and len(text) <= 12:
        return None

    score = 0
    tags = []
    if _live_alert_contains_any(text_low, (cfg or {}).get("question_keywords", [])):
        score += 1
        tags.append("question")
    if _live_alert_contains_any(text_low, (cfg or {}).get("product_keywords", [])):
        score += 2
        tags.append("product")
    if _live_alert_contains_any(text_low, (cfg or {}).get("issue_keywords", [])):
        score += 3
        tags.append("issue")
    if _live_alert_contains_any(text_low, (cfg or {}).get("purchase_keywords", [])):
        score += 3
        tags.append("purchase")
    if len(text) >= 18:
        score += 1
    if ("?" in text) or ("？" in text):
        score += 1

    ignore_hit = _live_alert_contains_any(text_low, (cfg or {}).get("ignore_keywords", []))
    if ignore_hit and score <= 2:
        return None

    min_score = int((cfg or {}).get("candidate_min_score", LIVE_ALERT_DEFAULT["candidate_min_score"]) or LIVE_ALERT_DEFAULT["candidate_min_score"])
    if score < min_score:
        return None

    norm_text = _live_alert_norm_text(text)
    if not norm_text:
        return None
    dedupe_key = f"{username}:{norm_text[:72]}"
    return {
        "heuristic_score": int(score),
        "tags": tags,
        "dedupe_key": dedupe_key,
        "text": text,
    }


def _ensure_dir(path):
    os.makedirs(path, exist_ok=True)
    return path


def _copy_if_newer(src, dst):
    if not src or not os.path.exists(src):
        return False
    try:
        if os.path.exists(dst):
            src_stat = os.stat(src)
            dst_stat = os.stat(dst)
            if int(src_stat.st_mtime) <= int(dst_stat.st_mtime) and int(src_stat.st_size) == int(dst_stat.st_size):
                return False
        _ensure_dir(os.path.dirname(dst))
        shutil.copy2(src, dst)
        return True
    except Exception:
        return False


def _ensure_claude_runtime_layout():
    _ensure_dir(LOG_DIR)
    _ensure_dir(CLAUDE_RUNTIME_DIR)
    _ensure_dir(CLAUDE_RUNTIME_CONFIG_DIR)
    _ensure_dir(CLAUDE_RUNTIME_TEMP_DIR)

    home_claude_dir = os.path.join(os.path.expanduser('~'), '.claude')
    for name in ('settings.json', 'settings.local.json', 'CLAUDE.md'):
        _copy_if_newer(
            os.path.join(home_claude_dir, name),
            os.path.join(CLAUDE_RUNTIME_CONFIG_DIR, name),
        )
    return {
        'config_dir': CLAUDE_RUNTIME_CONFIG_DIR,
        'temp_dir': CLAUDE_RUNTIME_TEMP_DIR,
    }


def _claude_project_mcp_path():
    target_path = os.path.join(RUNTIME_BASE_DIR, '.mcp.json')
    if os.path.exists(target_path):
        return target_path

    server_path = ''
    for cand in (
        os.path.join(RUNTIME_BASE_DIR, 'mcp_server.py'),
        os.path.join(RESOURCE_BASE_DIR, 'mcp_server.py'),
    ):
        if cand and os.path.exists(cand):
            server_path = cand
            break
    if not server_path:
        return target_path

    payload = {
        "mcpServers": {
            "wechat": {
                "type": "stdio",
                "command": "python",
                "args": [server_path],
                "env": {},
            }
        }
    }
    try:
        with open(target_path, 'w', encoding='utf-8') as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
    except Exception:
        pass
    return target_path


def _write_claude_prompt_bridge(prompt_text, suffix=''):
    _ensure_dir(CLAUDE_PROMPT_BRIDGE_DIR)
    name = f"prompt_{suffix or uuid.uuid4().hex}.txt"
    path = os.path.join(CLAUDE_PROMPT_BRIDGE_DIR, name)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(str(prompt_text or ''))
    _append_ai_debug_log('prompt_bridge', {
        'path': path,
        'preview': str(prompt_text or '')[:1000],
    })
    return path


def _build_claude_prompt_wrapper(prompt_path):
    safe_path = str(prompt_path or '').replace('\\', '/')
    return (
        "Read the UTF-8 text file at this absolute path and follow it as the full user request: "
        f"{safe_path}\n"
        "Treat the file contents as authoritative. Do not claim the question is garbled unless the file itself contains question marks.\n"
        "After reading the file, continue with the required WeChat MCP analysis."
    )


def _claude_has_wechat_mcp(list_text='', get_text=''):
    lt = str(list_text or '')
    gt = str(get_text or '')
    combo = "\n".join([lt, gt]).lower()
    if 'no mcp servers configured' in combo or 'no mcp server found with name: wechat' in combo:
        return False
    has_wechat = ('wechat:' in lt.lower()) or ('wechat:' in gt.lower()) or ('"wechat"' in combo)
    if not has_wechat:
        return False
    return ('connected' in combo) or ('scope:' in combo) or ('type:' in combo)


def _clean_claude_status_text(text):
    lines = []
    for raw in str(text or '').splitlines():
        line = str(raw or '').strip()
        if not line:
            if lines and lines[-1]:
                lines.append('')
            continue
        if 'UV_HANDLE_CLOSING' in line or line.startswith('Assertion failed: !(handle->flags'):
            continue
        lines.append(line)
    return "\n".join(lines).strip()


def _format_claude_runtime_error(message):
    text = _clean_claude_status_text(message)
    lower = text.lower()
    if 'no space left on device' in lower or 'enospc' in lower or 'disk is full' in lower:
        temp_dir = os.path.normpath(tempfile.gettempdir())
        return (
            "Claude Code 运行失败：磁盘或临时目录空间不足。"
            "本项目已改为优先使用 D 盘运行时目录，但你当前还残留了大量临时解密库。"
            f"请先清理 {temp_dir} 下的大型 tmp*.db。"
            f"\n原始错误: {text}"
        )
    if 'no mcp servers configured' in lower or 'no mcp server found with name: wechat' in lower:
        return "wechat MCP 未注册或未连接，已尝试自动修复。若仍失败，请重新发送一次问题。"
    return text


def _ensure_claude_mcp_ready(auto_reconnect=True):
    status = _probe_claude_status()
    if not status.get('claude_installed'):
        raise RuntimeError(str(status.get('detail', '') or 'Claude Code 未安装或不可用'))
    if status.get('wechat_mcp_connected'):
        return status
    if auto_reconnect:
        status = _try_reconnect_wechat_mcp()
        if status.get('wechat_mcp_connected'):
            return status
    detail = status.get('reconnect_cmd_output') or status.get('detail') or 'wechat MCP 未连接'
    raise RuntimeError(_format_claude_runtime_error(detail))


def _resolve_claude_executable():
    # Prefer the real Node CLI entrypoint on Windows. This avoids the .cmd/.ps1
    # wrapper layer, which has caused Chinese prompt corruption here.
    path_candidates = []
    node_exe = shutil.which('node')
    appdata = os.environ.get('APPDATA', '')
    user_home = os.path.expanduser('~')

    cli_candidates = []
    if appdata:
        cli_candidates.append(os.path.join(appdata, 'npm', 'node_modules', '@anthropic-ai', 'claude-code', 'cli.js'))
    cli_candidates.append(os.path.join(user_home, 'AppData', 'Roaming', 'npm', 'node_modules', '@anthropic-ai', 'claude-code', 'cli.js'))
    if node_exe:
        for cli_js in cli_candidates:
            if cli_js and os.path.exists(cli_js):
                return f'nodejs::{node_exe}::{cli_js}'

    if appdata:
        path_candidates.append(os.path.join(appdata, 'npm', 'claude.cmd'))
        path_candidates.append(os.path.join(appdata, 'npm', 'claude.exe'))
        path_candidates.append(os.path.join(appdata, 'npm', 'claude.ps1'))

    path_candidates.append(os.path.join(user_home, 'AppData', 'Roaming', 'npm', 'claude.cmd'))
    path_candidates.append(os.path.join(user_home, 'AppData', 'Roaming', 'npm', 'claude.exe'))
    path_candidates.append(os.path.join(user_home, 'AppData', 'Roaming', 'npm', 'claude.ps1'))

    for p in path_candidates:
        if p and os.path.exists(p):
            return p

    for name in ('claude.cmd', 'claude.exe', 'claude', 'claude.ps1'):
        p = shutil.which(name)
        if p:
            return p

    if appdata:
        npm_dir = os.path.join(appdata, 'npm')
        for name in ('claude.cmd', 'claude.exe', 'claude', 'claude.ps1'):
            p = os.path.join(npm_dir, name)
            if os.path.exists(p):
                return p

    npm_dir = os.path.join(user_home, 'AppData', 'Roaming', 'npm')
    for name in ('claude.cmd', 'claude.exe', 'claude', 'claude.ps1'):
        p = os.path.join(npm_dir, name)
        if os.path.exists(p):
            return p

    return 'claude'


def _prepare_subprocess_args(args):
    run_args = list(args)
    run_cwd = None
    if run_args and run_args[0] == 'claude':
        runtime_info = _ensure_claude_runtime_layout()
        exe = _resolve_claude_executable()
        run_cwd = RUNTIME_BASE_DIR
        if exe.startswith('nodejs::'):
            _tag, node_exe, cli_js = exe.split('::', 2)
            run_args = [node_exe, cli_js] + run_args[1:]
        else:
            run_args[0] = exe
        if not exe.startswith('nodejs::') and exe.lower().endswith('.ps1'):
            run_args = [
                'powershell',
                '-NoProfile',
                '-ExecutionPolicy', 'Bypass',
                '-File', exe
            ] + run_args[1:]

    env = os.environ.copy()
    appdata = env.get('APPDATA', '')
    if appdata:
        npm_bin = os.path.join(appdata, 'npm')
        old_path = env.get('PATH', '')
        if npm_bin and npm_bin not in old_path:
            env['PATH'] = npm_bin + os.pathsep + old_path
    if run_cwd:
        env['TMP'] = runtime_info['temp_dir']
        env['TEMP'] = runtime_info['temp_dir']
        env['TMPDIR'] = runtime_info['temp_dir']
        env['CLAUDE_CONFIG_DIR'] = runtime_info['config_dir']
    env['PYTHONUTF8'] = '1'
    env['PYTHONIOENCODING'] = 'utf-8'
    return run_args, env, run_cwd


def _subprocess_window_kwargs():
    if os.name != 'nt':
        return {}
    kwargs = {}
    try:
        kwargs['creationflags'] = getattr(subprocess, 'CREATE_NO_WINDOW', 0)
    except Exception:
        kwargs['creationflags'] = 0
    try:
        startup = subprocess.STARTUPINFO()
        startup.dwFlags |= getattr(subprocess, 'STARTF_USESHOWWINDOW', 0)
        startup.wShowWindow = 0
        kwargs['startupinfo'] = startup
    except Exception:
        pass
    return kwargs


def _run_cmd(args, timeout=30, input_text=None):
    run_args, env, run_cwd = _prepare_subprocess_args(args)

    p = subprocess.run(
        run_args,
        capture_output=True,
        input=None if input_text is None else str(input_text),
        text=True,
        encoding='utf-8',
        errors='ignore',
        timeout=timeout,
        env=env,
        cwd=run_cwd,
        **_subprocess_window_kwargs(),
    )
    out = (p.stdout or '').strip()
    err = (p.stderr or '').strip()
    return p.returncode, out, err


def _probe_claude_status():
    status = {
        'claude_installed': False,
        'claude_version': '',
        'wechat_mcp_connected': False,
        'wechat_mcp_configured': False,
        'detail': '',
    }
    try:
        rc, out, err = _run_cmd(['claude', '--version'], timeout=8)
        if rc == 0:
            status['claude_installed'] = True
            status['claude_version'] = out
        else:
            status['detail'] = err or out
            return status

        rc_list, out_list, err_list = _run_cmd(['claude', 'mcp', 'list'], timeout=12)
        rc_get, out_get, err_get = _run_cmd(['claude', 'mcp', 'get', 'wechat'], timeout=12)
        text = "\n".join([
            out_list or '',
            err_list or '',
            out_get or '',
            err_get or '',
        ]).strip()
        status['detail'] = _clean_claude_status_text(text)
        status['wechat_mcp_configured'] = _claude_has_wechat_mcp(out_list or err_list, out_get or err_get)
        if _claude_has_wechat_mcp(out_list or err_list, out_get or err_get):
            status['wechat_mcp_connected'] = True
    except Exception as e:
        status['detail'] = str(e)
    return status


def _probe_ai_status():
    st = _probe_claude_status()
    st['provider'] = 'claude_cli'
    st['provider_label'] = _ai_provider_label('claude_cli')
    st['model'] = 'claude_cli'
    st['base_url'] = ''
    return st


def _probe_ai_provider_status():
    cfg = _load_ai_provider_config()
    provider = _normalize_provider_name(cfg.get('provider', 'openai_compat'))
    out = {
        'provider': provider,
        'provider_label': _ai_provider_label(provider),
        'model': str(cfg.get('model', '') or '').strip(),
        'base_url': str(cfg.get('base_url', '') or '').strip(),
        'has_api_key': bool(str(cfg.get('api_key', '') or '').strip()),
        'ready': False,
        'provider_ready': False,
        'detail': '',
    }
    if provider == 'claude_cli':
        claude = _probe_claude_status()
        out.update({
            'claude_installed': bool(claude.get('claude_installed', False)),
            'claude_version': str(claude.get('claude_version', '') or ''),
            'wechat_mcp_connected': bool(claude.get('wechat_mcp_connected', False)),
            'detail': str(claude.get('detail', '') or ''),
        })
        out['ready'] = bool(out.get('claude_installed', False))
        out['provider_ready'] = out['ready']
        if not out['ready'] and not out['detail']:
            out['detail'] = 'Claude Code 未安装或不可用。'
        return out

    missing = []
    if not out['base_url']:
        missing.append('Base URL')
    if not out['model']:
        missing.append('模型')
    if not out['has_api_key']:
        missing.append('API Key')
    out['ready'] = len(missing) == 0
    out['provider_ready'] = out['ready']
    if missing:
        out['detail'] = '请先配置：' + ' / '.join(missing)
    return out


def _http_json_request(url, payload, headers=None, timeout_sec=180):
    body = json.dumps(payload, ensure_ascii=False).encode('utf-8')
    hdr = {'Content-Type': 'application/json'}
    if isinstance(headers, dict):
        for k, v in headers.items():
            if v is None:
                continue
            hdr[str(k)] = str(v)
    req = urllib.request.Request(url=url, data=body, headers=hdr, method='POST')
    try:
        with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
            raw = resp.read().decode('utf-8', errors='ignore')
            if not raw:
                return {}
            try:
                return json.loads(raw)
            except Exception:
                raise RuntimeError(f"invalid JSON response: {raw[:400]}")
    except urllib.error.HTTPError as e:
        raw = ''
        try:
            raw = e.read().decode('utf-8', errors='ignore')
        except Exception:
            raw = str(e)
        msg = raw.strip() or f"HTTP {e.code}"
        obj = None
        try:
            obj = json.loads(msg)
        except Exception:
            obj = None
        if isinstance(obj, dict):
            err = obj.get('error')
            if isinstance(err, dict):
                em = str(err.get('message', '') or '')
                ec = str(err.get('code', '') or '')
                if em:
                    if ec:
                        raise RuntimeError(f"{ec}: {em}")
                    raise RuntimeError(em)
            em = str(obj.get('message', '') or '')
            if em:
                raise RuntimeError(em)
        raise RuntimeError(msg[:1200])
    except Exception as e:
        raise RuntimeError(str(e))


def _openai_chat_url(base_url):
    base = str(base_url or '').strip().rstrip('/')
    if base.endswith('/chat/completions'):
        return base
    if base.endswith('/v1'):
        return base + '/chat/completions'
    return base + '/v1/chat/completions'


def _anthropic_messages_url(base_url):
    base = str(base_url or '').strip().rstrip('/')
    if base.endswith('/v1/messages'):
        return base
    if base.endswith('/v1'):
        return base + '/messages'
    return base + '/v1/messages'


def _extract_text_from_openai_content(content):
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for item in content:
            if isinstance(item, dict):
                t = str(item.get('text', '') or '')
                if t:
                    parts.append(t)
            elif isinstance(item, str):
                parts.append(item)
        return "\n".join([x for x in parts if x]).strip()
    if isinstance(content, dict):
        return str(content.get('text', '') or '')
    return str(content or '')


def _extract_text_from_anthropic_content(content):
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        out = []
        for item in content:
            if not isinstance(item, dict):
                continue
            if str(item.get('type', '') or '') == 'text':
                t = str(item.get('text', '') or '')
                if t:
                    out.append(t)
        return "\n".join(out).strip()
    if isinstance(content, dict):
        return str(content.get('text', '') or '')
    return str(content or '')


def _read_image_as_data_uri(path):
    with open(path, 'rb') as f:
        blob = f.read()
    if not blob:
        raise RuntimeError("image file is empty")
    mime = _detect_image_mime(blob) or 'image/png'
    b64 = base64.b64encode(blob).decode('ascii')
    return mime, b64, f"data:{mime};base64,{b64}"


def _build_recent_ai_history(session_obj, limit_items=16):
    msgs = session_obj.get('messages', []) if isinstance(session_obj, dict) else []
    if not isinstance(msgs, list):
        return []
    rows = []
    for m in msgs[-max(2, int(limit_items)):]:
        if not isinstance(m, dict):
            continue
        role = str(m.get('role', '') or '').strip().lower()
        role = 'assistant' if role == 'assistant' else 'user'
        content = str(m.get('content', '') or '').strip()
        if not content:
            continue
        rows.append({'role': role, 'content': content})
    return rows


def _ask_openai_compat(session_obj, question, context_obj, image_files, cfg):
    prompt_text = _build_ai_prompt(question, context_obj, image_files=None)
    history = _build_recent_ai_history(session_obj, limit_items=18)
    user_msg = {'role': 'user', 'content': prompt_text}
    if isinstance(image_files, list) and image_files:
        blocks = [{'type': 'text', 'text': prompt_text}]
        for img in image_files[:5]:
            if not isinstance(img, dict):
                continue
            p = str(img.get('path', '') or '').strip()
            if not p or not os.path.exists(p):
                continue
            mime, _b64, data_uri = _read_image_as_data_uri(p)
            blocks.append({
                'type': 'image_url',
                'image_url': {
                    'url': data_uri,
                    'detail': 'auto',
                }
            })
        user_msg = {'role': 'user', 'content': blocks}

    messages = history + [user_msg]
    payload = {
        'model': str(cfg.get('model', '') or ''),
        'messages': messages,
        'temperature': float(cfg.get('temperature', 0.2) or 0.2),
        'max_tokens': int(cfg.get('max_tokens', 4000) or 4000),
    }
    headers = {
        'Authorization': f"Bearer {str(cfg.get('api_key', '') or '').strip()}",
    }
    url = _openai_chat_url(cfg.get('base_url', ''))
    obj = _http_json_request(url, payload, headers=headers, timeout_sec=int(cfg.get('timeout_sec', 180) or 180))
    choices = obj.get('choices', [])
    if not isinstance(choices, list) or not choices:
        raise RuntimeError("OpenAI compatible response missing choices")
    msg = choices[0].get('message', {}) if isinstance(choices[0], dict) else {}
    answer = _extract_text_from_openai_content(msg.get('content', ''))
    if not answer:
        answer = str(choices[0].get('text', '') or '').strip()
    if not answer:
        raise RuntimeError("OpenAI compatible response is empty")
    return answer, {
        'model': payload['model'],
        'usage': obj.get('usage', {}),
        'provider': 'openai_compat',
    }


def _ask_anthropic_compat(session_obj, question, context_obj, image_files, cfg):
    prompt_text = _build_ai_prompt(question, context_obj, image_files=None)
    history = _build_recent_ai_history(session_obj, limit_items=18)
    messages = []
    for m in history:
        messages.append({
            'role': m.get('role', 'user'),
            'content': str(m.get('content', '') or ''),
        })

    current_content = [{'type': 'text', 'text': prompt_text}]
    if isinstance(image_files, list) and image_files:
        for img in image_files[:5]:
            if not isinstance(img, dict):
                continue
            p = str(img.get('path', '') or '').strip()
            if not p or not os.path.exists(p):
                continue
            mime, b64, _data_uri = _read_image_as_data_uri(p)
            current_content.append({
                'type': 'image',
                'source': {
                    'type': 'base64',
                    'media_type': mime,
                    'data': b64
                }
            })
    messages.append({
        'role': 'user',
        'content': current_content,
    })

    payload = {
        'model': str(cfg.get('model', '') or ''),
        'max_tokens': int(cfg.get('max_tokens', 4000) or 4000),
        'temperature': float(cfg.get('temperature', 0.2) or 0.2),
        'messages': messages,
    }
    headers = {
        'x-api-key': str(cfg.get('api_key', '') or '').strip(),
        'anthropic-version': str(cfg.get('anthropic_version', '2023-06-01') or '2023-06-01'),
    }
    url = _anthropic_messages_url(cfg.get('base_url', ''))
    obj = _http_json_request(url, payload, headers=headers, timeout_sec=int(cfg.get('timeout_sec', 180) or 180))
    answer = _extract_text_from_anthropic_content(obj.get('content', []))
    if not answer:
        raise RuntimeError("Anthropic compatible response is empty")
    return answer, {
        'model': payload['model'],
        'usage': obj.get('usage', {}),
        'provider': 'anthropic_compat',
    }


def _append_ai_session_reply(session_id, question, answer, context_obj, image_files=None, claude_sid=None):
    now = int(time.time())
    user_msg = {
        'role': 'user',
        'content': question,
        'ts': now,
        'context': context_obj,
        'images': image_files or [],
    }
    ai_msg = {
        'role': 'assistant',
        'content': answer,
        'ts': int(time.time()),
    }
    with ai_sessions_lock:
        s = ai_sessions.get(session_id)
        if not s:
            raise RuntimeError("session not found")
        if claude_sid:
            s['claude_session_id'] = claude_sid
        s['messages'].append(user_msg)
        s['messages'].append(ai_msg)
        s['updated_at'] = int(time.time())
        if not s.get('title'):
            s['title'] = question[:60]
    _save_ai_sessions()
    return ai_msg, _get_ai_session(session_id)


def _ask_ai_http(session_obj, question, context_obj, image_files, cfg):
    provider = str(cfg.get('provider', '') or '').strip().lower()
    if provider == 'openai_compat':
        answer, meta = _ask_openai_compat(session_obj, question, context_obj, image_files, cfg)
    elif provider == 'anthropic_compat':
        answer, meta = _ask_anthropic_compat(session_obj, question, context_obj, image_files, cfg)
    else:
        raise RuntimeError(f"unsupported provider: {provider}")
    ai_msg, snapshot = _append_ai_session_reply(
        session_id=session_obj.get('id'),
        question=question,
        answer=answer,
        context_obj=context_obj,
        image_files=image_files or [],
        claude_sid=None
    )
    return ai_msg, snapshot, meta

def _try_reconnect_wechat_mcp():
    before = _probe_claude_status()
    if before.get('wechat_mcp_connected'):
        return before

    server_path = os.path.join(RUNTIME_BASE_DIR, 'mcp_server.py')
    if not os.path.exists(server_path):
        server_path = os.path.join(RESOURCE_BASE_DIR, 'mcp_server.py')
    if not os.path.exists(server_path):
        after = dict(before)
        after['reconnect_cmd_rc'] = -1
        after['reconnect_cmd_output'] = 'mcp_server.py not found'
        return after

    _run_cmd(['claude', 'mcp', 'remove', '--scope', 'project', 'wechat'], timeout=12)
    rc, out, err = _run_cmd(
        ['claude', 'mcp', 'add', '--scope', 'project', 'wechat', 'python', server_path],
        timeout=20
    )
    after = _probe_claude_status()
    after['reconnect_cmd_rc'] = rc
    after['reconnect_cmd_output'] = (out + '\n' + err).strip()
    return after


def _ensure_ai_sessions_loaded():
    global ai_sessions
    with ai_sessions_lock:
        if ai_sessions:
            return
        try:
            if os.path.exists(AI_SESSIONS_FILE):
                with open(AI_SESSIONS_FILE, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                if isinstance(data, dict):
                    ai_sessions = data
        except Exception as e:
            print(f"[ai] load sessions failed: {e}", flush=True)
            ai_sessions = {}


def _save_ai_sessions():
    with ai_sessions_lock:
        os.makedirs(os.path.dirname(AI_SESSIONS_FILE), exist_ok=True)
        with open(AI_SESSIONS_FILE, 'w', encoding='utf-8') as f:
            json.dump(ai_sessions, f, ensure_ascii=False, indent=2)


def _ai_image_ext_by_mime(mime):
    m = (mime or '').lower().strip()
    if m in ('image/jpeg', 'image/jpg'):
        return '.jpg'
    if m == 'image/png':
        return '.png'
    if m == 'image/webp':
        return '.webp'
    if m == 'image/gif':
        return '.gif'
    if m == 'image/bmp':
        return '.bmp'
    return '.png'


def _save_inline_images(raw_items):
    items = raw_items if isinstance(raw_items, list) else []
    if not items:
        return []
    if len(items) > 5:
        raise RuntimeError("too many images (max 5)")

    os.makedirs(AI_UPLOAD_DIR, exist_ok=True)
    saved = []
    total_size = 0
    for it in items:
        if not isinstance(it, dict):
            continue
        b64_data = str(it.get('data', '') or '').strip()
        if not b64_data:
            continue
        mime = str(it.get('mime', '') or '').strip()
        name = str(it.get('name', '') or '').strip()
        if len(b64_data) > 12_000_000:
            raise RuntimeError("image payload too large")
        try:
            blob = base64.b64decode(b64_data, validate=True)
        except (ValueError, binascii.Error):
            raise RuntimeError("invalid image base64")
        if not blob:
            continue
        if len(blob) > 8 * 1024 * 1024:
            raise RuntimeError("single image too large (max 8MB)")
        total_size += len(blob)
        if total_size > 20 * 1024 * 1024:
            raise RuntimeError("total image size too large (max 20MB)")

        ext = _ai_image_ext_by_mime(mime)
        file_id = str(uuid.uuid4())
        filename = f"{file_id}{ext}"
        abs_path = os.path.join(AI_UPLOAD_DIR, filename)
        with open(abs_path, 'wb') as f:
            f.write(blob)
        saved.append({
            'id': file_id,
            'name': name or filename,
            'mime': mime or 'application/octet-stream',
            'size': len(blob),
            'file': filename,
            'path': abs_path,
            'url': f"/api/ai_image?f={urllib.parse.quote(filename)}",
        })
    return saved


def _session_summary_title(session_obj):
    title = (session_obj.get('title') or '').strip()
    if title:
        return title[:80]
    for m in session_obj.get('messages', []):
        if m.get('role') == 'user':
            text = str(m.get('content', '')).strip()
            if text:
                return text[:60]
    return "new_session"


def _create_ai_session(title=''):
    _ensure_ai_sessions_loaded()
    now = int(time.time())
    sid = str(uuid.uuid4())
    claude_sid = str(uuid.uuid4())
    session_obj = {
        'id': sid,
        'claude_session_id': claude_sid,
        'title': (title or '').strip(),
        'created_at': now,
        'updated_at': now,
        'messages': []
    }
    with ai_sessions_lock:
        ai_sessions[sid] = session_obj
    _save_ai_sessions()
    return session_obj


def _list_ai_sessions(limit=100):
    _ensure_ai_sessions_loaded()
    with ai_sessions_lock:
        items = list(ai_sessions.values())
    items.sort(key=lambda x: int(x.get('updated_at', 0)), reverse=True)
    out = []
    for s in items[:limit]:
        out.append({
            'id': s.get('id'),
            'title': _session_summary_title(s),
            'created_at': s.get('created_at', 0),
            'updated_at': s.get('updated_at', 0),
            'message_count': len(s.get('messages', []))
        })
    return out


def _get_ai_session(session_id):
    _ensure_ai_sessions_loaded()
    with ai_sessions_lock:
        s = ai_sessions.get(session_id)
        if not s:
            return None
        return {
            'id': s.get('id'),
            'title': _session_summary_title(s),
            'created_at': s.get('created_at', 0),
            'updated_at': s.get('updated_at', 0),
            'messages': list(s.get('messages', []))
        }


def _rename_ai_session(session_id, title):
    t = str(title or '').strip()
    if not t:
        raise RuntimeError("title cannot be empty")
    _ensure_ai_sessions_loaded()
    with ai_sessions_lock:
        s = ai_sessions.get(session_id)
        if not s:
            return None
        s['title'] = t[:120]
        s['updated_at'] = int(time.time())
    _save_ai_sessions()
    return _get_ai_session(session_id)


def _delete_ai_session(session_id):
    _ensure_ai_sessions_loaded()
    removed = None
    with ai_sessions_lock:
        removed = ai_sessions.pop(session_id, None)
    if removed is not None:
        _save_ai_sessions()
        return True
    return False


def _reset_ai_session_claude_sid(session_id):
    _ensure_ai_sessions_loaded()
    sid = str(session_id or '').strip()
    if not sid:
        return None
    new_sid = str(uuid.uuid4())
    ok = False
    with ai_sessions_lock:
        s = ai_sessions.get(sid)
        if not s:
            return None
        s['claude_session_id'] = new_sid
        s['updated_at'] = int(time.time())
        ok = True
    if ok:
        _save_ai_sessions()
        return new_sid
    return None


def _is_claude_session_in_use_error(err_text):
    t = str(err_text or '').lower()
    return ('already in use' in t) and ('session id' in t or 'session' in t)


def _build_ai_prompt(user_question, context_obj, image_files=None):
    scope = str(context_obj.get('scope', '') or '')
    chat = str(context_obj.get('chat', '') or '')
    username = str(context_obj.get('username', '') or '')
    start_ts = _safe_int(context_obj.get('start_ts', 0), 0, 0, None)
    end_ts = _safe_int(context_obj.get('end_ts', 0), 0, 0, None)
    limit = _safe_int(context_obj.get('limit', 0), 0, 0, 50000)
    include_history = bool(context_obj.get('include_history', True))
    include_realtime = bool(context_obj.get('include_realtime', True))
    range_days = _safe_int(context_obj.get('range_preset_days', 0), 0, 0, 10000)
    pinned_count = _safe_int(context_obj.get('pinned_count', 0), 0, 0, 1000)
    pinned_usernames_raw = context_obj.get('pinned_usernames', [])
    pinned_names_raw = context_obj.get('pinned_chat_names', [])
    pinned_chats_raw = context_obj.get('pinned_chats', [])
    self_usernames = sorted([x for x in _guess_self_usernames() if str(x or '').strip()])
    self_hint = ", ".join(self_usernames[:8]) if self_usernames else "-"
    q_lower = str(user_question or '')
    asks_about_self = any(token in q_lower for token in ('我', '我的', '自己', '本人'))
    asks_about_pinned = any(token in q_lower.lower() for token in ('置顶', 'pinned', 'pin'))

    pinned_usernames = []
    if isinstance(pinned_usernames_raw, list):
        for item in pinned_usernames_raw:
            val = str(item or '').strip()
            if val and val not in pinned_usernames:
                pinned_usernames.append(val)

    pinned_names = []
    if isinstance(pinned_names_raw, list):
        for item in pinned_names_raw:
            val = str(item or '').strip()
            if val and val not in pinned_names:
                pinned_names.append(val)
    if not pinned_names and isinstance(pinned_chats_raw, list):
        for row in pinned_chats_raw:
            if not isinstance(row, dict):
                continue
            val = str(row.get('chat', '') or row.get('username', '') or '').strip()
            if val and val not in pinned_names:
                pinned_names.append(val)

    pinned_hint = ", ".join(pinned_names[:12]) if pinned_names else "-"
    pinned_username_hint = ", ".join(pinned_usernames[:12]) if pinned_usernames else "-"

    scope_lines = [
        f"- scope: {scope or 'all_sessions'}",
        f"- chat: {chat or '-'}",
        f"- username: {username or '-'}",
        f"- self_usernames: {self_hint}",
        f"- start_ts: {start_ts or '-'}",
        f"- end_ts: {end_ts or '-'}",
        f"- page_limit_setting: {limit or '-'}",
        f"- include_history: {str(include_history).lower()}",
        f"- include_realtime: {str(include_realtime).lower()}",
        f"- range_preset_days: {range_days or '-'}",
        f"- pinned_count: {pinned_count or 0}",
        f"- pinned_chat_names: {pinned_hint}",
        f"- pinned_usernames: {pinned_username_hint}",
    ]
    scope_text = "\n".join(scope_lines)
    image_text = ""
    images = image_files if isinstance(image_files, list) else []
    if images:
        parts = []
        for i, img in enumerate(images, 1):
            if not isinstance(img, dict):
                continue
            p = str(img.get('path', '') or '')
            n = str(img.get('name', '') or '')
            if not p:
                continue
            parts.append(f"- image_{i}: path={p} name={n or '-'}")
        if parts:
            image_text = (
                "Attached images (local files):\n"
                + "\n".join(parts)
                + "\nIf the model supports image reading, inspect these files before answering.\n\n"
            )

    now = datetime.now()
    weekday_str = ["星期一", "星期二", "星期三", "星期四", "星期五", "星期六", "星期日"][now.weekday()]
    time_str = f"当前系统时间: {now.strftime('%Y-%m-%d %H:%M')} ({weekday_str})"
    
    if asks_about_pinned and pinned_names:
        prompt_lines = [
            time_str,
            f"提示：左侧已置顶 {len(pinned_names)} 个重点会话：{pinned_hint}。",
            "如果用户提到“我置顶的这些群/这些会话/这些群里”，默认就是指上面的置顶会话，不要缩成当前打开的单个聊天，也不要扩成全部会话。",
            f"任务：围绕这些置顶会话直接回答这个问题：{user_question}",
            "不要自我介绍，不要输出欢迎词、能力菜单，不要说问题乱码，不要让用户重新描述问题。",
            f"时间范围：{start_ts or 0} 到 {end_ts or 0}。",
            "如果需要取证，优先逐个检查这些置顶会话，总结共同热点和各群差异；若证据不足，再明确说明不足。",
            f"如果问题里的“我”指向当前账号，则把它理解为：{self_hint}。",
            "输出：只用中文，按“结论 -> 证据摘要 -> 关键发现”回答，并且只基于 MCP 证据。",
        ]
    elif scope == 'current_chat' and asks_about_self:
        prompt_lines = [
            time_str,
            f"提示：用户目前停留在聊天【{chat or '-'}】({username or '-'})的界面。你可以优先参考这个聊天，但如果用户的提问隐含了全局搜索的意图，请自由跨群或检索私聊数据。",
            f"任务：分析聊天中“我”的发言情况；这里的“我”指 {self_hint}。",
            "不要自我介绍，不要输出欢迎词、能力菜单，不要说问题乱码，不要让用户重新描述问题。",
            f"时间范围：{start_ts or 0} 到 {end_ts or 0}。",
            "如果当前时间范围证据不足，可以扩到 start_ts=0,end_ts=0。",
            "输出：只用中文，按“结论 -> 证据摘要 -> 关键发现”回答，并且只基于 MCP 证据。",
            f"用户原问题：{user_question}",
        ]
    elif scope == 'current_chat':
        prompt_lines = [
            time_str,
            f"提示：用户目前停留在聊天【{chat or '-'}】({username or '-'})的界面。你可以优先参考这个聊天，但如果用户的提问隐含了全局搜索的意图，请自由跨群或检索私聊数据。",
            f"任务：直接回答这个问题：{user_question}",
            "不要自我介绍，不要输出欢迎词、能力菜单，不要说问题乱码，不要让用户重新描述问题。",
            f"时间范围：{start_ts or 0} 到 {end_ts or 0}。",
            "如果当前时间范围证据不足，可以扩到 start_ts=0,end_ts=0。",
            "输出：只用中文，按“结论 -> 证据摘要 -> 关键发现”回答，并且只基于 MCP 证据。",
        ]
    else:
        prompt_lines = [
            time_str,
            f"任务：基于微信聊天数据直接回答这个问题：{user_question}",
            "不要自我介绍，不要输出欢迎词、能力菜单，不要说问题乱码，不要让用户重新描述问题。",
            f"如果问题里的“我”指向当前账号，则把它理解为：{self_hint}。",
            "输出：只用中文，按“结论 -> 证据摘要 -> 关键发现”回答，并且只基于 MCP 证据。",
        ]

    if image_text:
        prompt_lines.append(image_text.strip())
    prompt_lines.append("页面上下文：")
    prompt_lines.append(scope_text)
    return "\n".join(prompt_lines) + "\n"

def _ask_claude(session_obj, question, context_obj, image_files=None):
    _ensure_claude_mcp_ready(auto_reconnect=True)
    claude_sid = session_obj.get('claude_session_id') or str(uuid.uuid4())
    messages = session_obj.get('messages', [])
    first_turn = len(messages) == 0

    prompt = _build_ai_prompt(question, context_obj, image_files=image_files)
    prompt_file = _write_claude_prompt_bridge(prompt, suffix=f"ask_{claude_sid}")
    cmd = _build_claude_cmd(
        claude_sid,
        first_turn,
        prompt=_build_claude_prompt_wrapper(prompt_file),
        stream_json=False
    )

    rc, out, err = _run_cmd(cmd, timeout=180, input_text=None)
    if rc != 0:
        msg = _format_claude_runtime_error(err or out or f"claude exit code={rc}")
        if _is_claude_session_in_use_error(msg):
            _reset_ai_session_claude_sid(session_obj.get('id'))
            raise RuntimeError("Claude 会话被占用，已自动重置会话，请重新发送一次问题。")
        raise RuntimeError(msg)
    answer = out.strip()
    if not answer:
        answer = "(Claude 未返回内容)"
    ai_msg, _snapshot = _append_ai_session_reply(
        session_id=session_obj.get('id'),
        question=question,
        answer=answer,
        context_obj=context_obj,
        image_files=image_files or [],
        claude_sid=claude_sid
    )
    return ai_msg


def _short_json(value, max_len=600):
    try:
        text = json.dumps(value, ensure_ascii=False)
    except Exception:
        text = str(value)
    if len(text) > max_len:
        return text[:max_len] + "..."
    return text


def _build_claude_cmd(claude_sid, first_turn, prompt=None, stream_json=False):
    cmd = ['claude', '-p', '--dangerously-skip-permissions']
    mcp_cfg_path = _claude_project_mcp_path()
    if mcp_cfg_path and os.path.exists(mcp_cfg_path):
        # Use the explicit one-token form so the positional prompt cannot be
        # misparsed as a second mcp config path on Windows.
        cmd.append(f'--mcp-config={mcp_cfg_path}')
    if stream_json:
        cmd += ['--output-format', 'stream-json', '--include-partial-messages', '--verbose']
    else:
        cmd += ['--output-format', 'text']
    if first_turn:
        cmd += ['--session-id', claude_sid]
    else:
        cmd += ['--resume', claude_sid]
    if prompt is not None:
        cmd.append(str(prompt))
    return cmd


def _set_ai_task(task_id, **updates):
    with ai_tasks_lock:
        task = ai_tasks.get(task_id)
        if not task:
            return None
        task.update(updates)
        task['updated_at'] = int(time.time())
        return dict(task)


def _append_ai_task_event(task_id, kind, title, detail=''):
    now_ms = int(time.time() * 1000)
    evt = {
        'ts': int(now_ms // 1000),
        'ts_ms': now_ms,
        'kind': str(kind or 'info'),
        'title': str(title or ''),
        'detail': str(detail or ''),
    }
    with ai_tasks_lock:
        task = ai_tasks.get(task_id)
        if not task:
            return
        events = task.setdefault('events', [])
        if events:
            prev = events[-1]
            prev_ms = int(prev.get('ts_ms') or (int(prev.get('ts', 0)) * 1000))
            if prev_ms > 0:
                evt['since_prev_ms'] = max(0, now_ms - prev_ms)
        run_started_ms = int(task.get('run_started_ms', 0) or 0)
        if run_started_ms > 0:
            evt['since_run_ms'] = max(0, now_ms - run_started_ms)
        events.append(evt)
        if len(events) > 200:
            del events[:len(events) - 200]
        task['updated_at'] = int(time.time())


def _get_ai_task_snapshot(task_id):
    with ai_tasks_lock:
        task = ai_tasks.get(task_id)
        if not task:
            return None
        return dict(task)


def _create_ai_task_record(
    *,
    task_id,
    session_id='',
    task_type='chat',
    question='',
    module_name='',
    module_title='',
    username='',
):
    now = int(time.time())
    return {
        'id': task_id,
        'session_id': session_id,
        'task_type': str(task_type or 'chat'),
        'question': str(question or ''),
        'module_name': str(module_name or ''),
        'module_title': str(module_title or ''),
        'username': str(username or ''),
        'status': 'queued',
        'status_text': '排队中...',
        'progress_pct': 0,
        'created_at': now,
        'updated_at': now,
        'partial_reply': '',
        'final_reply': '',
        'error': '',
        'events': [],
        'session': None,
        'result': None,
        'run_started_ms': 0,
        'cancel_requested': False,
    }


def _prune_ai_tasks(max_keep=120):
    with ai_tasks_lock:
        if len(ai_tasks) <= max_keep:
            return
        items = sorted(
            ai_tasks.items(),
            key=lambda x: int(x[1].get('updated_at', 0)),
            reverse=True
        )
        keep = dict(items[:max_keep])
        ai_tasks.clear()
        ai_tasks.update(keep)


def _register_ai_task_proc(task_id, proc_obj):
    with ai_task_proc_lock:
        ai_task_procs[task_id] = proc_obj


def _pop_ai_task_proc(task_id):
    with ai_task_proc_lock:
        return ai_task_procs.pop(task_id, None)


def _get_ai_task_proc(task_id):
    with ai_task_proc_lock:
        return ai_task_procs.get(task_id)


def _is_ai_task_cancel_requested(task_id):
    with ai_tasks_lock:
        t = ai_tasks.get(task_id)
        if not t:
            return False
        return bool(t.get('cancel_requested'))


def _cancel_ai_task(task_id):
    session_id = ''
    with ai_tasks_lock:
        t = ai_tasks.get(task_id)
        if not t:
            return False, "task not found"
        status = str(t.get('status', '') or '')
        if status in ('done', 'error', 'cancelled'):
            return False, f"task already {status}"
        if t.get('cancel_requested'):
            return True, "already requested"
        t['cancel_requested'] = True
        t['status'] = 'cancelled'
        t['status_text'] = '已终止'
        t['updated_at'] = int(time.time())
        session_id = str(t.get('session_id', '') or '')

    _append_ai_task_event(task_id, 'done', '任务已终止（用户取消）', '')
    proc = _get_ai_task_proc(task_id)
    if proc:
        pid = proc.pid
        try:
            if proc.poll() is None and os.name == 'nt':
                subprocess.run(
                    ['taskkill', '/PID', str(pid), '/T', '/F'],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=3,
                    **_subprocess_window_kwargs(),
                )
            elif proc.poll() is None:
                proc.terminate()
        except Exception:
            pass
        try:
            proc.wait(timeout=1.2)
        except Exception:
            try:
                if proc.poll() is None:
                    proc.kill()
            except Exception:
                pass
    if session_id:
        _reset_ai_session_claude_sid(session_id)
    return True, "ok"


def _sync_ai_task_stream_event(task_id, obj, stream_state):
    otype = str(obj.get('type', '') or '')
    if otype == 'stream_event':
        ev = obj.get('event', {}) if isinstance(obj.get('event', {}), dict) else {}
        ev_type = str(ev.get('type', '') or '')
        if ev_type == 'content_block_start':
            block = ev.get('content_block', {}) if isinstance(ev.get('content_block', {}), dict) else {}
            if block.get('type') == 'tool_use':
                tool_name = str(block.get('name', 'tool') or 'tool')
                detail = _short_json(block.get('input', {}), max_len=500)
                _append_ai_task_event(task_id, 'tool', f'调用工具: {tool_name}', detail)
                _set_ai_task(task_id, status_text=f'调用工具: {tool_name}')
        elif ev_type == 'content_block_delta':
            delta = ev.get('delta', {}) if isinstance(ev.get('delta', {}), dict) else {}
            d_type = str(delta.get('type', '') or '')
            if d_type == 'thinking_delta':
                stream_state['thinking_chars'] += len(str(delta.get('thinking', '') or ''))
                _set_ai_task(task_id, status_text='思考中...')
            elif d_type == 'text_delta':
                piece = str(delta.get('text', '') or '')
                if piece:
                    stream_state['answer'] += piece
                    _set_ai_task(
                        task_id,
                        status_text='生成回答中...',
                        partial_reply=stream_state['answer']
                    )
        return

    if otype == 'assistant':
        msg = obj.get('message', {}) if isinstance(obj.get('message', {}), dict) else {}
        blocks = msg.get('content', [])
        if not isinstance(blocks, list):
            blocks = []
        for block in blocks:
            if not isinstance(block, dict):
                continue
            b_type = str(block.get('type', '') or '')
            if b_type == 'tool_use':
                tool_name = str(block.get('name', 'tool') or 'tool')
                detail = _short_json(block.get('input', {}), max_len=500)
                _append_ai_task_event(task_id, 'tool', f'调用工具: {tool_name}', detail)
                _set_ai_task(task_id, status_text=f'调用工具: {tool_name}')
            elif b_type == 'text':
                text = str(block.get('text', '') or '')
                if text and len(text) > len(stream_state['answer']):
                    stream_state['answer'] = text
                    _set_ai_task(
                        task_id,
                        status_text='生成回答中...',
                        partial_reply=stream_state['answer']
                    )
        return

    if otype == 'user':
        msg = obj.get('message', {}) if isinstance(obj.get('message', {}), dict) else {}
        blocks = msg.get('content', [])
        if not isinstance(blocks, list):
            blocks = []
        for block in blocks:
            if isinstance(block, dict) and str(block.get('type', '') or '') == 'tool_result':
                detail = _short_json(block.get('content', ''), max_len=700)
                _append_ai_task_event(task_id, 'tool_result', '工具返回', detail)
                _set_ai_task(task_id, status_text='处理工具结果...')
        return

    if otype == 'result':
        subtype = str(obj.get('subtype', '') or '')
        if subtype:
            _append_ai_task_event(task_id, 'result', f'执行完成: {subtype}', '')
        result_text = obj.get('result')
        if isinstance(result_text, str) and result_text.strip():
            stream_state['result_text'] = result_text.strip()
        return


def _run_ai_task_worker_claude(task_id, session_id, question, context_obj, image_files):
    proc = None
    try:
        _ensure_ai_sessions_loaded()
        with ai_sessions_lock:
            session_obj = ai_sessions.get(session_id)
            if not session_obj:
                raise RuntimeError("session not found")
            claude_sid = session_obj.get('claude_session_id') or str(uuid.uuid4())
            first_turn = len(session_obj.get('messages', [])) == 0

        prompt = _build_ai_prompt(question, context_obj, image_files=image_files)
        prompt_file = _write_claude_prompt_bridge(prompt, suffix=f"task_{task_id}")
        wrapper_prompt = _build_claude_prompt_wrapper(prompt_file)
        _append_ai_debug_log('claude_task_request', {
            'task_id': task_id,
            'session_id': session_id,
            'question': question,
            'question_repr': repr(question),
            'context': context_obj if isinstance(context_obj, dict) else {},
            'wrapper_prompt': wrapper_prompt,
        })
        cmd = _build_claude_cmd(
            claude_sid,
            first_turn,
            prompt=wrapper_prompt,
            stream_json=True
        )
        run_args, env, run_cwd = _prepare_subprocess_args(cmd)

        _set_ai_task(
            task_id,
            status='running',
            status_text='已启动 Claude，准备分析...',
            run_started_ms=int(time.time() * 1000)
        )
        _append_ai_task_event(task_id, 'status', '已启动 Claude', '')
        pre_status = _probe_claude_status()
        if not pre_status.get('wechat_mcp_connected'):
            _append_ai_task_event(task_id, 'status', 'wechat MCP 未连接，正在自动修复', '')
            ready_status = _ensure_claude_mcp_ready(auto_reconnect=True)
            _append_ai_task_event(task_id, 'status', 'wechat MCP 已就绪', str(ready_status.get('detail', '') or '')[:300])
        else:
            _append_ai_task_event(task_id, 'status', 'wechat MCP 已连接', '')

        if _is_ai_task_cancel_requested(task_id):
            _append_ai_task_event(task_id, 'done', '任务已终止', '')
            _set_ai_task(
                task_id,
                status='cancelled',
                status_text='已终止',
                error=''
            )
            return

        proc = subprocess.Popen(
            run_args,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding='utf-8',
            errors='ignore',
            env=env,
            cwd=run_cwd,
            **_subprocess_window_kwargs(),
        )
        _register_ai_task_proc(task_id, proc)
        stream_state = {
            'answer': '',
            'result_text': '',
            'thinking_chars': 0,
        }
        stdout_lines = []
        stderr_text = ""

        if proc.stdout is not None:
            for raw in proc.stdout:
                if _is_ai_task_cancel_requested(task_id):
                    try:
                        if proc.poll() is None:
                            proc.terminate()
                    except Exception:
                        pass
                    break
                line = (raw or '').strip()
                if not line:
                    continue
                stdout_lines.append(line)
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                _sync_ai_task_stream_event(task_id, obj, stream_state)

        if _is_ai_task_cancel_requested(task_id):
            try:
                if proc.poll() is None:
                    proc.terminate()
            except Exception:
                pass

        if proc.stderr is not None:
            stderr_text = (proc.stderr.read() or '').strip()
        try:
            rc = proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            if _is_ai_task_cancel_requested(task_id):
                rc = -15
            else:
                raise RuntimeError("claude process wait timeout")

        if _is_ai_task_cancel_requested(task_id):
            _append_ai_task_event(task_id, 'done', '任务已终止', '')
            _set_ai_task(
                task_id,
                status='cancelled',
                status_text='已终止',
                error='',
                partial_reply=(stream_state.get('answer') or '').strip()
            )
            return

        if rc != 0:
            msg = stderr_text
            if not msg:
                msg = stdout_lines[-1] if stdout_lines else f"claude exit code={rc}"
            raise RuntimeError(_format_claude_runtime_error(msg))

        answer = (stream_state.get('answer') or '').strip()
        if not answer:
            answer = (stream_state.get('result_text') or '').strip()
        if not answer:
            answer = "(Claude 返回为空)"

        _ai_msg, session_snapshot = _append_ai_session_reply(
            session_id=session_id,
            question=question,
            answer=answer,
            context_obj=context_obj,
            image_files=image_files or [],
            claude_sid=claude_sid
        )

        _append_ai_task_event(task_id, 'done', '回答已完成', '')
        _set_ai_task(
            task_id,
            status='done',
            status_text='已完成',
            partial_reply=answer,
            final_reply=answer,
            session=session_snapshot
        )
    except Exception as e:
        if _is_ai_task_cancel_requested(task_id):
            _set_ai_task(
                task_id,
                status='cancelled',
                status_text='已终止',
                error=''
            )
        else:
            err_text = _format_claude_runtime_error(e)
            if _is_claude_session_in_use_error(err_text):
                _reset_ai_session_claude_sid(session_id)
                _append_ai_task_event(task_id, 'status', '检测到会话占用，已重置会话ID', '')
                _set_ai_task(
                    task_id,
                    status='error',
                    status_text='会话占用，已重置',
                    error='Claude 会话被占用，已自动重置会话，请重新发送一次问题。'
                )
            else:
                _append_ai_task_event(task_id, 'error', '执行失败', err_text)
                _set_ai_task(
                    task_id,
                    status='error',
                    status_text='执行失败',
                    error=err_text
                )
    finally:
        _pop_ai_task_proc(task_id)


def _run_ai_task_worker_http(task_id, session_id, question, context_obj, image_files, provider_cfg):
    try:
        _ensure_ai_sessions_loaded()
        with ai_sessions_lock:
            session_obj = ai_sessions.get(session_id)
        if not session_obj:
            raise RuntimeError("session not found")

        provider = str(provider_cfg.get('provider', '') or '')
        provider_label = _ai_provider_label(provider)
        _set_ai_task(
            task_id,
            status='running',
            status_text=f'已启动 {provider_label}，准备分析...',
            run_started_ms=int(time.time() * 1000)
        )
        _append_ai_task_event(task_id, 'status', f'已启动 {provider_label}', '')
        _append_ai_task_event(task_id, 'status', '整理上下文', '')

        if _is_ai_task_cancel_requested(task_id):
            _append_ai_task_event(task_id, 'done', '任务已终止', '')
            _set_ai_task(
                task_id,
                status='cancelled',
                status_text='已终止',
                error=''
            )
            return

        _set_ai_task(task_id, status_text='请求模型中...')
        _append_ai_task_event(
            task_id,
            'status',
            f'请求模型: {provider_cfg.get("model", "")}',
            f'base_url={provider_cfg.get("base_url", "")}'
        )

        ai_msg, session_snapshot, meta = _ask_ai_http(
            session_obj=session_obj,
            question=question,
            context_obj=context_obj,
            image_files=image_files or [],
            cfg=provider_cfg,
        )
        answer = str(ai_msg.get('content', '') or '').strip()
        if not answer:
            answer = "(AI 返回为空)"

        if _is_ai_task_cancel_requested(task_id):
            _append_ai_task_event(task_id, 'done', '任务已终止', '')
            _set_ai_task(
                task_id,
                status='cancelled',
                status_text='已终止',
                error='',
                partial_reply=answer
            )
            return

        meta_text = _short_json(meta, max_len=500)
        _append_ai_task_event(task_id, 'result', '模型返回', meta_text)
        _append_ai_task_event(task_id, 'done', '回答已完成', '')
        _set_ai_task(
            task_id,
            status='done',
            status_text='已完成',
            partial_reply=answer,
            final_reply=answer,
            session=session_snapshot
        )
    except Exception as e:
        if _is_ai_task_cancel_requested(task_id):
            _set_ai_task(
                task_id,
                status='cancelled',
                status_text='已终止',
                error=''
            )
        else:
            err_text = str(e)
            _append_ai_task_event(task_id, 'error', '执行失败', err_text)
            _set_ai_task(
                task_id,
                status='error',
                status_text='执行失败',
                error=err_text
            )
    finally:
        _pop_ai_task_proc(task_id)


def _run_ai_task_worker(task_id, session_id, question, context_obj, image_files):
    try:
        provider_cfg = _resolve_ai_provider_config_for_surface('sidebar')
    except Exception as e:
        err_text = str(e)
        _append_ai_task_event(task_id, 'error', '执行失败', err_text)
        _set_ai_task(
            task_id,
            status='error',
            status_text='执行失败',
            error=err_text
        )
        return

    provider = _normalize_provider_name(provider_cfg.get('provider', 'openai_compat'))
    if provider == 'claude_cli':
        _run_ai_task_worker_claude(task_id, session_id, question, context_obj, image_files)
        return
    _run_ai_task_worker_http(task_id, session_id, question, context_obj, image_files, provider_cfg)


def _test_ai_provider_connection(cfg_override=None):
    cfg_effective = _resolve_ai_provider_config(cfg_override)
    provider = _normalize_provider_name(cfg_effective.get('provider', 'openai_compat'))
    if provider == 'claude_cli':
        st = _ensure_claude_mcp_ready(auto_reconnect=True)
        return {
            'ok': True,
            'provider': provider,
            'provider_label': _ai_provider_label(provider),
            'ready': True,
            'preview': st.get('claude_version', '') or '',
            'detail': st.get('detail', ''),
        }

    if not str(cfg_effective.get('base_url', '') or '').strip():
        raise RuntimeError('请先配置 Base URL')
    if not str(cfg_effective.get('api_key', '') or '').strip():
        raise RuntimeError('请先配置 API Key')
    if not str(cfg_effective.get('model', '') or '').strip():
        raise RuntimeError('请先配置模型')

    text, usage = _llm_complete_by_provider(
        cfg_effective,
        "你是连通性测试助手。",
        "请仅回答 OK。",
    )
    preview = str(text or '').strip().replace('\n', ' ')
    if len(preview) > 100:
        preview = preview[:100] + '...'
    return {
        'ok': True,
        'provider': provider,
        'provider_label': _ai_provider_label(provider),
        'ready': True,
        'model': str(cfg_effective.get('model', '') or '').strip(),
        'preview': preview,
        'usage': usage if isinstance(usage, dict) else {},
    }


def _ai_module_cache_get(key):
    now = time.time()
    with ai_module_cache_lock:
        item = ai_module_cache.get(key)
        if not item:
            return None
        ts = float(item.get('ts', 0.0) or 0.0)
        if now - ts > AI_MODULE_CACHE_TTL_SEC:
            ai_module_cache.pop(key, None)
            return None
        return item.get('data')


def _ai_module_cache_set(key, data):
    with ai_module_cache_lock:
        ai_module_cache[key] = {
            'ts': time.time(),
            'data': data,
        }
        if len(ai_module_cache) > 120:
            # simple LRU-like prune by timestamp
            items = sorted(ai_module_cache.items(), key=lambda x: float(x[1].get('ts', 0.0)), reverse=True)
            keep = dict(items[:80])
            ai_module_cache.clear()
            ai_module_cache.update(keep)


def _llm_complete_openai(cfg, system_prompt, user_prompt):
    payload = {
        'model': str(cfg.get('model', '') or ''),
        'messages': [
            {'role': 'system', 'content': str(system_prompt or '')},
            {'role': 'user', 'content': str(user_prompt or '')},
        ],
        'temperature': float(cfg.get('temperature', 0.2) or 0.2),
        'max_tokens': int(cfg.get('max_tokens', 4000) or 4000),
    }
    headers = {'Authorization': f"Bearer {str(cfg.get('api_key', '') or '').strip()}"}
    url = _openai_chat_url(cfg.get('base_url', ''))
    obj = _http_json_request(url, payload, headers=headers, timeout_sec=int(cfg.get('timeout_sec', 180) or 180))
    choices = obj.get('choices', [])
    if not isinstance(choices, list) or not choices:
        raise RuntimeError("OpenAI compatible response missing choices")
    msg = choices[0].get('message', {}) if isinstance(choices[0], dict) else {}
    text = _extract_text_from_openai_content(msg.get('content', ''))
    if not text:
        text = str(choices[0].get('text', '') or '').strip()
    if not text:
        raise RuntimeError("OpenAI compatible response is empty")
    return text, obj.get('usage', {})


def _llm_complete_anthropic(cfg, system_prompt, user_prompt):
    payload = {
        'model': str(cfg.get('model', '') or ''),
        'max_tokens': int(cfg.get('max_tokens', 4000) or 4000),
        'temperature': float(cfg.get('temperature', 0.2) or 0.2),
        'system': str(system_prompt or ''),
        'messages': [
            {'role': 'user', 'content': str(user_prompt or '')},
        ],
    }
    headers = {
        'x-api-key': str(cfg.get('api_key', '') or '').strip(),
        'anthropic-version': str(cfg.get('anthropic_version', '2023-06-01') or '2023-06-01'),
    }
    url = _anthropic_messages_url(cfg.get('base_url', ''))
    obj = _http_json_request(url, payload, headers=headers, timeout_sec=int(cfg.get('timeout_sec', 180) or 180))
    text = _extract_text_from_anthropic_content(obj.get('content', []))
    if not text:
        raise RuntimeError("Anthropic compatible response is empty")
    return text, obj.get('usage', {})


def _llm_complete_claude(system_prompt, user_prompt):
    prompt = (
        f"{str(system_prompt or '').strip()}\n\n"
        f"{str(user_prompt or '').strip()}"
    ).strip()
    sid = str(uuid.uuid4())
    cmd = _build_claude_cmd(sid, True, stream_json=False)
    rc, out, err = _run_cmd(cmd, timeout=240, input_text=prompt)
    if rc != 0:
        msg = err or out or f"claude exit code={rc}"
        raise RuntimeError(msg)
    text = str(out or '').strip()
    if not text:
        raise RuntimeError("Claude CLI response is empty")
    return text, {}


def _llm_complete_by_provider(cfg, system_prompt, user_prompt, progress_cb=None):
    provider = str(cfg.get('provider', '') or '').strip().lower()
    if provider == 'claude_cli':
        if callable(progress_cb):
            progress_cb('调用本机 Claude Code（claude 命令）', '', 62, 'status', '调用本机 Claude Code（claude 命令）')
        return _llm_complete_claude(system_prompt, user_prompt)
    if provider == 'openai_compat':
        if callable(progress_cb):
            progress_cb('请求 OpenAI 兼容接口', '', 62, 'status', '请求 OpenAI 兼容接口')
        return _llm_complete_openai(cfg, system_prompt, user_prompt)
    if provider == 'anthropic_compat':
        if callable(progress_cb):
            progress_cb('请求 Anthropic 兼容接口', '', 62, 'status', '请求 Anthropic 兼容接口')
        return _llm_complete_anthropic(cfg, system_prompt, user_prompt)
    raise RuntimeError(f"unsupported provider: {provider or 'unknown'}")


def _strip_md_fence(text):
    t = str(text or '').strip()
    if not t:
        return ''
    if t.startswith('```'):
        lines = t.splitlines()
        if len(lines) >= 2 and lines[-1].strip() == '```':
            lines = lines[1:-1]
        elif len(lines) >= 1:
            lines = lines[1:]
        t = "\n".join(lines).strip()
    return t


def _try_parse_json_obj(text):
    t = _strip_md_fence(text)
    if not t:
        return None
    try:
        return json.loads(t)
    except Exception:
        pass
    # try extract largest {...} block
    l = t.find('{')
    r = t.rfind('}')
    if l >= 0 and r > l:
        chunk = t[l:r + 1]
        try:
            return json.loads(chunk)
        except Exception:
            pass
    return None


def _claim_live_alert_task(dedupe_key, min_delay_sec=LIVE_ALERT_SKIP_COOLDOWN_SEC):
    key = str(dedupe_key or "").strip()
    if not key:
        return False
    now = time.time()
    _prune_live_alert_recent(now)
    with live_alert_task_lock:
        next_allowed = float(live_alert_recent.get(key, 0.0) or 0.0)
        if key in live_alert_pending:
            return False
        if next_allowed > now:
            return False
        live_alert_pending.add(key)
        live_alert_recent[key] = now + float(max(15, min_delay_sec))
        return True


def _finish_live_alert_task(dedupe_key, cooldown_sec):
    key = str(dedupe_key or "").strip()
    if not key:
        return
    now = time.time()
    with live_alert_task_lock:
        live_alert_pending.discard(key)
        live_alert_recent[key] = now + float(max(15, cooldown_sec))


def _live_alert_context_lines(monitor_obj, msg, cfg):
    if monitor_obj is None or not isinstance(msg, dict):
        return []
    username = str(msg.get("username", "") or "").strip()
    chat = str(msg.get("chat", username) or username).strip()
    ts = int(msg.get("timestamp", 0) or 0)
    if not username or ts <= 0:
        return []

    window_sec = int((cfg or {}).get("context_window_sec", LIVE_ALERT_DEFAULT["context_window_sec"]) or LIVE_ALERT_DEFAULT["context_window_sec"])
    limit = int((cfg or {}).get("context_message_limit", LIVE_ALERT_DEFAULT["context_message_limit"]) or LIVE_ALERT_DEFAULT["context_message_limit"])
    start_ts = max(0, ts - max(60, window_sec))
    try:
        rows = monitor_obj._query_message_rows(username, start_ts, ts)
    except Exception:
        rows = []
    if not rows:
        return []

    out = []
    for row in rows[-max(2, limit):]:
        try:
            built = monitor_obj._build_message_from_row(username, chat, row, unread=0)
        except Exception:
            continue
        text = _live_alert_plain_text(built)
        if not text:
            continue
        sender = str(built.get("sender", "") or "").strip() or "未知成员"
        stamp = str(built.get("time", "") or "").strip() or datetime.fromtimestamp(int(built.get("timestamp", ts) or ts)).strftime("%H:%M:%S")
        out.append(f"[{stamp}] {sender}: {text}")
    if not out:
        text = _live_alert_plain_text(msg)
        if text:
            sender = str(msg.get("sender", "") or "").strip() or "未知成员"
            stamp = str(msg.get("time", "") or "").strip()
            out.append(f"[{stamp}] {sender}: {text}")
    return out[-max(2, limit):]


def _extract_live_alert_decision(resp_text):
    obj = _try_parse_json_obj(resp_text)
    if not isinstance(obj, dict):
        return None
    severity = str(obj.get("severity", "medium") or "medium").strip().lower()
    if severity not in LIVE_ALERT_SEVERITY_ORDER:
        severity = "medium"
    category = str(obj.get("category", "other") or "other").strip().lower()
    notify_raw = obj.get("notify", False)
    if isinstance(notify_raw, str):
        notify = notify_raw.strip().lower() in ("1", "true", "yes", "y", "notify")
    else:
        notify = bool(notify_raw)
    try:
        confidence = int(float(obj.get("confidence", 0) or 0))
    except Exception:
        confidence = 0
    confidence = max(0, min(100, confidence))
    return {
        "notify": notify,
        "severity": severity,
        "category": category,
        "confidence": confidence,
        "title": str(obj.get("title", "") or "").strip(),
        "reason": str(obj.get("reason", "") or "").strip(),
        "suggested_action": str(obj.get("suggested_action", "") or "").strip(),
        "summary": str(obj.get("summary", "") or "").strip(),
    }


def _fallback_live_alert_decision(msg, candidate):
    tags = set(candidate.get("tags", []) if isinstance(candidate, dict) else [])
    score = int((candidate or {}).get("heuristic_score", 0) or 0)
    text = str((candidate or {}).get("text", "") or _live_alert_plain_text(msg)).strip()
    category = "other"
    severity = "low"
    notify = False
    reason = "启发式命中较弱，先不提醒。"
    if "issue" in tags:
        notify = True
        category = "bug_report"
        severity = "high"
        reason = "命中报错/故障类关键词。"
    elif "purchase" in tags:
        notify = True
        category = "purchase_intent"
        severity = "medium"
        reason = "命中价格/购买/开通类关键词。"
    elif "product" in tags and "question" in tags:
        notify = True
        category = "product_question"
        severity = "medium"
        reason = "命中产品词且是明确提问。"
    elif score >= 5 and "product" in tags:
        notify = True
        category = "negative_feedback"
        severity = "medium"
        reason = "命中产品相关强信号。"
    return {
        "notify": notify,
        "severity": severity,
        "category": category,
        "confidence": 54 if notify else 30,
        "title": "",
        "reason": reason,
        "suggested_action": "",
        "summary": text[:120],
    }


def _run_live_alert_worker(msg, candidate, cfg, context_lines):
    dedupe_key = str((candidate or {}).get("dedupe_key", "") or "").strip()
    cooldown_sec = int((cfg or {}).get("cooldown_sec", LIVE_ALERT_DEFAULT["cooldown_sec"]) or LIVE_ALERT_DEFAULT["cooldown_sec"])
    try:
        provider_cfg = None
        provider_ready = False
        decision = None
        provider_label = "shared_api"
        try:
            provider_cfg = _resolve_ai_provider_config_for_surface('live_alert')
            provider_name = _normalize_provider_name(provider_cfg.get("provider", "openai_compat"))
            provider_label = str(provider_cfg.get("provider", "") or "").strip() or "openai_compat"
            if provider_name == 'claude_cli':
                provider_ready = bool(_probe_claude_status().get("claude_installed", False))
            else:
                provider_ready = bool(_probe_ai_provider_status().get("provider_ready", False))
        except Exception:
            provider_cfg = None
            provider_ready = False
            provider_label = "heuristic_fallback"
        if provider_ready:
            system_prompt = (
                "你是微信群实时消息提醒助手，任务是只在真正值得打扰负责人的情况下提醒。"
                "请严格区分：产品咨询/报错/购买信号/负反馈/重复追问 vs 普通闲聊。"
                "必须只输出 JSON，不要输出解释性文字。"
            )
            extra_prompt = str((cfg or {}).get("ai_extra_prompt", "") or "").strip()
            if extra_prompt:
                system_prompt += "\n补充规则：\n" + extra_prompt
            user_prompt = (
                "请判断下面这条“最新消息”是否需要提醒负责人。\n"
                "提醒标准：\n"
                "1. 产品怎么用、功能在哪里、账号/会员/试用/开通/价格等咨询 -> 倾向提醒\n"
                "2. 报错、失败、用不了、异常、退款、投诉 -> 强提醒\n"
                "3. 普通寒暄、接龙、表情、无关闲聊 -> 不提醒\n"
                "4. 信息不足时优先保守，不要过度提醒\n\n"
                f"产品关键词: {json.dumps((cfg or {}).get('product_keywords', []), ensure_ascii=False)}\n"
                f"问题关键词: {json.dumps((cfg or {}).get('question_keywords', []), ensure_ascii=False)}\n"
                f"报错关键词: {json.dumps((cfg or {}).get('issue_keywords', []), ensure_ascii=False)}\n"
                f"购买关键词: {json.dumps((cfg or {}).get('purchase_keywords', []), ensure_ascii=False)}\n"
                f"忽略关键词: {json.dumps((cfg or {}).get('ignore_keywords', []), ensure_ascii=False)}\n\n"
                "输出 JSON schema:\n"
                '{"notify":true,"confidence":0-100,"severity":"low|medium|high","category":"product_question|bug_report|purchase_intent|negative_feedback|repeat_question|other","title":"短标题","reason":"提醒原因","suggested_action":"建议动作","summary":"给负责人的简短摘要"}\n\n'
                f"群聊: {msg.get('chat', '')}\n"
                f"发送人: {msg.get('sender', '')}\n"
                f"启发式标签: {json.dumps((candidate or {}).get('tags', []), ensure_ascii=False)}\n"
                f"启发式分数: {int((candidate or {}).get('heuristic_score', 0) or 0)}\n"
                f"最新消息: {str((candidate or {}).get('text', '') or _live_alert_plain_text(msg)).strip()}\n"
                f"最近上下文:\n" + "\n".join(context_lines or [])
            )
            resp_text, _usage = _llm_complete_by_provider(provider_cfg or {}, system_prompt, user_prompt)
            decision = _extract_live_alert_decision(resp_text)
        if not isinstance(decision, dict):
            decision = _fallback_live_alert_decision(msg, candidate)
            provider_label = "heuristic_fallback"

        if not bool(decision.get("notify", False)):
            _finish_live_alert_task(dedupe_key, LIVE_ALERT_SKIP_COOLDOWN_SEC)
            return
        if not _live_alert_meets_threshold(decision.get("severity", "low"), cfg):
            _finish_live_alert_task(dedupe_key, cooldown_sec)
            return

        content = str((candidate or {}).get("text", "") or _live_alert_plain_text(msg)).strip()
        title = str(decision.get("title", "") or "").strip() or _make_live_alert_title(decision.get("category"), msg.get("chat"), msg.get("sender"), content)
        row = {
            "id": str(uuid.uuid4()),
            "status": "open",
            "created_at": int(time.time()),
            "updated_at": int(time.time()),
            "message_ts": int(msg.get("timestamp", 0) or 0),
            "username": str(msg.get("username", "") or "").strip(),
            "chat": str(msg.get("chat", "") or "").strip(),
            "sender": str(msg.get("sender", "") or "").strip(),
            "content": content,
            "severity": str(decision.get("severity", "medium") or "medium"),
            "category": str(decision.get("category", "other") or "other"),
            "confidence": int(decision.get("confidence", 0) or 0),
            "title": title,
            "reason": str(decision.get("reason", "") or "").strip(),
            "suggested_action": str(decision.get("suggested_action", "") or "").strip(),
            "summary": str(decision.get("summary", "") or "").strip(),
            "dedupe_key": dedupe_key,
            "source": provider_label,
            "tags": list((candidate or {}).get("tags", []) or []),
            "context": list(context_lines or []),
        }
        openclaw_push = _dispatch_live_alert_to_openclaw(row, cfg)
        if isinstance(openclaw_push, dict):
            row["openclaw_push"] = openclaw_push
        _append_live_alert(row)
        _finish_live_alert_task(dedupe_key, cooldown_sec)
    except Exception as e:
        print(f"[live_alert] worker failed: {e}", flush=True)
        _finish_live_alert_task(dedupe_key, LIVE_ALERT_SKIP_COOLDOWN_SEC)


def _maybe_schedule_live_alert(msg, monitor_obj=None):
    cfg = _load_live_alert_config()
    candidate = _build_live_alert_candidate(msg, cfg)
    if not candidate:
        return
    dedupe_key = str(candidate.get("dedupe_key", "") or "").strip()
    if not _claim_live_alert_task(dedupe_key, LIVE_ALERT_SKIP_COOLDOWN_SEC):
        return
    context_lines = _live_alert_context_lines(monitor_obj, msg, cfg)
    _live_alert_executor.submit(
        _run_live_alert_worker,
        dict(msg or {}),
        dict(candidate or {}),
        dict(cfg or {}),
        list(context_lines or []),
    )


def _merge_usage_dict(total_usage, usage):
    out = dict(total_usage if isinstance(total_usage, dict) else {})
    if not isinstance(usage, dict):
        return out
    for k, v in usage.items():
        key = str(k or '').strip()
        if not key:
            continue
        if isinstance(v, (int, float)):
            base = out.get(key, 0)
            try:
                base_num = float(base)
            except Exception:
                base_num = 0.0
            out[key] = base_num + float(v)
        else:
            out[key] = v
    return out


def _truncate_text_for_prompt(text, max_chars=22000):
    s = str(text or '')
    lim = _safe_int(max_chars, 22000, 512, 300000)
    if len(s) <= lim:
        return s
    cut = max(0, len(s) - lim)
    return s[:lim] + f"\n...[truncated {cut} chars]"


def _mcp_depth_profile(depth='standard'):
    d = str(depth or 'standard').strip().lower()
    if d == 'quick':
        return {
            'rounds': 1,
            'max_calls_per_round': 1,
            'tool_max_chars': 180000,
            'result_clip': 14000,
        }
    if d == 'deep':
        return {
            'rounds': 3,
            'max_calls_per_round': 3,
            'tool_max_chars': 450000,
            'result_clip': 32000,
        }
    return {
        'rounds': 2,
        'max_calls_per_round': 2,
        'tool_max_chars': 280000,
        'result_clip': 22000,
    }


def _get_mcp_bridge_module():
    global mcp_bridge_module, mcp_bridge_error
    with mcp_bridge_lock:
        if mcp_bridge_module is not None:
            return mcp_bridge_module
        mcp_bridge_error = ''

        server_path = os.path.join(RUNTIME_BASE_DIR, 'mcp_server.py')
        if not os.path.exists(server_path):
            server_path = os.path.join(RESOURCE_BASE_DIR, 'mcp_server.py')
        if not os.path.exists(server_path):
            mcp_bridge_error = 'mcp_server.py not found'
            raise RuntimeError(mcp_bridge_error)

        try:
            spec = importlib.util.spec_from_file_location('wechat_mcp_bridge_runtime', server_path)
            if spec is None or spec.loader is None:
                raise RuntimeError('failed to load mcp_server.py spec')
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            mcp_bridge_module = mod
            return mcp_bridge_module
        except Exception as e:
            mcp_bridge_error = str(e)
            raise RuntimeError(f'load mcp bridge failed: {e}')


def _extract_tool_calls_from_text(text, max_calls=2):
    def _parse_args_loose(arg_val):
        if isinstance(arg_val, dict):
            return dict(arg_val)
        if not isinstance(arg_val, str):
            return {}
        s = str(arg_val or '').strip()
        if not s:
            return {}
        obj = _try_parse_json_obj(s)
        if isinstance(obj, dict):
            return obj

        out = {}
        try:
            parts = next(csv.reader([s], skipinitialspace=True))
        except Exception:
            parts = [x.strip() for x in s.split(',') if str(x).strip()]
        for part in parts:
            m = re.match(r'^\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*[:=]\s*(.+?)\s*$', str(part))
            if not m:
                continue
            k = str(m.group(1) or '').strip()
            v_raw = str(m.group(2) or '').strip()
            if not k:
                continue
            if (v_raw.startswith('"') and v_raw.endswith('"')) or (v_raw.startswith("'") and v_raw.endswith("'")):
                v = v_raw[1:-1]
            elif re.fullmatch(r'-?\d+', v_raw):
                try:
                    v = int(v_raw)
                except Exception:
                    v = v_raw
            elif re.fullmatch(r'-?\d+\.\d+', v_raw):
                try:
                    v = float(v_raw)
                except Exception:
                    v = v_raw
            else:
                low = v_raw.lower()
                if low in ('true', 'false'):
                    v = (low == 'true')
                else:
                    v = v_raw
            out[k] = v
        return out

    def _normalize_raw_calls(raw):
        if not isinstance(raw, list):
            return []
        out_calls = []
        for item in raw:
            if not isinstance(item, dict):
                continue
            fn_obj = item.get('function', {}) if isinstance(item.get('function', {}), dict) else {}
            name = str(
                item.get('name', '')
                or item.get('tool', '')
                or fn_obj.get('name', '')
            ).strip()
            if not name:
                continue
            args = item.get('arguments', item.get('args', fn_obj.get('arguments', {})))
            args = _parse_args_loose(args)
            out_calls.append({'name': name, 'arguments': args})
            if len(out_calls) >= _safe_int(max_calls, 2, 1, 8):
                break
        return out_calls

    def _extract_from_plain_text(raw_text):
        s = str(raw_text or '')
        if not s:
            return []
        out_calls = []
        pat = re.compile(r'([a-z_][a-z0-9_]*)\s*\(([^)]*)\)', flags=re.I)
        for m in pat.finditer(s):
            name = str(m.group(1) or '').strip()
            if name not in AI_MCP_ALLOWED_TOOLS:
                continue
            args = _parse_args_loose(m.group(2) or '')
            out_calls.append({'name': name, 'arguments': args})
            if len(out_calls) >= _safe_int(max_calls, 2, 1, 8):
                break
        return out_calls

    obj = _try_parse_json_obj(text)
    raw_calls = []
    if isinstance(obj, dict):
        for key in ('tool_calls', 'calls', 'tools', 'mcp_calls'):
            cand = obj.get(key, [])
            if isinstance(cand, list):
                raw_calls = cand
                if raw_calls:
                    break
    elif isinstance(obj, list):
        raw_calls = obj

    out = _normalize_raw_calls(raw_calls)
    if out:
        return out[:_safe_int(max_calls, 2, 1, 8)]
    return _extract_from_plain_text(text)[:_safe_int(max_calls, 2, 1, 8)]


def _tool_call_signature(call_obj):
    c = call_obj if isinstance(call_obj, dict) else {}
    name = str(c.get('name', '') or '').strip()
    args = c.get('arguments', {}) if isinstance(c.get('arguments', {}), dict) else {}
    try:
        args_key = json.dumps(args, ensure_ascii=False, sort_keys=True)
    except Exception:
        args_key = str(args)
    return f"{name}|{args_key}"


def _pick_top_sender_name_from_context(context_obj):
    ctx = context_obj if isinstance(context_obj, dict) else {}
    top = ctx.get('top_senders', [])
    if not isinstance(top, list):
        return ''
    for row in top:
        if not isinstance(row, dict):
            continue
        sender = str(row.get('sender', '') or '').strip()
        if sender:
            return sender
    return ''


def _pick_top_keywords_from_context(context_obj, limit=3):
    ctx = context_obj if isinstance(context_obj, dict) else {}
    kws = ctx.get('keywords', [])
    if not isinstance(kws, list):
        return []
    out = []
    seen = set()
    for row in kws:
        if not isinstance(row, dict):
            continue
        keyword = str(row.get('keyword', '') or row.get('topic', '') or '').strip()
        if not keyword:
            continue
        sig = keyword.lower()
        if sig in seen:
            continue
        seen.add(sig)
        out.append(keyword)
        if len(out) >= max(1, int(limit or 1)):
            break
    return out


def _seed_tool_calls_for_module(spec, context_obj, depth='standard', max_calls=2):
    module = str((spec or {}).get('module', '') or '').strip().lower()
    ctx = context_obj if isinstance(context_obj, dict) else {}
    chat = str(ctx.get('chat', '') or ctx.get('username', '') or '').strip()
    rg = ctx.get('range', {}) if isinstance(ctx.get('range', {}), dict) else {}
    start_ts = _safe_int(rg.get('start_ts', 0), 0, 0, None)
    end_ts = _safe_int(rg.get('end_ts', 0), 0, 0, None)
    top_sender = _pick_top_sender_name_from_context(ctx)
    top_keywords = _pick_top_keywords_from_context(ctx, limit=3)

    if not chat:
        return []

    depth_name = str(depth or 'standard').strip().lower()
    if depth_name not in ('quick', 'standard', 'deep'):
        depth_name = 'standard'
    history_limit = 16000 if depth_name == 'quick' else (42000 if depth_name == 'standard' else 90000)
    sender_limit = 1200 if depth_name == 'quick' else (2400 if depth_name == 'standard' else 4200)

    calls = []
    def _push(name, arguments):
        if name not in AI_MCP_ALLOWED_TOOLS:
            return
        calls.append({'name': name, 'arguments': dict(arguments if isinstance(arguments, dict) else {})})

    if module == 'report':
        _push('get_round_table_candidates', {
            'chat_name': chat,
            'start_ts': start_ts,
            'end_ts': end_ts,
            'window_minutes': 180,
            'min_participants': 5,
            'keywords': ' '.join(top_keywords[:2]),
            'limit': 18,
        })
        _push('get_high_quality_candidates', {
            'chat_name': chat,
            'start_ts': start_ts,
            'end_ts': end_ts,
            'min_text_length': 60,
            'min_quality_score': 68,
            'context_window_seconds': 180,
            'limit': 28,
        })
        if top_keywords:
            _push('search_messages', {
                'chat_name': chat,
                'keyword': top_keywords[0],
                'start_ts': start_ts,
                'end_ts': end_ts,
                'limit': 180,
            })
        if top_sender:
            _push('get_sender_profile', {
                'chat_name': chat,
                'sender': top_sender,
                'start_ts': start_ts,
                'end_ts': end_ts,
                'context_before': 4,
                'context_after': 4,
            })
        _push('get_daily_message_trend', {
            'chat_name': chat,
            'granularity': 'day',
            'start_ts': start_ts,
            'end_ts': end_ts,
        })
    elif module == 'sentiment':
        _push('get_emotion_signal_summary', {
            'chat_name': chat,
            'start_ts': start_ts,
            'end_ts': end_ts,
            'limit': history_limit,
        })
        if top_sender:
            _push('get_sender_profile', {
                'chat_name': chat,
                'sender': top_sender,
                'start_ts': start_ts,
                'end_ts': end_ts,
                'context_before': -1,
                'context_after': -1,
            })
        _push('get_chat_history', {
            'chat_name': chat,
            'limit': history_limit,
            'offset': 0,
            'start_ts': start_ts,
            'end_ts': end_ts,
        })
    elif module == 'topic':
        _push('get_topic_distribution', {
            'chat_name': chat,
            'start_ts': start_ts,
            'end_ts': end_ts,
            'min_topic_frequency': 3,
            'clustering_method': 'keyword',
        })
        _push('get_round_table_candidates', {
            'chat_name': chat,
            'start_ts': start_ts,
            'end_ts': end_ts,
            'window_minutes': 210,
            'min_participants': 4,
            'keywords': ' '.join(top_keywords[:3]),
            'limit': 20,
        })
        if top_keywords:
            _push('search_messages', {
                'chat_name': chat,
                'keyword': top_keywords[0],
                'start_ts': start_ts,
                'end_ts': end_ts,
                'limit': 180,
            })
        _push('get_high_quality_candidates', {
            'chat_name': chat,
            'start_ts': start_ts,
            'end_ts': end_ts,
            'min_text_length': 56,
            'min_quality_score': 64,
            'context_window_seconds': 180,
            'limit': 20,
        })
    elif module == 'risk':
        _push('get_risk_alert_candidates', {
            'chat_name': chat,
            'start_ts': start_ts,
            'end_ts': end_ts,
            'limit': history_limit,
        })
        _push('smart_search_messages', {
            'chat_name': chat,
            'query': '投诉 OR 退款 OR 违规 OR 审核 OR bug OR 崩 OR 无语 OR 报错',
            'search_mode': 'boolean',
            'start_ts': start_ts,
            'end_ts': end_ts,
            'limit': 800,
        })
    elif module == 'persona':
        _push('get_member_profile_cards', {
            'chat_name': chat,
            'limit': 12,
            'start_ts': start_ts,
            'end_ts': end_ts,
        })
        _push('get_group_member_stats', {
            'chat_name': chat,
            'limit': 120,
            'start_ts': start_ts,
            'end_ts': end_ts,
        })
        if top_sender:
            _push('get_sender_profile', {
                'chat_name': chat,
                'sender': top_sender,
                'start_ts': start_ts,
                'end_ts': end_ts,
                'context_before': 6,
                'context_after': 6,
            })
            _push('get_sender_messages', {
                'chat_name': chat,
                'sender': top_sender,
                'limit': 120,
                'start_ts': start_ts,
                'end_ts': end_ts,
                'context_before': 2,
                'context_after': 2,
            })
    elif module == 'strategy':
        _push('get_score_rules', {})
        _push('get_score_leaderboard', {
            'chat_name': chat,
            'start_ts': start_ts,
            'end_ts': end_ts,
            'include_manual': True,
            'limit': 150,
        })
        _push('get_topic_score_candidates', {
            'chat_name': chat,
            'start_ts': start_ts,
            'end_ts': end_ts,
            'window_minutes': 180,
            'min_unique_responders': 5,
            'limit': 60,
        })
        _push('get_high_quality_candidates', {
            'chat_name': chat,
            'start_ts': start_ts,
            'end_ts': end_ts,
            'min_text_length': 50,
            'min_quality_score': 60,
            'limit': 80,
        })
        _push('get_risk_alert_candidates', {
            'chat_name': chat,
            'start_ts': start_ts,
            'end_ts': end_ts,
            'limit': 3000,
        })
        _push('get_round_table_candidates', {
            'chat_name': chat,
            'start_ts': start_ts,
            'end_ts': end_ts,
            'window_minutes': 180,
            'min_participants': 5,
            'limit': 50,
        })
    else:
        _push('get_chat_detail_stats', {
            'chat_name': chat,
            'start_ts': start_ts,
            'end_ts': end_ts,
            'include_topics': True,
            'include_media_breakdown': True,
        })

    return calls[:_safe_int(max_calls, 2, 1, 8)]


def _build_openai_tools_for_mcp():
    def _guess_type(desc):
        d = str(desc or '').strip().lower()
        if 'bool' in d:
            return 'boolean'
        if 'int' in d or 'float' in d or 'number' in d or 'unix seconds' in d:
            return 'number'
        return 'string'

    tools = []
    for row in AI_MCP_TOOL_SCHEMAS:
        if not isinstance(row, dict):
            continue
        name = str(row.get('name', '') or '').strip()
        if not name or name not in AI_MCP_ALLOWED_TOOLS:
            continue
        args = row.get('args', {}) if isinstance(row.get('args', {}), dict) else {}
        props = {}
        required = []
        for k, v in args.items():
            key = str(k or '').strip()
            if not key:
                continue
            desc = str(v or '').strip()
            props[key] = {
                'type': _guess_type(desc),
                'description': desc,
            }
            if 'optional' not in desc.lower():
                required.append(key)
        tools.append({
            'type': 'function',
            'function': {
                'name': name,
                'description': str(row.get('description', '') or name),
                'parameters': {
                    'type': 'object',
                    'properties': props,
                    'required': required,
                    'additionalProperties': False,
                },
            },
        })
    return tools


def _plan_tool_calls_openai_native(cfg, system_prompt, plan_prompt, max_calls=2):
    payload = {
        'model': str(cfg.get('model', '') or ''),
        'messages': [
            {'role': 'system', 'content': str(system_prompt or '')},
            {'role': 'user', 'content': str(plan_prompt or '')},
        ],
        'temperature': 0,
        'max_tokens': min(1200, int(cfg.get('max_tokens', 4000) or 4000)),
        'tools': _build_openai_tools_for_mcp(),
        'tool_choice': 'auto',
        'parallel_tool_calls': False,
    }
    headers = {'Authorization': f"Bearer {str(cfg.get('api_key', '') or '').strip()}"}
    url = _openai_chat_url(cfg.get('base_url', ''))
    obj = _http_json_request(url, payload, headers=headers, timeout_sec=int(cfg.get('timeout_sec', 180) or 180))
    choices = obj.get('choices', [])
    if not isinstance(choices, list) or not choices:
        raise RuntimeError("native tool plan response missing choices")

    msg = choices[0].get('message', {}) if isinstance(choices[0], dict) else {}
    tool_calls = msg.get('tool_calls', []) if isinstance(msg, dict) else []
    calls = []
    if isinstance(tool_calls, list):
        for tc in tool_calls:
            if not isinstance(tc, dict):
                continue
            fn = tc.get('function', {}) if isinstance(tc.get('function', {}), dict) else {}
            name = str(fn.get('name', '') or tc.get('name', '') or '').strip()
            if not name:
                continue
            args_raw = fn.get('arguments', tc.get('arguments', {}))
            args = {}
            if isinstance(args_raw, dict):
                args = dict(args_raw)
            elif isinstance(args_raw, str):
                parsed = _try_parse_json_obj(args_raw)
                if isinstance(parsed, dict):
                    args = parsed
            calls.append({'name': name, 'arguments': args})
            if len(calls) >= _safe_int(max_calls, 2, 1, 8):
                break

    text = _extract_text_from_openai_content(msg.get('content', '') if isinstance(msg, dict) else '')
    if not text:
        text = str(msg.get('content', '') or '').strip() if isinstance(msg, dict) else ''
    if not calls and text:
        calls = _extract_tool_calls_from_text(text, max_calls=max_calls)

    return calls, text, obj.get('usage', {})


def _safe_bool(v, default=False):
    if isinstance(v, bool):
        return v
    if v is None:
        return bool(default)
    s = str(v).strip().lower()
    if s in ('1', 'true', 'yes', 'y', 'on'):
        return True
    if s in ('0', 'false', 'no', 'n', 'off'):
        return False
    return bool(default)


def _normalize_mcp_tool_args(tool_name, arguments, context_obj, depth='standard'):
    name = str(tool_name or '').strip()
    if name not in AI_MCP_ALLOWED_TOOLS:
        raise RuntimeError(f'tool not allowed: {name}')
    args_in = dict(arguments if isinstance(arguments, dict) else {})

    ctx = context_obj if isinstance(context_obj, dict) else {}
    range_obj = ctx.get('range', {}) if isinstance(ctx.get('range', {}), dict) else {}
    default_chat = str(ctx.get('chat', '') or ctx.get('username', '') or '').strip()
    default_start = _safe_int(range_obj.get('start_ts', 0), 0, 0, None)
    default_end = _safe_int(range_obj.get('end_ts', 0), 0, 0, None)
    profile = _mcp_depth_profile(depth)
    default_max_chars = int(profile.get('tool_max_chars', 280000) or 280000)

    def _chat_name():
        val = str(args_in.get('chat_name', '') or default_chat).strip()
        if not val:
            raise RuntimeError('missing chat_name')
        return val

    if name == 'get_chat_history':
        return {
            'chat_name': _chat_name(),
            'limit': _safe_int(args_in.get('limit', 40000), 40000, 1, 200000),
            'offset': _safe_int(args_in.get('offset', 0), 0, 0, 2000000),
            'start_ts': _safe_int(args_in.get('start_ts', default_start), default_start, 0, None),
            'end_ts': _safe_int(args_in.get('end_ts', default_end), default_end, 0, None),
            'max_chars': _safe_int(args_in.get('max_chars', default_max_chars), default_max_chars, 100000, 900000),
        }

    if name == 'get_sender_messages':
        sender = str(args_in.get('sender', '') or '').strip()
        if not sender:
            raise RuntimeError('missing sender for get_sender_messages')
        return {
            'chat_name': _chat_name(),
            'sender': sender,
            'limit': _safe_int(args_in.get('limit', 2000), 2000, 1, 20000),
            'offset': _safe_int(args_in.get('offset', 0), 0, 0, 2000000),
            'start_ts': _safe_int(args_in.get('start_ts', default_start), default_start, 0, None),
            'end_ts': _safe_int(args_in.get('end_ts', default_end), default_end, 0, None),
            'max_chars': _safe_int(args_in.get('max_chars', default_max_chars), default_max_chars, 100000, 900000),
            'context_before': _safe_int(args_in.get('context_before', -1), -1, -1, 60),
            'context_after': _safe_int(args_in.get('context_after', -1), -1, -1, 60),
        }

    if name == 'get_sender_profile':
        sender = str(args_in.get('sender', '') or '').strip()
        if not sender:
            raise RuntimeError('missing sender for get_sender_profile')
        return {
            'chat_name': _chat_name(),
            'sender': sender,
            'start_ts': _safe_int(args_in.get('start_ts', default_start), default_start, 0, None),
            'end_ts': _safe_int(args_in.get('end_ts', default_end), default_end, 0, None),
            'context_before': _safe_int(args_in.get('context_before', -1), -1, -1, 60),
            'context_after': _safe_int(args_in.get('context_after', -1), -1, -1, 60),
        }

    if name == 'search_messages':
        kw = str(args_in.get('keyword', '') or '').strip()
        if not kw:
            raise RuntimeError('missing keyword for search_messages')
        return {
            'keyword': kw,
            'limit': _safe_int(args_in.get('limit', 500), 500, 1, 5000),
            'offset': _safe_int(args_in.get('offset', 0), 0, 0, 2000000),
            'start_ts': _safe_int(args_in.get('start_ts', default_start), default_start, 0, None),
            'end_ts': _safe_int(args_in.get('end_ts', default_end), default_end, 0, None),
            'chat_name': str(args_in.get('chat_name', default_chat) or '').strip(),
        }

    if name == 'smart_search_messages':
        query = str(args_in.get('query', '') or '').strip()
        if not query:
            raise RuntimeError('missing query for smart_search_messages')
        mode = str(args_in.get('search_mode', 'boolean') or 'boolean').strip().lower()
        if mode not in ('simple', 'boolean', 'regex'):
            mode = 'boolean'
        return {
            'chat_name': _chat_name(),
            'query': query,
            'search_mode': mode,
            'start_ts': _safe_int(args_in.get('start_ts', default_start), default_start, 0, None),
            'end_ts': _safe_int(args_in.get('end_ts', default_end), default_end, 0, None),
            'limit': _safe_int(args_in.get('limit', 1000), 1000, 1, 20000),
        }

    if name == 'get_recent_sessions':
        return {'limit': _safe_int(args_in.get('limit', 200), 200, 1, 2000)}

    if name == 'get_chat_detail_stats':
        return {
            'chat_name': _chat_name(),
            'start_ts': _safe_int(args_in.get('start_ts', default_start), default_start, 0, None),
            'end_ts': _safe_int(args_in.get('end_ts', default_end), default_end, 0, None),
            'include_topics': _safe_bool(args_in.get('include_topics', True), True),
            'include_media_breakdown': _safe_bool(args_in.get('include_media_breakdown', True), True),
        }

    if name == 'get_daily_message_trend':
        granularity = str(args_in.get('granularity', 'day') or 'day').strip().lower()
        if granularity not in ('day', 'week', 'month'):
            granularity = 'day'
        return {
            'chat_name': _chat_name(),
            'granularity': granularity,
            'start_ts': _safe_int(args_in.get('start_ts', default_start), default_start, 0, None),
            'end_ts': _safe_int(args_in.get('end_ts', default_end), default_end, 0, None),
        }

    if name == 'get_group_member_stats':
        return {
            'chat_name': _chat_name(),
            'limit': _safe_int(args_in.get('limit', 80), 80, 1, 1000),
            'start_ts': _safe_int(args_in.get('start_ts', default_start), default_start, 0, None),
            'end_ts': _safe_int(args_in.get('end_ts', default_end), default_end, 0, None),
        }

    if name == 'get_member_profile_cards':
        return {
            'chat_name': _chat_name(),
            'limit': _safe_int(args_in.get('limit', 12), 12, 3, 30),
            'start_ts': _safe_int(args_in.get('start_ts', default_start), default_start, 0, None),
            'end_ts': _safe_int(args_in.get('end_ts', default_end), default_end, 0, None),
        }

    if name == 'get_emotion_signal_summary':
        return {
            'chat_name': _chat_name(),
            'limit': _safe_int(args_in.get('limit', 5000), 5000, 200, 60000),
            'start_ts': _safe_int(args_in.get('start_ts', default_start), default_start, 0, None),
            'end_ts': _safe_int(args_in.get('end_ts', default_end), default_end, 0, None),
        }

    if name == 'get_risk_alert_candidates':
        return {
            'chat_name': _chat_name(),
            'limit': _safe_int(args_in.get('limit', 4000), 4000, 200, 80000),
            'start_ts': _safe_int(args_in.get('start_ts', default_start), default_start, 0, None),
            'end_ts': _safe_int(args_in.get('end_ts', default_end), default_end, 0, None),
        }

    if name == 'get_topic_distribution':
        return {
            'chat_name': _chat_name(),
            'start_ts': _safe_int(args_in.get('start_ts', default_start), default_start, 0, None),
            'end_ts': _safe_int(args_in.get('end_ts', default_end), default_end, 0, None),
            'min_topic_frequency': _safe_int(args_in.get('min_topic_frequency', 3), 3, 1, 100000),
            'clustering_method': 'keyword',
        }

    if name == 'get_score_rules':
        return {}

    if name == 'get_score_leaderboard':
        return {
            'chat_name': _chat_name(),
            'start_ts': _safe_int(args_in.get('start_ts', default_start), default_start, 0, None),
            'end_ts': _safe_int(args_in.get('end_ts', default_end), default_end, 0, None),
            'include_manual': _safe_bool(args_in.get('include_manual', True), True),
            'limit': _safe_int(args_in.get('limit', 120), 120, 1, 500),
        }

    if name == 'get_topic_score_candidates':
        return {
            'chat_name': _chat_name(),
            'start_ts': _safe_int(args_in.get('start_ts', default_start), default_start, 0, None),
            'end_ts': _safe_int(args_in.get('end_ts', default_end), default_end, 0, None),
            'window_minutes': _safe_int(args_in.get('window_minutes', 180), 180, 30, 1440),
            'min_unique_responders': _safe_int(args_in.get('min_unique_responders', 5), 5, 1, 200),
            'limit': _safe_int(args_in.get('limit', 60), 60, 1, 300),
        }

    if name == 'get_high_quality_candidates':
        return {
            'chat_name': _chat_name(),
            'start_ts': _safe_int(args_in.get('start_ts', default_start), default_start, 0, None),
            'end_ts': _safe_int(args_in.get('end_ts', default_end), default_end, 0, None),
            'min_text_length': _safe_int(args_in.get('min_text_length', 50), 50, 20, 300),
            'min_quality_score': _safe_int(args_in.get('min_quality_score', 60), 60, 30, 95),
            'context_window_seconds': _safe_int(args_in.get('context_window_seconds', 120), 120, 30, 600),
            'limit': _safe_int(args_in.get('limit', 120), 120, 1, 500),
        }

    if name == 'get_round_table_candidates':
        return {
            'chat_name': _chat_name(),
            'start_ts': _safe_int(args_in.get('start_ts', default_start), default_start, 0, None),
            'end_ts': _safe_int(args_in.get('end_ts', default_end), default_end, 0, None),
            'window_minutes': _safe_int(args_in.get('window_minutes', 180), 180, 30, 720),
            'min_participants': _safe_int(args_in.get('min_participants', 5), 5, 2, 200),
            'keywords': str(args_in.get('keywords', '') or '').strip(),
            'limit': _safe_int(args_in.get('limit', 80), 80, 1, 500),
        }

    if name == 'get_new_messages':
        return {}

    if name == 'export_chat_markdown':
        time_range = str(args_in.get('time_range', '') or '').strip().lower()
        if time_range not in ('', 'all', 'all_time', 'last_7_days', '7d', '7days', 'last_30_days', '30d', '30days', 'last_180_days', '180d', 'half_year', 'last_365_days', '365d', '1y', 'year'):
            time_range = ''
        return {
            'chat_name': _chat_name(),
            'time_range': time_range or ('last_7_days' if default_start or default_end else 'all'),
            'start_ts': _safe_int(args_in.get('start_ts', default_start), default_start, 0, None),
            'end_ts': _safe_int(args_in.get('end_ts', default_end), default_end, 0, None),
            'per_file_messages': _safe_int(args_in.get('per_file_messages', 4000), 4000, 200, 10000),
            'max_chars_per_file': _safe_int(args_in.get('max_chars_per_file', 700000), 700000, 50000, 1200000),
            'include_media': _safe_bool(args_in.get('include_media', True), True),
            'include_system': _safe_bool(args_in.get('include_system', False), False),
        }

    if name == 'read_exported_markdown':
        path = str(args_in.get('path', '') or '').strip()
        if not path:
            raise RuntimeError('missing path for read_exported_markdown')
        return {
            'path': path,
            'start_line': _safe_int(args_in.get('start_line', 1), 1, 1, 10_000_000),
            'max_lines': _safe_int(args_in.get('max_lines', 1200), 1200, 50, 4000),
        }

    raise RuntimeError(f'unsupported tool: {name}')


def _execute_mcp_tool_call(call_obj, context_obj, depth='standard'):
    call = call_obj if isinstance(call_obj, dict) else {}
    tool_name = str(call.get('name', '') or '').strip()
    args = call.get('arguments', {}) if isinstance(call.get('arguments', {}), dict) else {}
    started = time.perf_counter()

    if not tool_name:
        return {
            'name': '',
            'arguments': {},
            'error': 'missing tool name',
            'ok': False,
            'elapsed_ms': 0.0,
            'result': '',
        }

    try:
        norm_args = _normalize_mcp_tool_args(tool_name, args, context_obj, depth=depth)
        mod = _get_mcp_bridge_module()
        fn = getattr(mod, tool_name, None)
        if not callable(fn):
            raise RuntimeError(f'tool function not found: {tool_name}')
        raw = fn(**norm_args)
        raw_text = str(raw or '')
        elapsed_ms = round((time.perf_counter() - started) * 1000, 1)
        return {
            'name': tool_name,
            'arguments': norm_args,
            'ok': True,
            'error': '',
            'elapsed_ms': elapsed_ms,
            'result': raw_text,
        }
    except Exception as e:
        elapsed_ms = round((time.perf_counter() - started) * 1000, 1)
        return {
            'name': tool_name,
            'arguments': args,
            'ok': False,
            'error': str(e),
            'elapsed_ms': elapsed_ms,
            'result': '',
        }


def _build_mcp_planning_prompt(spec, context_obj, evidence_rows, max_calls):
    ctx = context_obj if isinstance(context_obj, dict) else {}
    small_ctx = {
        'chat': ctx.get('chat', ''),
        'username': ctx.get('username', ''),
        'range': ctx.get('range', {}),
        'summary': ctx.get('summary', {}),
    }
    brief_evidence = []
    for r in (evidence_rows or [])[-8:]:
        if not isinstance(r, dict):
            continue
        brief_evidence.append(
            {
                'name': r.get('name', ''),
                'ok': bool(r.get('ok', False)),
                'elapsed_ms': r.get('elapsed_ms', 0),
                'arguments': r.get('arguments', {}),
                'result_excerpt': _truncate_text_for_prompt(r.get('result', ''), 2000),
                'error': r.get('error', ''),
            }
        )
    module_name = str((spec or {}).get('module', '') or '').strip().lower()
    planning_hint = {
        'report': (
            "Need evidence for turning points, concrete topic examples, representative quotes, "
            "and the members who pushed the discussion forward."
        ),
        'topic': (
            "Need evidence for topic evolution, trigger moments, contrasting stances, "
            "and quotes that show why the topic heated up."
        ),
        'persona': (
            "Need evidence for why a member matters: what they said, how often they appeared, "
            "how others followed or responded, and what interaction style supports playful MBTI/animal/archetype guesses."
        ),
        'risk': (
            "Need evidence for suspicious spikes, risky links, repeated complaints, or concentrated negative feedback."
        ),
        'strategy': (
            "Need evidence for topics and member behaviors that can be turned into next-step operating plans."
        ),
    }.get(module_name, "Prefer tools that add concrete evidence instead of re-fetching summary statistics.")
    return (
        "You are an MCP tool planner for WeChat analysis.\\n"
        "Return ONLY one JSON object, with no markdown and no extra prose.\\n"
        "Available whitelist tools:\\n"
        f"{json.dumps(AI_MCP_TOOL_SCHEMAS, ensure_ascii=False)}\\n\\n"
        f"Current module: {spec.get('title', spec.get('module', 'analysis'))}\\n"
        f"Current context JSON: {json.dumps(small_ctx, ensure_ascii=False)}\\n"
        f"Already collected evidence JSON: {json.dumps(brief_evidence, ensure_ascii=False)}\\n\\n"
        f"Evidence priority: {planning_hint}\\n"
        "Output format exactly:\\n"
        "{\\\"tool_calls\\\":[{\\\"name\\\":\\\"tool_name\\\",\\\"arguments\\\":{}}]}\\n"
        f"Rules: at most {int(max_calls)} tool_calls this round. "
        "If evidence is enough, return {\\\"tool_calls\\\":[]}.\\n"
        "Prefer current chat and selected time range unless evidence is insufficient.\\n"
        "Avoid re-fetching aggregate stats that are already present in context; use tools to补人物、话题、时间节点和原话证据。"
    )


def _build_mcp_final_prompt(spec, context_obj, schema_hint, module_guide_text, evidence_rows):
    ctx = context_obj if isinstance(context_obj, dict) else {}
    evidence_for_model = []
    for r in (evidence_rows or [])[-16:]:
        if not isinstance(r, dict):
            continue
        evidence_for_model.append(
            {
                'name': r.get('name', ''),
                'ok': bool(r.get('ok', False)),
                'elapsed_ms': r.get('elapsed_ms', 0),
                'arguments': r.get('arguments', {}),
                'result': _truncate_text_for_prompt(r.get('result', ''), 26000),
                'error': r.get('error', ''),
            }
        )
    return (
        f"Module: {spec.get('title', spec.get('module', 'analysis'))}\\n"
        "Generate final analysis output as ONE JSON object only.\\n"
        f"Target schema hint: {schema_hint}\\n"
        "Rules:\\n"
        "1) Prefer MCP evidence over aggregated summaries when conflict exists.\\n"
        "2) Do not fabricate missing facts; if evidence is weak, state insufficiency in relevant fields.\\n"
        "3) Keep recommendations actionable and scoped to the selected time range.\\n"
        "4) Prefer exact dates, member names, topic names, file/link names, and trigger events over vague summaries.\\n"
        "5) Reconstruct what happened like a readable postmortem, not a flat dashboard dump.\\n"
        f"Module guide: {module_guide_text}\\n"
        f"Structured context JSON:\\n{json.dumps(ctx, ensure_ascii=False)}\\n"
        f"MCP evidence JSON:\\n{json.dumps(evidence_for_model, ensure_ascii=False)}"
    )


def _llm_complete_module_with_mcp(cfg_effective, spec, context_obj, schema_hint, module_guide_text, depth='standard', progress_cb=None):
    profile = _mcp_depth_profile(depth)
    rounds = int(profile.get('rounds', 2) or 2)
    max_calls = int(profile.get('max_calls_per_round', 2) or 2)
    clip_len = int(profile.get('result_clip', 22000) or 22000)
    usage_total = {}
    evidence_rows = []
    planning_raw = []
    planning_errors = []
    executed_signatures = set()
    system_prompt = (
        "You are a senior WeChat analytics assistant. "
        "You can request backend MCP tools and then produce structured analysis JSON."
    )
    provider = str(cfg_effective.get('provider', '') or '').strip().lower()
    for ridx in range(max(1, rounds)):
        if callable(progress_cb):
            progress_cb(
                f'规划第 {ridx + 1}/{max(1, rounds)} 轮补证据',
                '寻找还缺的转折点、人物和原话',
                min(56, 34 + ridx * 8),
                'status',
                f'规划第 {ridx + 1}/{max(1, rounds)} 轮补证据'
            )
        plan_prompt = _build_mcp_planning_prompt(spec, context_obj, evidence_rows, max_calls=max_calls)
        calls = []
        plan_text = ''
        planner_mode = 'text_json'
        if provider == 'openai_compat':
            try:
                native_calls, native_text, usage = _plan_tool_calls_openai_native(
                    cfg_effective,
                    system_prompt,
                    plan_prompt,
                    max_calls=max_calls,
                )
                usage_total = _merge_usage_dict(usage_total, usage)
                calls = native_calls if isinstance(native_calls, list) else []
                plan_text = str(native_text or '')
                planner_mode = 'native_tools'
            except Exception as e:
                planning_errors.append(f"round {ridx + 1} native planner failed: {e}")
        if not calls:
            try:
                plan_text, usage = _llm_complete_by_provider(cfg_effective, system_prompt, plan_prompt, progress_cb=progress_cb)
                usage_total = _merge_usage_dict(usage_total, usage)
                calls = _extract_tool_calls_from_text(plan_text, max_calls=max_calls)
                planner_mode = 'text_json'
            except Exception as e:
                planning_errors.append(f"round {ridx + 1} text planner failed: {e}")
                calls = []
                plan_text = ''
        calls = [
            c for c in (calls or [])
            if isinstance(c, dict)
            and str(c.get('name', '') or '').strip() in AI_MCP_ALLOWED_TOOLS
        ]
        if not calls:
            calls = _seed_tool_calls_for_module(
                spec=spec,
                context_obj=context_obj,
                depth=depth,
                max_calls=max_calls,
            )
            if calls:
                planner_mode = 'seed_fallback'
        uniq_calls = []
        for call in (calls or []):
            sig = _tool_call_signature(call)
            if sig in executed_signatures:
                continue
            executed_signatures.add(sig)
            uniq_calls.append(call)
            if len(uniq_calls) >= max_calls:
                break
        if plan_text:
            planning_raw.append(f"[{planner_mode}] " + _truncate_text_for_prompt(plan_text, 1800))
        else:
            planning_raw.append(f"[{planner_mode}]")
        if not uniq_calls:
            break
        for cidx, call in enumerate(uniq_calls[:max_calls], 1):
            if callable(progress_cb):
                call_name = str(call.get('name', 'tool') or 'tool')
                progress_cb(
                    f'补抓证据 {cidx}/{len(uniq_calls[:max_calls])}',
                    call_name,
                    min(74, 42 + ridx * 14 + cidx * 6),
                    'tool',
                    f'调用工具: {call_name}'
                )
            rec = _execute_mcp_tool_call(call, context_obj=context_obj, depth=depth)
            if rec.get('ok'):
                rec['result'] = _truncate_text_for_prompt(rec.get('result', ''), clip_len)
            evidence_rows.append(rec)
            if callable(progress_cb):
                progress_cb(
                    '证据已入账',
                    str(rec.get('name', '') or ''),
                    min(80, 48 + ridx * 14 + cidx * 6),
                    'tool_result',
                    '处理新拿到的证据'
                )
    final_user_prompt = _build_mcp_final_prompt(
        spec=spec,
        context_obj=context_obj,
        schema_hint=schema_hint,
        module_guide_text=module_guide_text,
        evidence_rows=evidence_rows,
    )
    if callable(progress_cb):
        progress_cb('把证据串成完整叙事', '正在生成结构化结果', 84, 'status', '把证据串成完整叙事')
    final_text, usage = _llm_complete_by_provider(cfg_effective, system_prompt, final_user_prompt, progress_cb=progress_cb)
    usage_total = _merge_usage_dict(usage_total, usage)
    meta = {
        'enabled': True,
        'tool_rounds': rounds,
        'tool_calls': len(evidence_rows),
        'planner': 'native+text+seed',
        'planning_errors': planning_errors[-8:],
        'evidence': [
            {
                'name': str(r.get('name', '') or ''),
                'ok': bool(r.get('ok', False)),
                'elapsed_ms': float(r.get('elapsed_ms', 0) or 0),
                'arguments': r.get('arguments', {}),
                'error': str(r.get('error', '') or ''),
            }
            for r in evidence_rows
            if isinstance(r, dict)
        ],
        'planning_preview': planning_raw[-4:],
    }
    return final_text, usage_total, meta


def _build_ai_module_context(full_data, depth='standard'):
    d = full_data if isinstance(full_data, dict) else {}
    ov = d.get('overview', {}) if isinstance(d.get('overview', {}), dict) else {}
    summary = ov.get('summary', {}) if isinstance(ov.get('summary', {}), dict) else {}
    trend = ov.get('trend', []) if isinstance(ov.get('trend', []), list) else []
    top_senders = ov.get('top_senders', []) if isinstance(ov.get('top_senders', []), list) else []
    link_sources = ov.get('link_sources', []) if isinstance(ov.get('link_sources', []), list) else []
    hot_links = ov.get('hot_links', []) if isinstance(ov.get('hot_links', []), list) else []
    members_page = d.get('members', {}) if isinstance(d.get('members', {}), dict) else {}
    members_table = members_page.get('members_table', []) if isinstance(members_page.get('members_table', []), list) else []
    insight = d.get('insight', {}) if isinstance(d.get('insight', {}), dict) else {}
    kws = insight.get('keywords', []) if isinstance(insight.get('keywords', []), list) else []
    activity = d.get('activity', {}) if isinstance(d.get('activity', {}), dict) else {}
    quality_model = activity.get('quality_model', {}) if isinstance(activity.get('quality_model', {}), dict) else {}
    activity_trend = activity.get('activity_trend', {}) if isinstance(activity.get('activity_trend', {}), dict) else {}
    recent_samples = ov.get('recent_samples', []) if isinstance(ov.get('recent_samples', []), list) else []

    depth_name = str(depth or 'standard').strip().lower()
    if depth_name not in ('quick', 'standard', 'deep'):
        depth_name = 'standard'
    if depth_name == 'quick':
        max_kw = 30
        max_member = 20
        max_trend = 20
        max_links = 12
        max_samples = 24
    elif depth_name == 'deep':
        max_kw = 80
        max_member = 60
        max_trend = 60
        max_links = 30
        max_samples = 72
    else:
        max_kw = 50
        max_member = 35
        max_trend = 40
        max_links = 20
        max_samples = 42

    ctx = {
        'chat': d.get('chat', ''),
        'username': d.get('username', ''),
        'range': d.get('range', {}),
        'summary': summary,
        'trend': trend[-max_trend:],
        'top_senders': top_senders[:max_member],
        'members': [
            {
                'rank': int(r.get('rank', 0) or 0),
                'name': r.get('sender', ''),
                'messages': int(r.get('messages', 0) or 0),
                'active_days': int(r.get('active_days', 0) or 0),
                'level': r.get('level', ''),
                'impact': int(r.get('impact_score', 0) or 0),
                'recent': r.get('recent_active_text', ''),
            }
            for r in members_table[:max_member]
            if isinstance(r, dict)
        ],
        'funnel': members_page.get('funnel', []),
        'level_logic': members_page.get('level_logic', {}),
        'keywords': kws[:max_kw],
        'link_sources': link_sources[:15],
        'hot_links': hot_links[:max_links],
        'message_samples': recent_samples[:max_samples],
        'quality_model': quality_model,
        'activity_kpis': activity.get('kpis', {}),
        'activity_trend': {
            'day': (activity_trend.get('day', []) if isinstance(activity_trend.get('day', []), list) else [])[-max_trend:],
            'week': (activity_trend.get('week', []) if isinstance(activity_trend.get('week', []), list) else [])[-20:],
            'month': (activity_trend.get('month', []) if isinstance(activity_trend.get('month', []), list) else [])[-12:],
        },
    }
    return ctx


def _module_spec(module_name):
    m = str(module_name or '').strip().lower()
    if m not in ('report', 'sentiment', 'topic', 'risk', 'persona', 'strategy'):
        m = 'report'
    specs = {
        'report': {
            'title': '智能洞察报告',
            'schema_hint': (
                '{"headline":"", "range_note":"", "story_title":"", "story_dek":"", '
                '"story_points":[""], "story_tags":[""], '
                '"story_questions":[{"title":"","reason":"","evidence":"","target_hint":"peak|topic|member|quality"}], '
                '"turning_points":[{"date":"","title":"","detail":"","evidence":"","topic":"","member":"","tone":"positive|neutral|warn|danger"}], '
                '"summary_markdown":"", '
                '"focus_metrics":[{"label":"","value":"","delta":"","tone":"positive|neutral|warn"}], '
                '"executive_points":[{"title":"","detail":"","evidence":""}], '
                '"member_watch":[{"name":"","role":"","signal":"","evidence":""}], '
                '"topic_watch":[{"topic":"","heat":0,"summary":"","evidence":""}], '
                '"anomalies":[{"title":"","detail":"","severity":"info|warn|high"}], '
                '"actions":[{"title":"","detail":"","priority":"高|中|低","owner":"","window":""}]}'
            )
        },
        'sentiment': {
            'title': '情绪氛围分析',
            'schema_hint': (
                '{"overall_score":0, "distribution":{"positive":0,"neutral":0,"negative":0}, '
                '"emotion_labels":[{"label":"","count":0}], "narrative":"", '
                '"trend":[{"date":"MM-DD","positive":0,"neutral":0,"negative":0}], '
                '"samples":[{"polarity":"积极|中性|消极","confidence":0,"time":"","text":""}], '
                '"positive_members":[{"sender":"","score":0,"time":"","quote":"","suggestion":""}], '
                '"negative_members":[{"sender":"","score":0,"time":"","quote":"","suggestion":""}], '
                '"representative_quotes":[{"sender":"","polarity":"","label":"","time":"","text":""}], '
                '"suggestions":[{"title":"","detail":""}]}'
            )
        },
        'topic': {
            'title': '话题脉络追踪',
            'schema_hint': (
                '{"summary_markdown":"", "topic_cards":[{"name":"","heat":0,"desc":"","stage":"","signal":""}], '
                '"timeline":[{"time":"","tag":"","event":"","evidence":""}], '
                '"stance_groups":[{"name":"","stance":"","members":[""],"summary":"","quote":""}], '
                '"topic_summary":[{"topic":"","summary":"","members":[""],"quote":""}], '
                '"next_topics":[{"topic":"","why_now":"","action":""}]}'
            )
        },
        'risk': {
            'title': '风险预警监测',
            'schema_hint': (
                '{"risk_level":"低|中|高", "summary_markdown":"", '
                '"metrics":{"violation":0,"emotion":0,"outlier":0,"external":0}, '
                '"risk_dimensions":[{"name":"","score":0,"detail":"","evidence":""}], '
                '"alerts":[{"level":"info|warn|high","title":"","time":"","action":"","evidence":""}], '
                '"watch_items":[{"name":"","reason":"","owner":"","window":""}], '
                '"mitigation_plan":[{"title":"","detail":"","priority":"高|中|低"}]}'
            )
        },
        'persona': {
            'title': '成员行为画像',
            'schema_hint': (
                '{"layers":[{"name":"KOL","count":0}], '
                '"cohort_summary":[{"name":"","count":0,"signal":"","action":""}], '
                '"top_members":[{"name":"","role":"","influence":0,"recent":"","focus":[""],"quote":"","mbti_guess":"","animal":"","archetype":"","vibe_tags":[""],"energy_style":""}], '
                '"member_cards":[{"name":"","level":"","influence":0,"recent":"","tags":[""],"quote":"","insight":"","next_step":"","fun_title":"","mbti_guess":"","mbti_reason":"","animal":"","animal_reason":"","social_style":"","vibe_tags":[""]}], '
                '"tags":[""], "operator_notes":[{"title":"","detail":""}]}'
            )
        },
        'strategy': {
            'title': '运营策略建议',
            'schema_hint': (
                '{"north_star":"", '
                '"priority_actions":[{"title":"","desc":"","priority":"高|中|低","buttons":[""],"evidence":""}], '
                '"content_dirs":[{"name":"","why":"","format":"","cadence":""}], '
                '"campaign_cards":[{"name":"","goal":"","hook":"","owner":"","window":""}], '
                '"metric_targets":[{"metric":"","target":"","reason":""}], '
                '"health_plan":"", "schedule_plan":[{"period":"","focus":"","deliverable":""}]}'
            )
        },
    }
    x = dict(specs[m])
    x['module'] = m
    return x


def _fallback_module_result(module_name, full_data):
    m = str(module_name or '').strip().lower()
    d = full_data if isinstance(full_data, dict) else {}
    ov = d.get('overview', {}) if isinstance(d.get('overview', {}), dict) else {}
    s = ov.get('summary', {}) if isinstance(ov.get('summary', {}), dict) else {}
    trend = ov.get('trend', []) if isinstance(ov.get('trend', []), list) else []
    samples = ov.get('recent_samples', []) if isinstance(ov.get('recent_samples', []), list) else []
    members = (d.get('members', {}) or {}).get('members_table', [])
    if not isinstance(members, list):
        members = []
    kws = (d.get('insight', {}) or {}).get('keywords', [])
    if not isinstance(kws, list):
        kws = []
    link_sources = ov.get('link_sources', []) if isinstance(ov.get('link_sources', []), list) else []

    sender_samples = defaultdict(list)
    for rec in samples:
        if not isinstance(rec, dict):
            continue
        sender = str(rec.get('sender', '') or '').strip() or '鎴愬憳'
        txt = str(rec.get('text', '') or '').strip()
        if not txt:
            continue
        sender_samples[sender].append(rec)

    def _pick_quote(sender=''):
        rows = sender_samples.get(sender, []) if sender else samples
        for rec in rows:
            if not isinstance(rec, dict):
                continue
            txt = str(rec.get('text', '') or '').strip()
            if not txt:
                continue
            if len(txt) > 120:
                txt = txt[:120] + "..."
            return txt
        return ''

    def _simple_sentiment_score(text):
        t = str(text or '').strip()
        if not t:
            return 0
        pos_words = (
            "好", "开心", "感谢", "厉害", "赞", "支持", "优秀", "稳", "棒", "喜欢",
            "值得", "收获", "进展", "解决", "期待", "感谢分享", "真棒", "太好了",
        )
        neg_words = (
            "难", "烦", "累", "崩", "错", "差", "焦虑", "失望", "生气", "卡住",
            "不行", "问题", "bug", "崩溃", "难受", "郁闷", "吐槽", "无语",
        )
        score = 0
        for w in pos_words:
            if w in t:
                score += 1
        for w in neg_words:
            if w in t:
                score -= 1
        return score

    if m == 'sentiment':
        sender_scores = defaultdict(list)
        day_scores = defaultdict(lambda: {'pos': 0, 'neu': 0, 'neg': 0})
        classified_samples = []
        label_counter = Counter()
        for rec in samples[:220]:
            if not isinstance(rec, dict):
                continue
            txt = str(rec.get('text', '') or '').strip()
            if not txt:
                continue
            sender = str(rec.get('sender', '') or '').strip() or '成员'
            score = _simple_sentiment_score(txt)
            if score > 0:
                pol = '积极'
                label = '认可/兴奋'
            elif score < 0:
                pol = '消极'
                label = '吐槽/问题反馈'
            else:
                pol = '中性'
                label = '信息交流'
            conf = min(98, 70 + abs(score) * 8)
            ts = int(rec.get('ts', 0) or 0)
            dkey = datetime.fromtimestamp(ts).strftime('%m-%d') if ts else str(rec.get('time', '') or '')[:5]
            if not dkey:
                dkey = '未知'
            if pol == '积极':
                day_scores[dkey]['pos'] += 1
            elif pol == '消极':
                day_scores[dkey]['neg'] += 1
            else:
                day_scores[dkey]['neu'] += 1
            sender_scores[sender].append(score)
            label_counter[label] += 1
            classified_samples.append({
                'sender': sender,
                'polarity': pol,
                'label': label,
                'confidence': conf,
                'time': str(rec.get('time', '') or ''),
                'text': txt,
                'score': score,
            })

        pos_n = len([x for x in classified_samples if x.get('polarity') == '积极'])
        neg_n = len([x for x in classified_samples if x.get('polarity') == '消极'])
        neu_n = len([x for x in classified_samples if x.get('polarity') == '中性'])
        total_n = max(1, pos_n + neg_n + neu_n)
        dist = {
            'positive': int(round(pos_n * 100.0 / total_n)),
            'neutral': int(round(neu_n * 100.0 / total_n)),
            'negative': int(round(neg_n * 100.0 / total_n)),
        }

        day_keys = sorted(day_scores.keys())[-30:]
        trows = []
        for dk in day_keys:
            row = day_scores.get(dk, {'pos': 0, 'neu': 0, 'neg': 0})
            day_total = max(1, int(row['pos'] + row['neu'] + row['neg']))
            trows.append({
                'date': dk,
                'positive': int(round(row['pos'] * 100.0 / day_total)),
                'neutral': int(round(row['neu'] * 100.0 / day_total)),
                'negative': int(round(row['neg'] * 100.0 / day_total)),
            })
        if not trows:
            for r in trend[-30:]:
                total = max(1, int((r or {}).get('total', 0) or 0))
                p = int(round(100.0 * (int((r or {}).get('text', 0) or 0) / total)))
                n = int(round(100.0 * (int((r or {}).get('link', 0) or 0) / total)))
                z = max(0, 100 - p - n)
                trows.append({
                    'date': str((r or {}).get('date', '') or '')[-5:],
                    'positive': p,
                    'neutral': z,
                    'negative': n,
                })

        sender_avg = []
        for sender, arr in sender_scores.items():
            if not arr:
                continue
            avg = sum(arr) / max(1, len(arr))
            sender_avg.append((sender, avg, len(arr)))
        sender_avg.sort(key=lambda x: (x[1], x[2]), reverse=True)
        pos_members = []
        neg_members = []
        for sender, avg, cnt in sender_avg:
            quote = _pick_quote(sender)
            item = {
                'sender': sender,
                'score': round(avg, 2),
                'time': '',
                'quote': quote,
                'suggestion': '继续保持正向输出，带动群内互动。' if avg > 0 else '建议关注其近期反馈，必要时进行点对点沟通。',
                'count': int(cnt),
            }
            if avg > 0 and len(pos_members) < 6:
                pos_members.append(item)
            if avg < 0 and len(neg_members) < 6:
                neg_members.append(item)
        overall = int(max(0, min(100, 50 + (dist['positive'] - dist['negative']) * 0.8)))
        return {
            'overall_score': overall,
            'distribution': dist,
            'emotion_labels': [{'label': k, 'count': int(v)} for k, v in label_counter.most_common(6)],
            'narrative': (
                f"当前时间范围内，群聊情绪以{'积极' if dist['positive'] >= dist['negative'] else '谨慎/偏负向'}为主，"
                f"积极占比 {dist['positive']}%，消极占比 {dist['negative']}%。"
            ),
            'trend': trows,
            'samples': [
                {
                    'polarity': x.get('polarity', '中性'),
                    'label': x.get('label', '信息交流'),
                    'confidence': x.get('confidence', 75),
                    'time': x.get('time', ''),
                    'text': x.get('text', ''),
                }
                for x in classified_samples[:12]
            ],
            'positive_members': pos_members,
            'negative_members': neg_members,
            'representative_quotes': [
                {
                    'sender': x.get('sender', '成员'),
                    'polarity': x.get('polarity', '中性'),
                    'label': x.get('label', '信息交流'),
                    'time': x.get('time', ''),
                    'text': x.get('text', ''),
                }
                for x in sorted(classified_samples, key=lambda y: abs(int(y.get('score', 0) or 0)), reverse=True)[:10]
            ],
            'suggestions': [
                {
                    'title': '情绪运营建议',
                    'detail': '优先回应消极情绪成员，同时给积极成员更多可见反馈，形成正向示范。',
                },
                {
                    'title': '话题安排建议',
                    'detail': '把高互动时段的话题从问题导向调整为案例和解决方案导向，降低负向扩散。',
                },
            ],
        }
    if m == 'topic':
        cards = []
        max_heat = max([int((it or {}).get('count', 0) or 0) for it in kws[:6] if isinstance(it, dict)] + [1])
        for it in kws[:6]:
            if not isinstance(it, dict):
                continue
            heat_val = int(it.get('count', 0) or 0)
            cards.append({
                'name': str(it.get('keyword', '') or ''),
                'heat': heat_val,
                'desc': '近期高热讨论主题',
                'stage': '爆发' if heat_val >= max_heat * 0.8 else ('升温' if heat_val >= max_heat * 0.45 else '常规'),
                'signal': '高频反复出现，值得作为内容策划切入口。',
            })
        timeline = []
        peak_days = sorted(trend[-20:], key=lambda x: int((x or {}).get('total', 0) or 0), reverse=True)[:8]
        for idx, r in enumerate(peak_days):
            topic_name = cards[idx % max(1, len(cards))]['name'] if cards else '社群讨论'
            timeline.append({
                'time': str((r or {}).get('date', '') or ''),
                'tag': topic_name,
                'event': f"消息峰值日：{int((r or {}).get('total', 0) or 0)} 条，围绕“{topic_name}”展开讨论。",
                'evidence': _pick_quote() or '暂无可展示原文',
            })
        topic_summary = []
        member_names = [str(x.get('sender', '') or '') for x in members[:8] if isinstance(x, dict) and str(x.get('sender', '') or '').strip()]
        for c in cards[:8]:
            topic_summary.append({
                'topic': c.get('name', ''),
                'summary': f"话题热度约 {int(c.get('heat', 0) or 0)}，建议继续跟进该方向的讨论深度。",
                'members': member_names[:3],
                'quote': _pick_quote() or '暂无可展示原文',
            })
        stance_groups = []
        for idx, c in enumerate(cards[:4], start=1):
            stance_groups.append({
                'name': c.get('name', ''),
                'stance': '讨论聚焦于经验、问题与方案交换',
                'members': member_names[idx - 1:idx + 2] or member_names[:3],
                'summary': f"围绕“{c.get('name', '')}”的讨论里，成员更关注实操价值和问题排查。",
                'quote': _pick_quote() or '暂无可展示原文',
            })
        next_topics = []
        for c in cards[:4]:
            next_topics.append({
                'topic': c.get('name', ''),
                'why_now': '已经具备持续热度，可扩展为专题串联内容。',
                'action': '补一条案例帖 + 一条复盘帖，承接已有讨论。',
            })
        summary_md = (
            f"## 话题概况\n"
            f"- 当前识别出 {len(cards)} 个高频主题。\n"
            f"- 高峰讨论通常集中在晚间时段，可安排重点话题发布。\n"
            f"- 建议把高热话题与经验复盘结合，提升沉淀质量。\n"
        )
        return {
            'summary_markdown': summary_md,
            'topic_cards': cards,
            'timeline': timeline,
            'stance_groups': stance_groups,
            'topic_summary': topic_summary,
            'next_topics': next_topics,
        }
    if m == 'risk':
        external = int(s.get('link_messages', 0) or 0)
        emotion = 0 if external < 80 else 2
        outlier = 0 if int(s.get('total_messages', 0) or 0) < 500 else 1
        risk_level = '低'
        if emotion + outlier >= 3:
            risk_level = '中'
        alerts = [
            {
                'level': 'info',
                'title': '建议保持外链审核',
                'time': datetime.now().strftime('%Y-%m-%d'),
                'action': '查看',
                'evidence': '当前窗口内仍有链接内容传播，需要保持基础审查。',
            }
        ]
        if external >= 20:
            alerts.append({
                'level': 'warn',
                'title': f'外链消息累计 {external} 条',
                'time': datetime.now().strftime('%Y-%m-%d'),
                'action': '检查链接来源与导流目的',
                'evidence': '外链占比抬升时，容易混入营销导流或非目标内容。',
            })
        alerts.append({
            'level': 'info' if outlier <= 0 else 'warn',
            'title': '关注异常峰值窗口',
            'time': datetime.now().strftime('%Y-%m-%d'),
            'action': '回看峰值日上下文样本',
            'evidence': '峰值日消息量与常规日差异较大时，需要结合上下文复核。',
        })
        return {
            'risk_level': risk_level,
            'summary_markdown': (
                f"## 风险判断\n"
                f"- 当前整体风险等级为 **{risk_level}**。\n"
                f"- 主要关注点在外链传播与异常情绪扩散。\n"
                f"- 建议保持值班复看和重点链接抽检。"
            ),
            'metrics': {
                'violation': 0,
                'emotion': emotion,
                'outlier': outlier,
                'external': external,
            },
            'risk_dimensions': [
                {'name': '外链传播', 'score': external, 'detail': '外链量越高，越需要关注导流和低质内容。', 'evidence': '查看 hot_links / link_sources'},
                {'name': '情绪波动', 'score': emotion, 'detail': '负向讨论上升时，容易引发集中吐槽。', 'evidence': _pick_quote() or '暂无可展示原文'},
                {'name': '异常活跃', 'score': outlier, 'detail': '峰值日需要结合主题内容判断是否异常。', 'evidence': '查看趋势峰值日样本'},
            ],
            'alerts': alerts,
            'watch_items': [
                {
                    'name': '重点外链',
                    'reason': '优先核查高频域名与重复转发内容。',
                    'owner': '运营值班',
                    'window': '今天',
                },
                {
                    'name': '负向反馈样本',
                    'reason': '关注持续吐槽或重复反馈的问题点。',
                    'owner': '群主 / 管理员',
                    'window': '24h',
                },
                {
                    'name': '峰值日上下文',
                    'reason': '确认活跃高峰是否伴随风险事件或集中导流。',
                    'owner': '运营值班',
                    'window': '本周',
                },
            ],
            'mitigation_plan': [
                {'title': '高频外链二次审核', 'detail': '把高频转发链接集中复核，必要时做白名单/黑名单。', 'priority': '高'},
                {'title': '负向问题单独回收', 'detail': '把集中吐槽的问题转成 FAQ 或公告，减少重复扩散。', 'priority': '中'},
                {'title': '建立峰值日复盘机制', 'detail': '每次异常高峰后补一份简短复盘，沉淀触发原因和处理动作。', 'priority': '中'},
            ],
        }
    if m == 'persona':
        def _persona_level_key(label):
            raw = str(label or '').strip()
            if raw.lower() == 'kol' or 'KOL' in raw:
                return 'kol'
            if '核心' in raw:
                return 'core'
            if '普通' in raw:
                return 'normal'
            return 'low'

        def _persona_mbti_guess(level_key, messages, active_days, influence, recent_hours):
            if level_key == 'kol' and messages >= 80 and active_days >= 10:
                return ('ENFJ', '高频开口且持续带动别人接话，更像外向型组织者。')
            if level_key == 'kol' and influence >= 72:
                return ('ENTJ', '更常给方向和判断，像会把讨论往目标上拧的人。')
            if influence >= 68 and messages <= 42:
                return ('INTJ', '不是一直说，但一开口通常就在关键位置定调。')
            if messages >= 90:
                return ('ENTP', '抛点子快、接梗也快，容易把话题带去新角度。')
            if active_days >= 12:
                return ('ISFJ', '活跃天数稳定，更多是在补位和维持节奏。')
            if recent_hours <= 24 and messages >= 36:
                return ('ESFP', '现场感很强，热起来时会主动把气氛推高。')
            if influence >= 42:
                return ('INFJ', '话不一定最多，但经常在关键处给出有判断力的回应。')
            return ('ISTP', '更像先观察再出手，表达直接，不会一直占麦。')

        def _persona_animal(level_key, messages, active_days, influence, recent_hours):
            if level_key == 'kol' and active_days >= 10:
                return ('边牧', '会主动赶着话题往前跑，也能把场子拢起来。')
            if influence >= 68 and messages <= 42:
                return ('猫头鹰', '平时不吵，但关键时刻会给出判断和方向。')
            if active_days >= 12:
                return ('海狸', '经常默默补位，把讨论结构一点点搭好。')
            if messages >= 80 or recent_hours <= 24:
                return ('蜜蜂', '来回接球很快，现场热度主要靠他维持。')
            if level_key == 'normal':
                return ('松鼠', '擅长搬运线索和碎片信息，把讨论补得更完整。')
            return ('猫咪', '平时低调观察，但偶尔一爪子就能拍到重点。')

        def _persona_social_style(level_key, messages, active_days, influence):
            if level_key == 'kol':
                return '点火 + 定调型'
            if active_days >= 12:
                return '补位 + 收束型'
            if messages >= 80:
                return '抛球 + 接球型'
            if influence >= 52:
                return '关键判断型'
            return '观察后插话型'

        def _persona_fun_title(animal_name):
            mapping = {
                '边牧': '把场子往前赶的人',
                '猫头鹰': '关键时刻定方向的人',
                '海狸': '默默把结构搭起来的人',
                '蜜蜂': '现场接球最快的人',
                '松鼠': '会捡线索补细节的人',
                '猫咪': '平时安静，开口就有点子的人',
            }
            return mapping.get(str(animal_name or '').strip(), '值得单独观察的人')

        def _persona_vibe_tags(level_key, messages, active_days, influence, recent_hours, focus_tags):
            tags = []
            if messages >= 80:
                tags.append('高频开麦')
            if active_days >= 10:
                tags.append('稳定在线')
            if influence >= 68:
                tags.append('能定调')
            if recent_hours <= 24:
                tags.append('最近很热')
            if level_key == 'kol':
                tags.append('带动讨论')
            elif level_key == 'core':
                tags.append('稳定接力')
            elif level_key == 'normal':
                tags.append('补细节')
            else:
                tags.append('潜伏观察')
            for item in (focus_tags or [])[:2]:
                txt = str(item or '').strip()
                if txt:
                    tags.append(txt)
            out = []
            for item in tags:
                if item not in out:
                    out.append(item)
            return out[:5]

        def _persona_next_step(level_key):
            if level_key == 'kol':
                return '给他一个主题主持位、首发位或案例共创任务。'
            if level_key == 'core':
                return '让他负责接话、补充案例或做阶段性复盘。'
            if level_key == 'normal':
                return '给一个低门槛的接龙、投票或案例补充任务。'
            return '先用轻互动试水，找到他愿意开口的触发点。'

        top = []
        for r in members[:12]:
            if not isinstance(r, dict):
                continue
            sender_name = str(r.get('sender', '') or '')
            quote = _pick_quote(sender_name)
            role_label = str(r.get('level', '') or '')
            level_key = _persona_level_key(role_label)
            influence = int(r.get('impact_score', 0) or 0)
            messages = int(r.get('month_messages', r.get('messages', 0)) or 0)
            active_days = int(r.get('active_days', 0) or 0)
            recent_hours = int(r.get('recent_active_hours', 0) or 0)
            focus_tags = [str(x.get('keyword', '') or '') for x in kws[:3] if isinstance(x, dict) and str(x.get('keyword', '') or '').strip()]
            mbti_guess, _ = _persona_mbti_guess(level_key, messages, active_days, influence, recent_hours)
            animal_name, _ = _persona_animal(level_key, messages, active_days, influence, recent_hours)
            top.append({
                'name': sender_name,
                'role': role_label,
                'influence': influence,
                'recent': r.get('recent_active_text', ''),
                'focus': focus_tags,
                'quote': quote,
                'mbti_guess': mbti_guess,
                'animal': animal_name,
                'archetype': _persona_fun_title(animal_name),
                'vibe_tags': _persona_vibe_tags(level_key, messages, active_days, influence, recent_hours, focus_tags),
                'energy_style': _persona_social_style(level_key, messages, active_days, influence),
            })
        funnel = (d.get('members', {}) or {}).get('funnel', [])
        layers = [{'name': str(x.get('name', '') or ''), 'count': int(x.get('count', 0) or 0)} for x in funnel if isinstance(x, dict)]
        tags = [str(x.get('keyword', '') or '') for x in kws[:24] if isinstance(x, dict)]
        cohort_summary = []
        for row in layers[:4]:
            cohort_summary.append({
                'name': row.get('name', ''),
                'count': int(row.get('count', 0) or 0),
                'signal': f"{row.get('name', '')} 人群具备明显互动特征，可单独设计触达策略。",
                'action': '设计对应的互动任务与内容节奏。',
            })
        member_cards = []
        for i, row in enumerate(top[:12], start=1):
            role = str(row.get('role', '') or '')
            level_key = _persona_level_key(role)
            if level_key == 'kol':
                label = '社群带动者'
            elif level_key == 'core':
                label = '稳定贡献者'
            elif level_key == 'normal':
                label = '互动参与者'
            else:
                label = '潜力成员'
            influence = int(row.get('influence', 0) or 0)
            mbti_guess, mbti_reason = _persona_mbti_guess(level_key, influence, i + 2, influence, 24)
            animal_name = str(row.get('animal', '') or '')
            _, animal_reason = _persona_animal(level_key, influence, i + 2, influence, 24)
            member_cards.append({
                'name': row.get('name', ''),
                'level': role,
                'influence': influence,
                'recent': row.get('recent', ''),
                'tags': row.get('focus', []),
                'quote': row.get('quote', ''),
                'insight': f"{animal_name or '这位成员'}型的{label}，更像{row.get('energy_style', '某个关键位置的补位者')}，当前排名第 {i}。",
                'next_step': _persona_next_step(level_key),
                'fun_title': _persona_fun_title(animal_name),
                'mbti_guess': str(row.get('mbti_guess', '') or mbti_guess),
                'mbti_reason': mbti_reason,
                'animal': animal_name,
                'animal_reason': animal_reason,
                'social_style': str(row.get('energy_style', '') or ''),
                'vibe_tags': row.get('vibe_tags', []),
            })
        return {
            'layers': layers,
            'cohort_summary': cohort_summary,
            'top_members': top,
            'member_cards': member_cards,
            'tags': tags,
            'operator_notes': [
                {'title': '核心成员要给舞台', 'detail': '对高影响力成员，优先安排展示位、案例位和共创任务。'},
                {'title': '潜力成员要给轻任务', 'detail': '给低门槛参与动作，避免只看不说。'},
                {'title': '稳定成员要给反馈闭环', 'detail': '让稳定参与者知道自己被看见，避免中段成员逐步沉默。'},
            ],
        }
    if m == 'strategy':
        return {
            'north_star': '提升稳定活跃人数，并让高热讨论沉淀为可复用内容资产。',
            'priority_actions': [
                {'title': '激活沉默成员', 'desc': '针对近期低活跃成员设置互动话题和提醒机制。', 'priority': '高', 'buttons': ['一键生成话题', '设置提醒'], 'evidence': '成员分层里尾部成员较多。'},
                {'title': '聚焦高互动主题', 'desc': '围绕近期高频关键词安排内容节奏，提升互动深度。', 'priority': '高', 'buttons': ['查看主题', '生成周计划'], 'evidence': '近期高频关键词已形成稳定讨论。'},
                {'title': '建立周复盘节奏', 'desc': '把高热讨论固定沉淀成周复盘，减少高价值信息流失。', 'priority': '中', 'buttons': ['生成复盘模板'], 'evidence': '当前高热内容有讨论热度，但沉淀动作不足。'},
            ],
            'content_dirs': [
                {
                    'name': str(x.get('keyword', '') or ''),
                    'why': '已有自然讨论热度，适合继续深挖。',
                    'format': '案例拆解 / 经验帖',
                    'cadence': '每周 1-2 次',
                }
                for x in kws[:5] if isinstance(x, dict)
            ],
            'campaign_cards': [
                {'name': '一周复盘贴', 'goal': '沉淀高热讨论', 'hook': '把本周最热问题做一次统一回答', 'owner': '运营', 'window': '本周'},
                {'name': '成员案例征集', 'goal': '放大核心成员内容供给', 'hook': '邀请高活跃成员提交案例和经验', 'owner': '群主', 'window': '7 天'},
                {'name': '新人欢迎任务', 'goal': '提升新成员首周开口率', 'hook': '给新人一个低门槛的首次互动动作', 'owner': '管理员', 'window': '持续执行'},
            ],
            'metric_targets': [
                {'metric': '稳定活跃人数', 'target': '+10%~20%', 'reason': '优先看人而不是只看消息量。'},
                {'metric': '高质量内容占比', 'target': '每周至少 3 条', 'reason': '形成可沉淀的社群资产。'},
                {'metric': '重点主题复盘频次', 'target': '每周 1 次', 'reason': '减少高热讨论流失。'},
                {'metric': '新人首周开口率', 'target': '提升到 35%+', 'reason': '补足群聊中段成员供给。'},
            ],
            'health_plan': '建议每周至少安排一次主题讨论日，并跟踪核心成员带动情况。',
            'schedule_plan': [
                {'period': '周一', 'focus': '抛出问题与收集需求', 'deliverable': '提问帖'},
                {'period': '周三', 'focus': '放大案例和成员经验', 'deliverable': '案例帖 / 语音分享'},
                {'period': '周五', 'focus': '统一收尾并沉淀结论', 'deliverable': '周复盘'},
                {'period': '周日', 'focus': '检查成员活跃与反馈闭环', 'deliverable': '简版运营看板'},
            ],
        }
    # report fallback
    top_sender = ''
    if isinstance(members, list) and members:
        first = members[0] if isinstance(members[0], dict) else {}
        top_sender = str(first.get('sender', '') or '')
    top_topic = ''
    if isinstance(kws, list) and kws:
        first_kw = kws[0] if isinstance(kws[0], dict) else {}
        top_topic = str(first_kw.get('keyword', '') or '')
    summary_md = (
        f"## 核心结论\n"
        f"- 当前范围消息数：{int(s.get('total_messages', 0) or 0)}\n"
        f"- 活跃成员数：{int(s.get('active_senders', 0) or 0)}\n"
        f"- 核心发言成员：{top_sender or '暂无'}\n\n"
        f"## 关键建议\n"
        f"- 围绕高热话题安排每周固定内容节奏。\n"
        f"- 针对低活跃成员设置轻量互动机制，提升留存。\n"
    )
    return {
        'headline': f"{d.get('chat', '')} 智能洞察报告",
        'range_note': f"{str((d.get('range', {}) or {}).get('label', '') or '').strip()}",
        'story_title': f"{top_topic or '这段时间的讨论主线'}是谁点燃、谁在接力",
        'story_dek': (
            f"当前窗口里，{top_topic or '高热话题'}是最稳定的讨论锚点，"
            f"{top_sender or '核心成员'}是明显的推进者之一；建议先看转折点，再看主线和关键人物。"
        ),
        'story_points': [
            f"这段时间里最稳定的主线仍是“{top_topic or '当前高热主题'}”，它决定了群聊的大部分注意力流向。",
            f"{top_sender or '头部成员'}持续站在前排推进讨论，说明这不是随机噪声，而是有人在持续接力。",
            f"如果要读懂这段群聊，先抓消息峰值日，再对照该日出现的代表话题和发言样本。"
        ],
        'story_tags': [x for x in [top_topic, top_sender, '转折点', '话题主线'] if str(x or '').strip()],
        'story_questions': [
            {
                'title': f"为什么“{top_topic or '这条主线'}”会成为这段时间的中心？",
                'reason': '需要对照峰值日的上下文和高质量发言样本，确认是需求爆发、资料传播还是关键成员带动。',
                'evidence': _pick_quote() or '建议回看高峰日消息上下文。',
                'target_hint': 'topic',
            },
            {
                'title': f"{top_sender or '核心成员'}到底是在发起、接力，还是放大讨论？",
                'reason': '要结合其代表发言和互动关系判断其真正作用，而不是只看消息条数。',
                'evidence': _pick_quote(top_sender) or '建议查看该成员的代表发言。',
                'target_hint': 'member',
            },
            {
                'title': '哪一天是这段讨论真正拐过去的节点？',
                'reason': '峰值日通常能暴露最强触发器，也能解释后续为什么会升温或转向。',
                'evidence': '建议先对照趋势峰值日，再补看原始消息样本。',
                'target_hint': 'peak',
            },
        ],
        'turning_points': [
            {
                'date': '',
                'title': '先抓住峰值日',
                'detail': '高峰窗口最容易看见真正的触发器、关键人物和高质量线索。',
                'evidence': _pick_quote() or '建议回看峰值日消息。',
                'topic': top_topic,
                'member': top_sender,
                'tone': 'warn',
            },
            {
                'date': '',
                'title': '再看主线有没有延续',
                'detail': f'如果“{top_topic or "高热主题"}”在高峰后仍持续出现，说明这不是一次性噪声，而是稳定主线。',
                'evidence': '可结合关键词热度与后续讨论样本继续核对。',
                'topic': top_topic,
                'member': top_sender,
                'tone': 'positive',
            },
        ],
        'summary_markdown': summary_md,
        'focus_metrics': [
            {'label': '消息总量', 'value': int(s.get('total_messages', 0) or 0), 'delta': '', 'tone': 'neutral'},
            {'label': '活跃成员', 'value': int(s.get('active_senders', 0) or 0), 'delta': '', 'tone': 'positive'},
            {'label': '媒体消息', 'value': int(s.get('media_messages', 0) or 0), 'delta': '', 'tone': 'neutral'},
            {'label': '链接消息', 'value': int(s.get('link_messages', 0) or 0), 'delta': '', 'tone': 'warn' if int(s.get('link_messages', 0) or 0) > 20 else 'neutral'},
        ],
        'executive_points': [
            {
                'title': '社群主轴判断',
                'detail': f"当前讨论主轴仍由 {top_sender or '核心成员'} 等高活跃成员带动，建议继续围绕高热主题做内容承接。",
                'evidence': _pick_quote(top_sender) or '暂无可展示原文',
            },
            {
                'title': '运营抓手',
                'detail': '优先关注高热主题沉淀和中低活跃成员激活，两条线并行推进。',
                'evidence': '成员分层与关键词热度均支持该判断。',
            },
            {
                'title': '风险提示',
                'detail': '外链和媒体内容需要跟随消息高峰做抽检，避免热点期间质量下滑。',
                'evidence': '趋势、链接与媒体分布可以直接支撑该判断。',
            },
        ],
        'member_watch': [
            {
                'name': str((row or {}).get('sender', '') or ''),
                'role': str((row or {}).get('level', '') or ''),
                'signal': f"近期开口 {int((row or {}).get('messages', 0) or 0)} 条。",
                'evidence': _pick_quote(str((row or {}).get('sender', '') or '')) or '暂无可展示原文',
            }
            for row in members[:4] if isinstance(row, dict)
        ],
        'topic_watch': [
            {
                'topic': str((kw or {}).get('keyword', '') or ''),
                'heat': int((kw or {}).get('count', 0) or 0),
                'summary': '该主题具备继续深挖的讨论基础。',
                'evidence': _pick_quote() or '暂无可展示原文',
            }
            for kw in kws[:4] if isinstance(kw, dict)
        ],
        'highlights': [
            {
                'title': '活跃峰值观察',
                'detail': f"当前时间范围内累计消息 {int(s.get('total_messages', 0) or 0)} 条，活跃成员 {int(s.get('active_senders', 0) or 0)} 人。"
            },
            {
                'title': '内容结构观察',
                'detail': f"媒体消息 {int(s.get('media_messages', 0) or 0)} 条，链接消息 {int(s.get('link_messages', 0) or 0)} 条，可据此调整内容节奏。"
            }
        ],
        'anomalies': [
            {
                'title': '关注峰值日消息结构',
                'detail': '建议回看高峰日消息上下文，确认是否存在异常扩散或突发需求。',
                'severity': 'warn',
            }
        ],
        'actions': [
            {
                'title': '围绕高热主题做周节奏',
                'detail': '把本周 Top 话题拆成提问帖、案例帖和总结帖三段式，提升讨论沉淀深度。',
                'priority': '高',
                'owner': '运营',
                'window': '本周',
            },
            {
                'title': '给中段成员安排轻互动',
                'detail': '设置低门槛投票、接龙或提问动作，提升稳定活跃人数。',
                'priority': '中',
                'owner': '管理员',
                'window': '7 天',
            },
            {
                'title': '建立主题复盘卡',
                'detail': '对高热主题固定输出复盘卡片，减少讨论价值流失。',
                'priority': '中',
                'owner': '群主 / 运营',
                'window': '每周',
            },
        ],
    }


def _is_empty_ai_value(v):
    if v is None:
        return True
    if isinstance(v, str):
        return not v.strip()
    if isinstance(v, (list, tuple, set, dict)):
        return len(v) == 0
    return False


def _merge_ai_result_dict(primary, fallback):
    out = dict(primary if isinstance(primary, dict) else {})
    fb = fallback if isinstance(fallback, dict) else {}
    for k, fv in fb.items():
        if k not in out or _is_empty_ai_value(out.get(k)):
            out[k] = fv
            continue
        pv = out.get(k)
        if isinstance(pv, dict) and isinstance(fv, dict):
            out[k] = _merge_ai_result_dict(pv, fv)
    return out


def _normalize_ai_module_result(module_name, parsed_data, fallback_data):
    m = str(module_name or '').strip().lower()
    p = parsed_data if isinstance(parsed_data, dict) else {}
    f = fallback_data if isinstance(fallback_data, dict) else {}
    out = _merge_ai_result_dict(p, f)

    def _ensure_list(key, min_len=1):
        arr = out.get(key, [])
        fb_arr = f.get(key, [])
        if not isinstance(arr, list):
            arr = []
        if not isinstance(fb_arr, list):
            fb_arr = []
        if len(arr) < int(min_len):
            merged = list(arr)
            for x in fb_arr:
                if len(merged) >= max(int(min_len), len(fb_arr)):
                    break
                merged.append(x)
            arr = merged
        out[key] = arr

    if m == 'report':
        _ensure_list('story_points', 3)
        _ensure_list('story_tags', 3)
        _ensure_list('story_questions', 3)
        _ensure_list('turning_points', 2)
        _ensure_list('focus_metrics', 4)
        _ensure_list('executive_points', 3)
        _ensure_list('member_watch', 4)
        _ensure_list('topic_watch', 4)
        _ensure_list('highlights', 2)
        _ensure_list('anomalies', 1)
        _ensure_list('actions', 3)
        if _is_empty_ai_value(out.get('summary_markdown')):
            out['summary_markdown'] = f.get('summary_markdown', '')
        if _is_empty_ai_value(out.get('headline')):
            out['headline'] = f.get('headline', '')
        if _is_empty_ai_value(out.get('story_title')):
            out['story_title'] = f.get('story_title', '')
        if _is_empty_ai_value(out.get('story_dek')):
            out['story_dek'] = f.get('story_dek', '')
        return out

    if m == 'sentiment':
        if not isinstance(out.get('distribution', {}), dict):
            out['distribution'] = f.get('distribution', {})
        _ensure_list('emotion_labels', 3)
        _ensure_list('trend', 8)
        _ensure_list('samples', 4)
        _ensure_list('positive_members', 2)
        _ensure_list('negative_members', 2)
        _ensure_list('representative_quotes', 4)
        _ensure_list('suggestions', 2)
        if _is_empty_ai_value(out.get('overall_score')):
            out['overall_score'] = f.get('overall_score', 0)
        if _is_empty_ai_value(out.get('narrative')):
            out['narrative'] = f.get('narrative', '')
        return out

    if m == 'topic':
        if _is_empty_ai_value(out.get('summary_markdown')):
            out['summary_markdown'] = f.get('summary_markdown', '')
        _ensure_list('topic_cards', 4)
        _ensure_list('timeline', 4)
        _ensure_list('stance_groups', 2)
        _ensure_list('topic_summary', 3)
        _ensure_list('next_topics', 2)
        return out

    if m == 'risk':
        if not isinstance(out.get('metrics', {}), dict):
            out['metrics'] = f.get('metrics', {})
        _ensure_list('risk_dimensions', 3)
        _ensure_list('alerts', 3)
        _ensure_list('watch_items', 3)
        _ensure_list('mitigation_plan', 3)
        if _is_empty_ai_value(out.get('risk_level')):
            out['risk_level'] = f.get('risk_level', '低')
        if _is_empty_ai_value(out.get('summary_markdown')):
            out['summary_markdown'] = f.get('summary_markdown', '')
        return out

    if m == 'persona':
        _ensure_list('layers', 3)
        _ensure_list('cohort_summary', 3)
        _ensure_list('top_members', 8)
        _ensure_list('member_cards', 8)
        _ensure_list('tags', 12)
        _ensure_list('operator_notes', 3)
        return out

    if m == 'strategy':
        if _is_empty_ai_value(out.get('north_star')):
            out['north_star'] = f.get('north_star', '')
        _ensure_list('priority_actions', 3)
        _ensure_list('content_dirs', 4)
        _ensure_list('campaign_cards', 3)
        _ensure_list('metric_targets', 4)
        _ensure_list('schedule_plan', 4)
        if _is_empty_ai_value(out.get('health_plan')):
            out['health_plan'] = f.get('health_plan', '')
        return out

    return out


def _run_ai_module_analysis(username, start_ts, end_ts, module_name, depth='standard', force=False, use_mcp=False, cfg_override=None, progress_cb=None):
    username = str(username or '').strip()
    if not username:
        raise RuntimeError("missing username")
    spec = _module_spec(module_name)
    cfg_effective = _resolve_ai_provider_config_for_surface('insight', cfg_override)
    provider = _normalize_provider_name(cfg_effective.get('provider', 'openai_compat'))
    model_name = str(cfg_effective.get('model', '') or '').strip()
    use_mcp = bool(use_mcp)

    def emit(title, detail='', pct=None, kind='status', status_text=None):
        if callable(progress_cb):
            progress_cb(title, detail, pct, kind, status_text)

    emit('检查模型配置', _ai_provider_label(provider), 8)

    if provider != 'claude_cli':
        if not str(cfg_effective.get('base_url', '') or '').strip():
            raise RuntimeError("请先配置 Base URL")
        if not str(cfg_effective.get('api_key', '') or '').strip():
            raise RuntimeError("请先配置 API Key")
        if not model_name:
            raise RuntimeError("请先配置模型")

    cache_key = (
        f"aimod:{provider}:{model_name}:{spec['module']}:{username}:"
        f"{int(start_ts or 0)}:{int(end_ts or 0)}:{str(depth or 'standard')}:mcp={1 if use_mcp else 0}"
    )
    if not force:
        cached = _ai_module_cache_get(cache_key)
        if cached:
            emit('命中分析缓存', spec.get('title', spec.get('module')), 100, 'result', '命中分析缓存')
            return dict(cached)

    emit('读取群聊底稿', spec.get('title', spec.get('module')), 18)
    full_data = _build_analysis_full(username=username, start_ts=start_ts, end_ts=end_ts, link_limit=12000)
    emit('梳理人物、话题和时间线', str(depth or 'standard'), 30)
    context_obj = _build_ai_module_context(full_data, depth=depth)
    schema_hint = spec.get('schema_hint', '{}')

    system_prompt = (
        "你是资深社群数据分析助手，专门为微信社群输出高密度、强证据、可执行的结构化分析报告。"
        "你只能基于给定结构化数据和 MCP 证据输出，禁止编造不存在的事实。"
        "输出必须是单个 JSON 对象，不能输出 markdown 代码块。"
        "结论必须兼顾：1) 核心判断；2) 代表证据；3) 成员/主题/风险分层；4) 可执行动作。"
        "语气要求专业但有人味，像真正读过聊天记录的人在写复盘，不要冷冰冰罗列数据，也不要文学化夸张。"
    )
    module_guide = {
        'report': (
            "这是总报告模板，但不是冷冰冰的统计表。必须按『封面叙事 / 核心判断 / 管理层结论 / 优先动作 / 关注成员 / 关注话题 / 趋势 / 异常』来组织。"
            "必须给出 headline、range_note、story_title、story_dek、story_points、story_tags、story_questions、turning_points、summary_markdown、focus_metrics、executive_points、member_watch、topic_watch、anomalies、actions。"
            "story_title 要像封面标题，直接点明最关键的变化；story_dek 用 1-2 句话交代时间、主线话题和关键人物；story_points 写 3-5 条具体剧情线，尽量包含日期、人物、话题、结果。"
            "turning_points 至少 2 条，必须带 date、detail、evidence；story_questions 至少 3 条，必须是下一步值得继续追问的具体问题。summary_markdown 先给判断再给证据，但不要写套话。"
        ),
        'sentiment': (
            "这是情绪分析模板，必须按『评分 / 分布 / 曲线 / 标签 / 正向成员 / 待关注成员 / 代表语料 / 运营动作』输出。"
            "必须给出 overall_score、distribution、emotion_labels、narrative、trend、positive_members、negative_members、representative_quotes、suggestions。"
            "positive_members / negative_members 都要带 quote 与 suggestion，quote 必须优先来自 message_samples 或 MCP 原文证据。"
        ),
        'topic': (
            "这是话题脉络模板，必须按『话题热度 / 话题卡 / 观点分组 / 演化时间线 / 主题结论 / 后续选题』输出。"
            "必须给出 topic_cards、timeline、stance_groups、topic_summary、next_topics。"
            "timeline 至少 4 条，并带 evidence；topic_summary 需包含 members 与 quote。不要只写“高热主题”，要写清楚主题是怎么被点燃、转向、沉淀的。"
        ),
        'risk': (
            "这是风险预警模板，必须按『风险等级 / 风险维度 / 预警卡 / 观察清单 / 缓解动作』输出。"
            "必须给出 risk_level、summary_markdown、metrics、risk_dimensions、alerts、watch_items、mitigation_plan。"
            "alerts 至少 3 条，含 level、title、time、action、evidence；mitigation_plan 至少 3 条。"
        ),
        'persona': (
            "这是成员画像模板，必须按『成员分层 / 影响力 / 分层说明 / 运营备注 / 成员画像卡 / 成员表』输出，而不是简单排行榜。"
            "必须给出 layers、cohort_summary、top_members、member_cards、tags、operator_notes。member_cards 至少 6 条。"
            "每张成员卡都要包含代表发言 quote、insight、next_step、mbti_guess、animal、vibe_tags、social_style。"
            "MBTI 和动物只能写成基于行为的轻量猜测，必须给出 mbti_reason / animal_reason，不能写成确定事实。"
            "insight 不能只是排名描述，要解释这个人为什么重要、在什么场景下冒头。"
        ),
        'strategy': (
            "这是运营策略模板，必须按『北极星 / 优先动作 / 内容方向 / 活动卡 / 指标目标 / 执行节奏 / 健康方案』输出。"
            "必须给出 north_star、priority_actions、content_dirs、campaign_cards、metric_targets、health_plan、schedule_plan。"
            "建议要可执行，且与当前时间范围的数据证据一致。priority_actions 至少 3 条，campaign_cards 至少 3 条。"
        ),
    }
    module_guide_text = module_guide.get(spec.get('module'), '')
    user_prompt = (
        f"Task module: {spec.get('title', spec.get('module'))}\\n"
        f"Generate a reusable, report-grade structured analysis from the following data.\\n"
        f"Output JSON schema reference: {schema_hint}\\n"
        "Template quality bar: the output should be dense enough to power a polished dashboard/report page, not a lightweight note.\\n"
        "Output rule: fill every important field with concrete content when evidence exists.\\n"
        "Evidence rule: every major conclusion should be traceable to message_samples or MCP evidence.\\n"
        "Narrative rule: summarize patterns, not just counts. Reconstruct what happened, what triggered it, who pushed it, and what remains.\\n"
        "Specificity rule: prefer exact dates, member names, topic names, file/link names, and trigger events over generic wording.\\n"
        "Humanity rule: write like an experienced editor-analyst who actually read the chat, not like a KPI console.\\n"
        "Action rule: recommendations must be immediately executable by community ops.\\n"
        f"Range rule: all conclusions must stay within the selected time range.\\n"
        f"Module guide: {module_guide_text}\\n"
        f"Data JSON:\\n{json.dumps(context_obj, ensure_ascii=False)}"
    )

    mcp_meta = {
        'enabled': bool(use_mcp),
        'tool_calls': 0,
        'error': '',
    }

    if use_mcp:
        try:
            emit('补抓原始证据', spec.get('title', spec.get('module')), 34)
            text, usage, mcp_meta_ext = _llm_complete_module_with_mcp(
                cfg_effective=cfg_effective,
                spec=spec,
                context_obj=context_obj,
                schema_hint=schema_hint,
                module_guide_text=module_guide_text,
                depth=depth,
                progress_cb=emit,
            )
            if isinstance(mcp_meta_ext, dict):
                mcp_meta.update(mcp_meta_ext)
        except Exception as e:
            mcp_meta['error'] = str(e)
            emit('补证据失败，回退直连模型', str(e), 58, 'error', '补证据失败，回退直连模型')
            text, usage = _llm_complete_by_provider(cfg_effective, system_prompt, user_prompt, progress_cb=emit)
    else:
        emit('交给模型组织叙事', spec.get('title', spec.get('module')), 52)
        text, usage = _llm_complete_by_provider(cfg_effective, system_prompt, user_prompt, progress_cb=emit)

    emit('把分析写成结构化结果', '', 88)
    parsed = _try_parse_json_obj(text)
    fb = _fallback_module_result(spec.get('module'), full_data)
    emit('校正字段并补齐证据槽位', '', 94)
    parsed = _normalize_ai_module_result(spec.get('module'), parsed if isinstance(parsed, dict) else {}, fb)

    result = {
        'module': spec.get('module'),
        'module_title': spec.get('title', spec.get('module')),
        'generated_at': int(time.time()),
        'provider': provider,
        'provider_label': _ai_provider_label(provider),
        'model': model_name,
        'depth': str(depth or 'standard'),
        'mcp': mcp_meta,
        'data': parsed,
        'context': {
            'username': username,
            'chat': full_data.get('chat', username),
            'start_ts': int(start_ts or 0),
            'end_ts': int(end_ts or 0),
            'analysis_version': str(full_data.get('analysis_version', '') or ''),
        },
        'usage': usage if isinstance(usage, dict) else {},
    }
    _ai_module_cache_set(cache_key, result)
    emit('分析完成', spec.get('title', spec.get('module')), 100, 'done', '分析完成')
    return result


def _start_ai_task(session_obj, question, context_obj, image_files=None):
    task_id = str(uuid.uuid4())
    with ai_tasks_lock:
        ai_tasks[task_id] = _create_ai_task_record(
            task_id=task_id,
            session_id=session_obj.get('id'),
            task_type='chat',
            question=question,
        )
    _prune_ai_tasks()

    t = threading.Thread(
        target=_run_ai_task_worker,
        args=(task_id, session_obj.get('id'), question, context_obj, image_files or []),
        daemon=True
    )
    t.start()
    return task_id


def _run_ai_module_task_worker(task_id, username, start_ts, end_ts, module_name, depth, force, use_mcp, cfg_override):
    spec = _module_spec(module_name)
    module_title = spec.get('title', module_name)
    t0 = time.perf_counter()

    def emit(title, detail='', pct=None, kind='status', status_text=None):
        payload = {
            'status_text': str(status_text or title or ''),
        }
        if pct is not None:
            try:
                payload['progress_pct'] = max(0, min(100, int(round(float(pct)))))
            except Exception:
                pass
        _set_ai_task(task_id, **payload)
        _append_ai_task_event(task_id, kind, str(title or ''), str(detail or ''))

    try:
        _set_ai_task(
            task_id,
            status='running',
            status_text=f'已启动 {module_title}',
            progress_pct=3,
            run_started_ms=int(time.time() * 1000),
        )
        emit(f'{module_title} 已启动', f'范围用户：{username}', pct=5)
        result = _run_ai_module_analysis(
            username=username,
            start_ts=start_ts,
            end_ts=end_ts,
            module_name=module_name,
            depth=depth,
            force=force,
            use_mcp=use_mcp,
            cfg_override=cfg_override,
            progress_cb=emit,
        )
        result = dict(result if isinstance(result, dict) else {})
        result['elapsed_ms'] = round((time.perf_counter() - t0) * 1000, 1)
        _set_ai_task(
            task_id,
            status='done',
            status_text='已完成',
            progress_pct=100,
            result=result,
        )
        _append_ai_task_event(task_id, 'done', '分析完成', module_title)
    except Exception as e:
        err_text = str(e)
        _append_ai_task_event(task_id, 'error', '执行失败', err_text)
        _set_ai_task(
            task_id,
            status='error',
            status_text='执行失败',
            progress_pct=100,
            error=err_text,
        )
    finally:
        _pop_ai_task_proc(task_id)


def _start_ai_module_task(username, start_ts, end_ts, module_name, depth='standard', force=False, use_mcp=False, cfg_override=None):
    task_id = str(uuid.uuid4())
    spec = _module_spec(module_name)
    with ai_tasks_lock:
        ai_tasks[task_id] = _create_ai_task_record(
            task_id=task_id,
            task_type='module',
            module_name=spec.get('module', module_name),
            module_title=spec.get('title', module_name),
            username=username,
        )
    _prune_ai_tasks()

    t = threading.Thread(
        target=_run_ai_module_task_worker,
        args=(task_id, username, start_ts, end_ts, module_name, depth, force, use_mcp, cfg_override),
        daemon=True
    )
    t.start()
    return task_id


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def handle(self):
        try:
            super().handle()
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError, OSError):
            pass  # 濞村繗顫嶉崳銊ュ彠闂傤叀绻涢幒銉礉濮濓絽鐖?
    def _send_json(self, obj, code=200):
        self.send_response(code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.end_headers()
        self.wfile.write(json.dumps(obj, ensure_ascii=False).encode('utf-8'))

    def _read_json_body(self):
        try:
            n = int(self.headers.get('Content-Length', '0') or '0')
        except Exception:
            n = 0
        if n <= 0:
            return {}
        raw = self.rfile.read(n)
        if not raw:
            return {}
        try:
            return json.loads(raw.decode('utf-8'))
        except Exception:
            return {}

    def do_GET(self):
        parsed_path = urllib.parse.urlparse(self.path)
        request_path = parsed_path.path or '/'

        if request_path in ('/', '/index.html'):
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0')
            self.end_headers()
            self.wfile.write(HTML_PAGE.encode('utf-8'))

        elif request_path.startswith('/analysis'):
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0')
            self.end_headers()
            self.wfile.write(ANALYSIS_PAGE.encode('utf-8'))

        elif self.path.startswith('/api/analysis/summary'):
            parsed_path = urllib.parse.urlparse(self.path)
            query = urllib.parse.parse_qs(parsed_path.query)
            username = str(query.get('username', [''])[0] or '').strip()
            if not username:
                self._send_json({'error': 'missing username'}, code=400)
                return
            start_ts, end_ts = _parse_time_range(query)
            link_limit = _safe_int(query.get('link_limit', ['6000'])[0], 6000, 200, 20000)
            try:
                t0 = time.perf_counter()
                data = _build_chat_analysis(
                    username=username,
                    start_ts=start_ts,
                    end_ts=end_ts,
                    link_limit=link_limit,
                    lightweight=True,
                )
                data['elapsed_ms'] = round((time.perf_counter() - t0) * 1000, 1)
                self._send_json(data)
            except Exception as e:
                print(f"[analysis] failed: {e}", flush=True)
                self._send_json({'error': str(e)}, code=500)

        elif self.path.startswith('/api/analysis/full'):
            parsed_path = urllib.parse.urlparse(self.path)
            query = urllib.parse.parse_qs(parsed_path.query)
            username = str(query.get('username', [''])[0] or '').strip()
            if not username:
                self._send_json({'error': 'missing username'}, code=400)
                return
            start_ts, end_ts = _parse_time_range(query)
            link_limit = _safe_int(query.get('link_limit', ['12000'])[0], 12000, 1000, 40000)
            try:
                t0 = time.perf_counter()
                data = _build_analysis_full(
                    username=username,
                    start_ts=start_ts,
                    end_ts=end_ts,
                    link_limit=link_limit,
                )
                out = dict(data)
                out['elapsed_ms'] = round((time.perf_counter() - t0) * 1000, 1)
                self._send_json(out)
            except Exception as e:
                print(f"[analysis_full] failed: {e}", flush=True)
                self._send_json({'error': str(e)}, code=500)

        elif self.path.startswith('/api/analysis/score_rules'):
            self._send_json({'rules': ANALYSIS_SCORE_RULES})

        elif self.path.startswith('/api/analysis/manual_entries'):
            parsed_path = urllib.parse.urlparse(self.path)
            query = urllib.parse.parse_qs(parsed_path.query)
            username = str(query.get('username', [''])[0] or '').strip()
            start_ts, end_ts = _parse_time_range(query)
            rows = _manual_score_list(username=username, start_ts=start_ts, end_ts=end_ts)
            self._send_json({'entries': rows})

        elif self.path.startswith('/api/live_alert/config'):
            self._send_json(_get_live_alert_config())

        elif self.path.startswith('/api/live_alert/list'):
            parsed_path = urllib.parse.urlparse(self.path)
            query = urllib.parse.parse_qs(parsed_path.query)
            limit = _safe_int(query.get('limit', ['60'])[0], 60, 1, LIVE_ALERT_MAX_ITEMS)
            status = str(query.get('status', ['open'])[0] or 'open').strip().lower()
            keyword = _normalize_keyword(query.get('keyword', [''])[0])
            category = str(query.get('category', [''])[0] or '').strip().lower()
            start_ts, end_ts = _parse_time_range(query)
            scoped_rows = _filter_live_alert_rows(
                _load_live_alerts(),
                status='all',
                keyword=keyword,
                category=category,
                start_ts=start_ts,
                end_ts=end_ts,
            )
            counts = _count_live_alert_statuses(scoped_rows)
            rows = _filter_live_alert_rows(scoped_rows, status=status or 'open')[:limit]
            self._send_json({
                'alerts': rows,
                'open_count': counts.get('open', 0),
                'history_count': counts.get('history', 0),
                'total_count': counts.get('all', 0),
                'status_counts': counts,
            })

        elif self.path.startswith('/api/sessions'):
            parsed_path = urllib.parse.urlparse(self.path)
            query = urllib.parse.parse_qs(parsed_path.query)
            limit = _safe_int(query.get('limit', ['5000'])[0], 5000, 1, 50000)
            data = []
            try:
                names = load_contact_names()
                rows = []
                snap = _get_session_state_snapshot()
                if snap:
                    for username, item in snap.items():
                        if not username:
                            continue
                        item = item if isinstance(item, dict) else {}
                        rows.append((
                            username,
                            int(item.get('unread', 0) or 0),
                            item.get('summary', '') or '',
                            int(item.get('timestamp', 0) or 0),
                            int(item.get('msg_type', 0) or 0),
                        ))
                    rows.sort(key=lambda x: int(x[3] or 0), reverse=True)
                    if limit > 0:
                        rows = rows[:limit]
                else:
                    with session_db_lock:
                        if not _looks_like_sqlite_file(DECRYPTED_SESSION):
                            raise sqlite3.DatabaseError("decrypted session db is not ready")
                        conn = sqlite3.connect(f"file:{DECRYPTED_SESSION}?mode=ro", uri=True)
                        try:
                            rows = conn.execute(
                                """
                                SELECT username, unread_count, summary, last_timestamp, last_msg_type
                                FROM SessionTable
                                WHERE last_timestamp > 0
                                ORDER BY last_timestamp DESC
                                LIMIT ?
                                """,
                                (limit,)
                            ).fetchall()
                        finally:
                            conn.close()

                for username, unread, summary, ts, msg_type in rows:
                    if not username or _is_placeholder_session(username):
                        continue
                    is_group = '@chatroom' in username
                    text = summary or ""
                    if text and ':\n' in text:
                        text = text.split(':\n', 1)[1]
                    text = _fallback_content_by_type(msg_type, text)
                    data.append({
                        'username': username,
                        'chat': _display_name_for_username(username, names),
                        'timestamp': int(ts or 0),
                        'time': datetime.fromtimestamp(int(ts)).strftime('%m-%d %H:%M:%S') if ts else '',
                        'unread': int(unread or 0),
                        'summary': text,
                        'is_group': is_group,
                        'official': _is_official_account(username),
                    })
            except Exception as e:
                print(f"[sessions] failed: {e}", flush=True)

            self.send_response(200)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.end_headers()
            self.wfile.write(json.dumps(data, ensure_ascii=False).encode('utf-8'))

        elif self.path.startswith('/api/ai/status'):
            self._send_json(_probe_ai_status())

        elif self.path.startswith('/api/ai/provider_config'):
            self._send_json(_get_ai_provider_config(mask_secret=True))

        elif self.path.startswith('/api/ai/provider_status'):
            self._send_json(_probe_ai_provider_status())

        elif self.path.startswith('/api/ai/sessions'):
            parsed_path = urllib.parse.urlparse(self.path)
            query = urllib.parse.parse_qs(parsed_path.query)
            limit = _safe_int(query.get('limit', ['100'])[0], 100, 1, 500)
            self._send_json({'sessions': _list_ai_sessions(limit=limit)})

        elif self.path.startswith('/api/ai/session'):
            parsed_path = urllib.parse.urlparse(self.path)
            query = urllib.parse.parse_qs(parsed_path.query)
            sid = query.get('id', [''])[0]
            if not sid:
                self._send_json({'error': 'missing id'}, code=400)
                return
            obj = _get_ai_session(sid)
            if not obj:
                self._send_json({'error': 'session not found'}, code=404)
                return
            self._send_json(obj)

        elif self.path.startswith('/api/ai/task_status'):
            parsed_path = urllib.parse.urlparse(self.path)
            query = urllib.parse.parse_qs(parsed_path.query)
            tid = query.get('id', [''])[0]
            if not tid:
                self._send_json({'error': 'missing id'}, code=400)
                return
            task = _get_ai_task_snapshot(tid)
            if not task:
                self._send_json({'error': 'task not found'}, code=404)
                return
            events = task.get('events', [])
            if isinstance(events, list) and len(events) > 120:
                events = events[-120:]
            self._send_json({
                'id': task.get('id'),
                'session_id': task.get('session_id'),
                'task_type': task.get('task_type', 'chat'),
                'module_name': task.get('module_name', ''),
                'module_title': task.get('module_title', ''),
                'username': task.get('username', ''),
                'status': task.get('status'),
                'status_text': task.get('status_text', ''),
                'progress_pct': task.get('progress_pct', 0),
                'partial_reply': task.get('partial_reply', ''),
                'final_reply': task.get('final_reply', ''),
                'error': task.get('error', ''),
                'events': events if isinstance(events, list) else [],
                'created_at': task.get('created_at', 0),
                'run_started_ms': task.get('run_started_ms', 0),
                'cancel_requested': bool(task.get('cancel_requested', False)),
                'updated_at': task.get('updated_at', 0),
                'session': task.get('session'),
                'result': task.get('result'),
            })

        elif self.path.startswith('/api/history'):
            parsed_path = urllib.parse.urlparse(self.path)
            query = urllib.parse.parse_qs(parsed_path.query)
            limit = _safe_int(query.get('limit', ['300'])[0], 300, 1, MAX_LOG)
            start_ts, end_ts = _parse_time_range(query)

            with messages_lock:
                data = sorted(messages_log, key=lambda m: m.get('timestamp', 0))
            if start_ts:
                data = [m for m in data if m.get('timestamp', 0) >= start_ts]
            if end_ts:
                data = [m for m in data if m.get('timestamp', 0) <= end_ts]
            if limit and len(data) > limit:
                data = data[-limit:]
            self.send_response(200)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.end_headers()
            self.wfile.write(json.dumps(data, ensure_ascii=False).encode('utf-8'))

        elif self.path.startswith('/api/chat_history'):
            parsed_path = urllib.parse.urlparse(self.path)
            query = urllib.parse.parse_qs(parsed_path.query)
            username = query.get('username', [''])[0]
            keyword = _normalize_keyword(query.get('keyword', [''])[0])
            fast_mode = str(query.get('fast', [''])[0] or '').strip().lower() in {'1', 'true', 'yes', 'fast'}
            paged_mode = str(query.get('paged', [''])[0] or '').strip().lower() in {'1', 'true', 'yes', 'paged'}
            limit_raw = query.get('limit', [''])[0]
            if str(limit_raw).strip() == '':
                limit = 0
            else:
                limit = _safe_int(limit_raw, 0, 0, 2000000)
            before_ts = _safe_int(query.get('before_ts', ['0'])[0], 0, 0, None)
            before_local_id = _safe_int(query.get('before_local_id', ['0'])[0], 0, 0, None)
            page_limit = limit if paged_mode else 0
            query_limit = (page_limit + 1) if page_limit > 0 else limit
            start_ts, end_ts = _parse_time_range(query)
            
            data = []
            has_more = False
            next_before_ts = 0
            next_before_local_id = 0
            if username:
                db_path, table_name = _find_msg_table_for_user(username, ensure_fresh=True)
                if db_path:
                    try:
                        refresh_info = ensure_message_db_ready_for_read(
                            db_path,
                            prefer_stale=True,
                            min_async_interval_sec=12,
                        )
                        refresh_mode = str(refresh_info.get("mode", "ready") or "ready")
                        if refresh_mode == "sync":
                            print(
                                f"[chat_history] sync refreshed {os.path.basename(db_path)} "
                                f"{refresh_info.get('pages', 0)}pg/{float(refresh_info.get('ms', 0.0)):.1f}ms",
                                flush=True
                            )
                        elif refresh_mode == "stale":
                            print(
                                f"[chat_history] using readable cached copy for {os.path.basename(db_path)}; "
                                f"background refresh scheduled={bool(refresh_info.get('scheduled', False))}",
                                flush=True
                            )

                        # Refresh resource index with throttle; avoid blocking refresh
                        # for heavy FTS DB on every chat click.
                        if not fast_mode:
                            try:
                                _refresh_aux_db_throttled(DECRYPTED_MESSAGE_RESOURCE, min_interval_sec=20)
                            except Exception as e:
                                print(f"[chat_history] resource refresh failed: {e}", flush=True)
                        cols, rowid_sender_map, rows_meta = _load_message_rows_safe(
                            db_path=db_path,
                            table_name=table_name,
                            start_ts=start_ts,
                            end_ts=end_ts,
                            limit=query_limit,
                            newest_first=True,
                            before_ts=before_ts,
                            before_local_id=before_local_id,
                        )
                        if page_limit > 0 and len(rows_meta) > page_limit:
                            has_more = True
                            rows_meta = rows_meta[:page_limit]
                        if has_more and rows_meta:
                            last_meta = rows_meta[-1] or {}
                            next_before_ts = int(last_meta.get("timestamp", 0) or 0)
                            next_before_local_id = int(last_meta.get("local_id", 0) or 0)
                        rows = [
                            (
                                int(r.get("local_id", 0) or 0),
                                int(r.get("local_type", 0) or 0),
                                int(r.get("timestamp", 0) or 0),
                                int(r.get("server_id", 0) or 0),
                                r.get("content", ""),
                                int(r.get("status", 0) or 0),
                                r.get("source", b""),
                                int(r.get("real_sender_id", 0) or 0),
                                r.get("ct_flag", None),
                            )
                            for r in rows_meta
                        ]

                        server_ids = []
                        local_ids = []
                        fts_needed_rows = []
                        if limit <= 0:
                            max_fts_rows = 40000
                        elif limit <= 600:
                            max_fts_rows = 300
                        elif limit <= 2000:
                            max_fts_rows = 1200
                        else:
                            max_fts_rows = 3000
                        for row in rows:
                            local_id = row[0] if len(row) > 0 and isinstance(row[0], int) else 0
                            local_type = row[1] if len(row) > 1 and isinstance(row[1], int) else 0
                            ts = row[2] if len(row) > 2 and isinstance(row[2], int) else 0
                            server_id = row[3] if len(row) > 3 and isinstance(row[3], int) else 0
                            content = row[4] if len(row) > 4 else ""
                            real_sender_id = row[7] if len(row) > 7 and isinstance(row[7], int) else 0
                            ct_msg = row[8] if len(row) > 8 and isinstance(row[8], int) else None
                            content_text = content if isinstance(content, str) else ""
                            if not content_text and isinstance(content, (bytes, bytearray)):
                                content_text = _decode_message_content(content, local_type, ct_msg)
                            content_is_blob = isinstance(content, (bytes, bytearray)) or ct_msg == 4
                            text_missing = not content_text.strip()
                            text_garbled = _is_text_garbled(content_text)

                            if isinstance(local_id, int) and local_id >= 0:
                                local_ids.append(local_id)
                            if isinstance(server_id, int) and server_id > 0:
                                server_ids.append(server_id)
                            # Use FTS fallback when text is encrypted/missing/garbled.
                            if (
                                (content_is_blob or text_missing or text_garbled)
                                and len(fts_needed_rows) < max_fts_rows
                                and _normalize_msg_type(local_type) in (1, 49, 10000, 10002)
                            ):
                                fts_needed_rows.append((local_id, ts))

                        if fast_mode:
                            resource_server_map, resource_local_map = {}, {}
                            fts_fallback_map = {}
                        else:
                            resource_server_map, resource_local_map = _load_resource_meta_maps(server_ids, local_ids)
                            if fts_needed_rows:
                                try:
                                    _refresh_aux_db_throttled(DECRYPTED_MESSAGE_FTS, min_interval_sec=12)
                                except Exception as e:
                                    print(f"[chat_history] fts refresh failed: {e}", flush=True)
                            fts_fallback_map = _load_fts_fallback_meta(username, fts_needed_rows)

                        contact_names = load_contact_names()
                        is_group = '@chatroom' in username
                        for row in reversed(rows):
                            local_id = row[0] if len(row) > 0 and isinstance(row[0], int) else 0
                            local_type = row[1] if len(row) > 1 and isinstance(row[1], int) else 0
                            ts = row[2] if len(row) > 2 and isinstance(row[2], int) else 0
                            server_id = row[3] if len(row) > 3 and isinstance(row[3], int) else 0
                            content = row[4] if len(row) > 4 else ""
                            status = row[5] if len(row) > 5 and isinstance(row[5], int) else 0
                            source_blob = row[6] if len(row) > 6 else b""
                            real_sender_id = row[7] if len(row) > 7 and isinstance(row[7], int) else 0
                            ct_msg = row[8] if len(row) > 8 and isinstance(row[8], int) else None

                            sender_username = rowid_sender_map.get(real_sender_id, "")
                            text = content if isinstance(content, str) else ""
                            if (not text.strip()) and isinstance(content, (bytes, bytearray)):
                                text = _decode_message_content(content, local_type, ct_msg)
                            if _is_text_garbled(text):
                                text = ""
                            fts_cand = _pick_best_fts_candidate(
                                fts_fallback_map.get(local_id, []),
                                ts
                            )

                            # Parse sender prefix in normal group text: "wxid_xxx:\n姝ｆ枃".
                            if is_group:
                                p_sender, p_body = _parse_group_sender_prefix(text)
                                if p_sender:
                                    if not sender_username:
                                        sender_username = p_sender
                                    text = p_body

                            # message_content may be encrypted/garbled: use fts plain text fallback.
                            if fts_cand and isinstance(fts_cand.get('text', ''), str):
                                fts_text = _clean_rich_text(fts_cand.get('text', ''))
                                if _is_text_garbled(fts_text):
                                    fts_text = ""
                                use_fts = False
                                if not text.strip():
                                    use_fts = True
                                else:
                                    clean_now = _clean_rich_text(text)
                                    clean_fts = _clean_rich_text(fts_text)
                                    if (
                                        clean_fts
                                        and len(clean_fts) > len(clean_now) + 24
                                        and _normalize_msg_type(local_type) in (1, 49, 10000, 10002)
                                    ):
                                        use_fts = True
                                if use_fts:
                                    if is_group:
                                        p_sender, p_body = _parse_group_sender_prefix(fts_text)
                                        if p_sender:
                                            if not sender_username:
                                                sender_username = p_sender
                                            text = p_body
                                        else:
                                            text = fts_text
                                    else:
                                        text = fts_text

                            if (not sender_username) and fts_cand:
                                sender_username = str(fts_cand.get('sender_username', '') or '').strip()

                            is_me = _resolve_is_self_message(is_group, status, sender_username)

                            # Render link/quote messages as readable text.
                            text = _render_link_or_quote_text(local_type, text, source_blob)
                            if _is_text_garbled(text) and fts_cand and isinstance(fts_cand.get('text', ''), str):
                                fts_text2 = _clean_rich_text(fts_cand.get('text', ''))
                                if is_group:
                                    _, p_body = _parse_group_sender_prefix(fts_text2)
                                    text = p_body or fts_text2
                                else:
                                    text = fts_text2
                            if _normalize_msg_type(local_type) == 49:
                                text = _sanitize_link_text(text)
                            link_source, link_url = _extract_link_meta(local_type, text, source_blob)

                            base_type = _normalize_msg_type(local_type)
                            media_url = _resolve_media_url_for_row(
                                base_type=base_type,
                                username=username,
                                ts=ts,
                                server_id=server_id,
                                local_id=local_id,
                                source_blob=source_blob,
                                content_blob=content,
                                ct_flag=ct_msg,
                                resource_server_map=resource_server_map,
                                resource_local_map=resource_local_map,
                            )
                            rich_media = _extract_rich_media_payload(
                                base_type,
                                text,
                                source_blob=source_blob,
                                link_source=link_source,
                                link_url=link_url,
                                media_url=media_url,
                            )
                            text = _finalize_display_content(base_type, text)

                            sender_display = ""
                            if is_me:
                                sender_display = "我"
                            elif sender_username:
                                sender_display = contact_names.get(sender_username, sender_username)
                            elif not is_group:
                                sender_display = contact_names.get(username, username)

                            row_out = {
                                'username': username,
                                'chat': _display_name_for_username(username, contact_names),
                                'is_group': is_group,
                                'time': datetime.fromtimestamp(ts).strftime('%m-%d %H:%M:%S') if ts else '',
                                'timestamp': ts,
                                'local_id': local_id,
                                'server_id': server_id,
                                'type': _display_msg_type(base_type, content=text, source_blob=source_blob),
                                'content': text,
                                'sender': sender_display,
                                'is_me': is_me,
                                'media_url': media_url,
                                'link_source': link_source,
                                'link_url': link_url,
                            }
                            if rich_media:
                                row_out['rich_media'] = rich_media
                            data.append(row_out)
                    except Exception as e:
                        print(f"[chat_history] load failed: {e}", flush=True)

            if keyword:
                data = [x for x in data if _history_row_matches_keyword(x, keyword)]
            
            if paged_mode:
                self._send_json({
                    'rows': data,
                    'has_more': has_more,
                    'next_before_ts': next_before_ts,
                    'next_before_local_id': next_before_local_id,
                })
            else:
                self.send_response(200)
                self.send_header('Content-Type', 'application/json; charset=utf-8')
                self.end_headers()
                self.wfile.write(json.dumps(data, ensure_ascii=False).encode('utf-8'))

        elif self.path.startswith('/api/ai_image'):
            parsed_path = urllib.parse.urlparse(self.path)
            query = urllib.parse.parse_qs(parsed_path.query)
            name = query.get('f', [''])[0]
            safe_name = os.path.basename(name)
            if not safe_name:
                self.send_error(400)
                return
            abs_path = os.path.abspath(os.path.join(AI_UPLOAD_DIR, safe_name))
            root = os.path.abspath(AI_UPLOAD_DIR)
            if not abs_path.startswith(root + os.sep):
                self.send_error(403)
                return
            if not os.path.exists(abs_path):
                self.send_error(404)
                return
            try:
                with open(abs_path, 'rb') as f:
                    data = f.read()
                mime = _detect_image_mime(data) or 'application/octet-stream'
                self.send_response(200)
                self.send_header('Content-Type', mime)
                self.send_header('Cache-Control', 'private, max-age=86400')
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            except Exception as e:
                print(f"[ai_image] serve failed: {e}", flush=True)
                self.send_error(500)

        elif self.path.startswith('/api/emoji'):
            parsed_path = urllib.parse.urlparse(self.path)
            query = urllib.parse.parse_qs(parsed_path.query)
            name = os.path.basename(query.get('f', [''])[0] or '')
            if not name:
                self.send_error(400)
                return
            abs_path = os.path.abspath(os.path.join(EMOJI_CACHE_DIR, name))
            root = os.path.abspath(EMOJI_CACHE_DIR)
            if not abs_path.startswith(root + os.sep):
                self.send_error(403)
                return
            if not os.path.exists(abs_path):
                self.send_error(404)
                return
            try:
                with open(abs_path, "rb") as f:
                    data = f.read()
                mime = _detect_image_mime(data) or "application/octet-stream"
                self.send_response(200)
                self.send_header('Content-Type', mime)
                self.send_header('Cache-Control', 'private, max-age=86400')
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            except Exception as e:
                print(f"[emoji] serve failed: {e}", flush=True)
                self.send_error(500)

        elif self.path.startswith('/api/media'):
            parsed_path = urllib.parse.urlparse(self.path)
            query = urllib.parse.parse_qs(parsed_path.query)
            rel = query.get('f', [''])[0]
            rel = urllib.parse.unquote(rel).replace('/', os.sep).replace('\\', os.sep)
            root = os.path.abspath(ATTACH_ROOT)
            abs_path = os.path.abspath(os.path.join(root, rel))
            if not rel or not abs_path.startswith(root + os.sep):
                self.send_error(403)
                return
            if not os.path.exists(abs_path):
                self.send_error(404)
                return
            try:
                mime, data = _read_wechat_media(abs_path)
                self.send_response(200)
                self.send_header('Content-Type', mime)
                self.send_header('Cache-Control', 'private, max-age=86400')
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            except Exception as e:
                print(f"[media] serve failed: {e}", flush=True)
                self.send_error(500)

        elif self.path == '/stream':
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Cache-Control', 'no-cache')
            self.send_header('Connection', 'keep-alive')
            self.end_headers()

            q = queue.Queue()
            with sse_lock:
                sse_clients.append(q)
            try:
                while True:
                    try:
                        payload = q.get(timeout=15)
                        self.wfile.write(payload.encode('utf-8'))
                        self.wfile.flush()
                    except queue.Empty:
                        self.wfile.write(b': hb\n\n')
                        self.wfile.flush()
            except:
                pass
            finally:
                with sse_lock:
                    if q in sse_clients:
                        sse_clients.remove(q)
        else:
            self.send_error(404)

    def do_POST(self):
        if self.path.startswith('/api/live_alert/config'):
            body = self._read_json_body()
            try:
                cfg = _update_live_alert_config(body if isinstance(body, dict) else {})
                self._send_json({'ok': True, 'config': cfg})
            except Exception as e:
                self._send_json({'error': str(e)}, code=400)
            return

        if self.path.startswith('/api/live_alert/mark'):
            body = self._read_json_body()
            alert_id = str(body.get('id', '') or body.get('alert_id', '') or '').strip()
            status = str(body.get('status', 'acknowledged') or 'acknowledged').strip().lower()
            if not alert_id:
                self._send_json({'error': 'missing id'}, code=400)
                return
            try:
                row = _update_live_alert_status(alert_id, status)
            except Exception as e:
                self._send_json({'error': str(e)}, code=400)
                return
            if not row:
                self._send_json({'error': 'alert not found'}, code=404)
                return
            self._send_json({'ok': True, 'alert': row})
            return

        if self.path.startswith('/api/analysis/manual_add'):
            body = self._read_json_body()
            rule_id = str(body.get('rule_id', '') or '').strip()
            rule_obj = None
            for r in ANALYSIS_SCORE_RULES:
                if str(r.get("id", "")) == rule_id:
                    rule_obj = r
                    break
            if not rule_obj:
                self._send_json({'error': 'invalid rule_id'}, code=400)
                return
            if not bool(rule_obj.get("manual", False)):
                self._send_json({'error': 'rule is auto-only, cannot add manual entry'}, code=400)
                return

            points_raw = body.get('points', None)
            if points_raw is None or str(points_raw).strip() == '':
                points = int(rule_obj.get('points', 0) or 0)
            else:
                points = _safe_int(points_raw, int(rule_obj.get('points', 0) or 0), -100000, 100000)
            ts = _safe_int(body.get('ts', int(time.time())), int(time.time()), 0, None)
            try:
                entry = _manual_score_add({
                    "username": str(body.get('username', '') or '').strip(),
                    "sender_id": str(body.get('sender_id', '') or '').strip(),
                    "sender": str(body.get('sender', '') or '').strip(),
                    "rule_id": rule_id,
                    "points": int(points),
                    "note": str(body.get('note', '') or '').strip(),
                    "ts": int(ts),
                })
                self._send_json({'ok': True, 'entry': entry})
            except Exception as e:
                self._send_json({'error': str(e)}, code=400)
            return

        if self.path.startswith('/api/analysis/manual_delete'):
            body = self._read_json_body()
            entry_id = str(body.get('id', '') or body.get('entry_id', '') or '').strip()
            if not entry_id:
                self._send_json({'error': 'missing id'}, code=400)
                return
            ok = _manual_score_delete(entry_id)
            if not ok:
                self._send_json({'error': 'entry not found'}, code=404)
                return
            self._send_json({'ok': True, 'id': entry_id})
            return

        if self.path.startswith('/api/export_pinned_zip'):
            body = self._read_json_body()
            raw_usernames = body.get('usernames', [])
            if isinstance(raw_usernames, str):
                raw_usernames = [raw_usernames]
            if not isinstance(raw_usernames, list):
                self._send_json({'error': 'usernames must be an array'}, code=400)
                return

            unique = set()
            usernames = []
            for item in raw_usernames:
                username = str(item or '').strip()
                if not username or username in unique:
                    continue
                unique.add(username)
                # only export group chats for this endpoint
                if '@chatroom' in username:
                    usernames.append(username)

            if not usernames:
                self._send_json({'error': '娌℃湁鍙鍑虹殑缃《缇よ亰'}, code=400)
                return

            start_ts = _safe_int(body.get('start_ts', 0), 0, 0, None)
            end_ts = _safe_int(body.get('end_ts', 0), 0, 0, None)
            if start_ts and end_ts and start_ts > end_ts:
                start_ts, end_ts = end_ts, start_ts
            limit = _safe_int(body.get('limit', 200000), 200000, 0, 2000000)
            range_label = _format_export_range_label(start_ts, end_ts)

            contact_names = load_contact_names()
            scope_label = f"群聊批量导出（{range_label}）"

            try:
                zip_buffer = io.BytesIO()
                exported = 0
                with zipfile.ZipFile(zip_buffer, mode='w', compression=zipfile.ZIP_DEFLATED) as zf:
                    for idx, username in enumerate(usernames, 1):
                        rows = _fetch_local_chat_history(
                            username=username,
                            limit=limit,
                            start_ts=start_ts,
                            end_ts=end_ts,
                            keyword="",
                        )
                        chat_name = _display_name_for_username(username, contact_names)
                        md_text = _build_export_markdown(chat_name, scope_label, rows)
                        safe_name = _safe_export_filename_part(chat_name, fallback=f"group_{idx}")
                        zf.writestr(f"{idx:02d}_{safe_name}.md", md_text.encode('utf-8'))
                        exported += 1

                zip_data = zip_buffer.getvalue()
                if not zip_data:
                    self._send_json({'error': '瀵煎嚭澶辫触锛歓IP涓虹┖'}, code=500)
                    return

                zip_name = f"缃《缇よ亰瀵煎嚭_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
                zip_name_q = urllib.parse.quote(zip_name)
                self.send_response(200)
                self.send_header('Content-Type', 'application/zip')
                self.send_header(
                    'Content-Disposition',
                    f"attachment; filename*=UTF-8''{zip_name_q}"
                )
                self.send_header('Content-Length', str(len(zip_data)))
                self.send_header('X-Exported-Count', str(exported))
                self.end_headers()
                self.wfile.write(zip_data)
            except Exception as e:
                print(f"[export_pinned_zip] failed: {e}", flush=True)
                self._send_json({'error': f'瀵煎嚭澶辫触: {e}'}, code=500)
            return

        if self.path.startswith('/api/ai/provider_config'):
            body = self._read_json_body()
            try:
                cfg = _update_ai_provider_config(body if isinstance(body, dict) else {})
                self._send_json({'ok': True, 'config': cfg})
            except Exception as e:
                self._send_json({'error': str(e)}, code=400)
            return

        if self.path.startswith('/api/ai/provider_test'):
            body = self._read_json_body()
            try:
                result = _test_ai_provider_connection(body if isinstance(body, dict) else None)
                self._send_json(result)
            except Exception as e:
                self._send_json({'error': str(e)}, code=500)
            return

        if self.path == '/api/analysis/member_deep_profile':
            body = self._read_json_body()
            username = str(body.get('username', '') or '').strip()
            sender_id = str(body.get('sender_id', '') or '').strip()
            sender_name = str(body.get('sender', '') or '').strip()
            start_ts = _safe_int(body.get('start_ts', 0), 0, 0, None)
            end_ts = _safe_int(body.get('end_ts', 0), 0, 0, None)
            use_ai = _safe_bool(body.get('use_ai', False), False)
            force = _safe_bool(body.get('force', False), False)
            cfg_override = body.get('provider_cfg', None) if isinstance(body.get('provider_cfg', None), dict) else None
            if start_ts and end_ts and start_ts > end_ts:
                start_ts, end_ts = end_ts, start_ts
            if not username:
                self._send_json({'error': 'missing username'}, code=400)
                return
            try:
                t0 = time.perf_counter()
                out = _run_member_deep_profile_analysis(
                    username=username,
                    sender_id=sender_id,
                    sender_name=sender_name,
                    start_ts=start_ts,
                    end_ts=end_ts,
                    use_ai=use_ai,
                    force=force,
                    cfg_override=cfg_override,
                )
                out = dict(out)
                out['elapsed_ms'] = round((time.perf_counter() - t0) * 1000, 1)
                self._send_json(out)
            except Exception as e:
                self._send_json({'error': str(e)}, code=500)
            return

        if self.path == '/api/ai/module_run':
            body = self._read_json_body()
            username = str(body.get('username', '') or '').strip()
            start_ts = _safe_int(body.get('start_ts', 0), 0, 0, None)
            end_ts = _safe_int(body.get('end_ts', 0), 0, 0, None)
            module_name = str(body.get('module', 'report') or 'report').strip().lower()
            depth = str(body.get('depth', 'standard') or 'standard').strip().lower()
            force = bool(body.get('force', False))
            use_mcp = _safe_bool(body.get('use_mcp', False), False)
            cfg_override = body.get('provider_cfg', None) if isinstance(body.get('provider_cfg', None), dict) else None
            if start_ts and end_ts and start_ts > end_ts:
                start_ts, end_ts = end_ts, start_ts
            if not username:
                self._send_json({'error': 'missing username'}, code=400)
                return
            try:
                t0 = time.perf_counter()
                out = _run_ai_module_analysis(
                    username=username,
                    start_ts=start_ts,
                    end_ts=end_ts,
                    module_name=module_name,
                    depth=depth,
                    force=force,
                    use_mcp=use_mcp,
                    cfg_override=cfg_override,
                )
                out = dict(out)
                out['elapsed_ms'] = round((time.perf_counter() - t0) * 1000, 1)
                self._send_json(out)
            except Exception as e:
                self._send_json({'error': str(e)}, code=500)
            return

        if self.path == '/api/ai/module_run_start':
            body = self._read_json_body()
            username = str(body.get('username', '') or '').strip()
            start_ts = _safe_int(body.get('start_ts', 0), 0, 0, None)
            end_ts = _safe_int(body.get('end_ts', 0), 0, 0, None)
            module_name = str(body.get('module', 'report') or 'report').strip().lower()
            depth = str(body.get('depth', 'standard') or 'standard').strip().lower()
            force = bool(body.get('force', False))
            use_mcp = _safe_bool(body.get('use_mcp', False), False)
            cfg_override = body.get('provider_cfg', None) if isinstance(body.get('provider_cfg', None), dict) else None
            if start_ts and end_ts and start_ts > end_ts:
                start_ts, end_ts = end_ts, start_ts
            if not username:
                self._send_json({'error': 'missing username'}, code=400)
                return
            try:
                tid = _start_ai_module_task(
                    username=username,
                    start_ts=start_ts,
                    end_ts=end_ts,
                    module_name=module_name,
                    depth=depth,
                    force=force,
                    use_mcp=use_mcp,
                    cfg_override=cfg_override,
                )
                task = _get_ai_task_snapshot(tid) or {}
                self._send_json({
                    'ok': True,
                    'task_id': tid,
                    'module_name': task.get('module_name', module_name),
                    'module_title': task.get('module_title', module_name),
                })
            except Exception as e:
                self._send_json({'error': str(e)}, code=500)
            return

        if self.path.startswith('/api/ai/new_session'):
            body = self._read_json_body()
            title = str(body.get('title', '') or '').strip()
            obj = _create_ai_session(title=title)
            self._send_json({
                'id': obj.get('id'),
                'title': _session_summary_title(obj),
                'created_at': obj.get('created_at'),
                'updated_at': obj.get('updated_at'),
                'message_count': len(obj.get('messages', [])),
            })
            return

        if self.path.startswith('/api/ai/rename_session'):
            body = self._read_json_body()
            sid = str(body.get('session_id', '') or '').strip()
            title = str(body.get('title', '') or '').strip()
            if not sid:
                self._send_json({'error': 'missing session_id'}, code=400)
                return
            try:
                obj = _rename_ai_session(sid, title)
                if not obj:
                    self._send_json({'error': 'session not found'}, code=404)
                    return
                self._send_json({'ok': True, 'session': obj})
            except Exception as e:
                self._send_json({'error': str(e)}, code=400)
            return

        if self.path.startswith('/api/ai/delete_session'):
            body = self._read_json_body()
            sid = str(body.get('session_id', '') or '').strip()
            if not sid:
                self._send_json({'error': 'missing session_id'}, code=400)
                return
            ok = _delete_ai_session(sid)
            if not ok:
                self._send_json({'error': 'session not found'}, code=404)
                return
            self._send_json({'ok': True, 'deleted_id': sid})
            return

        if self.path.startswith('/api/ai/reconnect'):
            data = _try_reconnect_wechat_mcp()
            self._send_json(data)
            return

        if self.path == '/api/ai/debug_echo':
            body = self._read_json_body()
            question = _decode_ai_question(body)
            self._send_json({
                'question': question,
                'question_repr': repr(question),
                'question_utf8_hex': question.encode('utf-8', errors='replace').hex(),
                'body_keys': sorted(list(body.keys())) if isinstance(body, dict) else [],
            })
            return

        if self.path.startswith('/api/ai/cancel_task'):
            body = self._read_json_body()
            tid = str(body.get('task_id', '') or '').strip()
            if not tid:
                self._send_json({'error': 'missing task_id'}, code=400)
                return
            ok, msg = _cancel_ai_task(tid)
            if not ok:
                if msg == 'task not found':
                    self._send_json({'error': msg}, code=404)
                else:
                    self._send_json({'error': msg}, code=400)
                return
            self._send_json({'ok': True, 'task_id': tid, 'message': msg})
            return

        if self.path.startswith('/api/ai/ask_start'):
            body = self._read_json_body()
            sid = str(body.get('session_id', '') or '').strip()
            question = _decode_ai_question(body).strip()
            context_obj = body.get('context', {}) if isinstance(body.get('context', {}), dict) else {}
            raw_images = body.get('images', [])
            _append_ai_debug_log('ask_start_http', {
                'session_id': sid,
                'question': question,
                'question_repr': repr(question),
                'body_keys': sorted(list(body.keys())) if isinstance(body, dict) else [],
                'context': context_obj if isinstance(context_obj, dict) else {},
            })
            if not question:
                self._send_json({'error': 'question is empty'}, code=400)
                return

            if not sid:
                session_obj = _create_ai_session()
                sid = session_obj['id']
            else:
                _ensure_ai_sessions_loaded()
                with ai_sessions_lock:
                    session_obj = ai_sessions.get(sid)
                if not session_obj:
                    self._send_json({'error': 'session not found'}, code=404)
                    return

            try:
                image_files = _save_inline_images(raw_images)
                task_id = _start_ai_task(session_obj, question, context_obj, image_files=image_files)
                self._send_json({
                    'session_id': sid,
                    'task_id': task_id,
                })
            except Exception as e:
                self._send_json({
                    'error': str(e),
                    'session_id': sid,
                }, code=500)
            return

        if self.path.startswith('/api/ai/ask'):
            body = self._read_json_body()
            sid = str(body.get('session_id', '') or '').strip()
            question = _decode_ai_question(body).strip()
            context_obj = body.get('context', {}) if isinstance(body.get('context', {}), dict) else {}
            raw_images = body.get('images', [])
            if not question:
                self._send_json({'error': 'question is empty'}, code=400)
                return

            if not sid:
                session_obj = _create_ai_session()
                sid = session_obj['id']
            else:
                _ensure_ai_sessions_loaded()
                with ai_sessions_lock:
                    session_obj = ai_sessions.get(sid)
                if not session_obj:
                    self._send_json({'error': 'session not found'}, code=404)
                    return

            try:
                image_files = _save_inline_images(raw_images)
                ai_msg = _ask_claude(session_obj, question, context_obj, image_files=image_files)
                current = _get_ai_session(sid)
                self._send_json({
                    'session_id': sid,
                    'reply': ai_msg.get('content', ''),
                    'session': current,
                })
            except Exception as e:
                self._send_json({
                    'error': str(e),
                    'session_id': sid,
                }, code=500)
            return

        self.send_error(404)


class ThreadedServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def _show_fatal_popup(message, title='WechatEngine'):
    try:
        ctypes.windll.user32.MessageBoxW(None, str(message), str(title), 0x10)
    except Exception:
        pass


def _append_ai_debug_log(kind, payload):
    try:
        _ensure_dir(LOG_DIR)
        row = {
            'ts': int(time.time()),
            'kind': str(kind or ''),
            'payload': payload if isinstance(payload, dict) else {'value': str(payload or '')},
        }
        with open(AI_DEBUG_LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    except Exception:
        pass


def _decode_ai_question(body):
    if not isinstance(body, dict):
        return ''
    q_b64 = str(body.get('question_b64', '') or '').strip()
    if q_b64:
        try:
            raw = base64.b64decode(q_b64.encode('ascii'), validate=True)
            text = raw.decode('utf-8')
            if text:
                return text
        except Exception:
            pass
    return str(body.get('question', '') or '')


def _find_port_owner_info(port):
    if os.name != 'nt':
        return None
    try:
        script = (
            "$conn = Get-NetTCPConnection -LocalPort " + str(int(port)) + " -State Listen -ErrorAction SilentlyContinue | "
            "Select-Object -First 1; "
            "if(-not $conn){ return }; "
            "$p = Get-CimInstance Win32_Process -Filter \"ProcessId=$($conn.OwningProcess)\" | Select-Object -First 1; "
            "if($p){ "
            "  [PSCustomObject]@{ pid=$p.ProcessId; name=$p.Name; commandline=$p.CommandLine } | ConvertTo-Json -Compress"
            "}"
        )
        rc, out, _err = _run_cmd(['powershell', '-NoProfile', '-Command', script], timeout=6)
        if rc != 0 or not out:
            return None
        obj = json.loads(out)
        if isinstance(obj, dict):
            return obj
    except Exception:
        return None
    return None


def _iter_bind_ports(preferred_port):
    seen = set()
    for port in (preferred_port,) + PORT_FALLBACKS:
        try:
            port = int(port)
        except Exception:
            continue
        if port < 0 or port > 65535 or port in seen:
            continue
        seen.add(port)
        yield port


def _bind_server(handler_cls, preferred_port):
    bind_errors = []
    for candidate in _iter_bind_ports(preferred_port):
        try:
            server = ThreadedServer(('0.0.0.0', candidate), handler_cls)
            return server, bind_errors
        except OSError as e:
            owner = _find_port_owner_info(candidate) if candidate else None
            bind_errors.append((candidate, e, owner))
    return None, bind_errors


def _read_keys_file():
    with open(KEYS_FILE, 'r', encoding='utf-8') as f:
        obj = json.load(f)
    if not isinstance(obj, dict) or not obj:
        raise RuntimeError(f"invalid keys file: {KEYS_FILE}")
    return obj


def _run_key_extractor(reason=""):
    if reason:
        print(f"[init] {reason}, running in-app key extractor...", flush=True)
    else:
        print("[init] keys missing/invalid, running in-app key extractor...", flush=True)
    try:
        key_extractor.main()
    except SystemExit as e:
        code = getattr(e, "code", 1)
        if code not in (0, None):
            raise RuntimeError(
                "failed to extract keys automatically. "
                "Please run WechatEngine as Administrator and ensure Weixin.exe is running."
            ) from e
    except Exception as e:
        raise RuntimeError(
            "failed to extract keys automatically. "
            "Please run WechatEngine as Administrator and ensure Weixin.exe is running."
        ) from e
    return _read_keys_file()


def _ensure_keys_file():
    try:
        return _read_keys_file()
    except Exception:
        return _run_key_extractor()


def _get_db_enc_key(keys_obj, rel_path):
    if not isinstance(keys_obj, dict):
        return None
    cands = [rel_path, rel_path.replace('\\', '/'), rel_path.replace('/', '\\')]
    for k in cands:
        item = keys_obj.get(k)
        if isinstance(item, dict):
            enc = str(item.get('enc_key', '') or '').strip()
            if enc:
                return enc
    rel_low = rel_path.replace('\\', '/').lower()
    for k, item in keys_obj.items():
        if not isinstance(item, dict):
            continue
        key_low = str(k).replace('\\', '/').lower()
        if key_low.endswith(rel_low):
            enc = str(item.get('enc_key', '') or '').strip()
            if enc:
                return enc
    return None


def main():
    global PORT

    print("=" * 60, flush=True)
    print("  WechatEngine WeChat Monitor (WAL + SSE)", flush=True)
    print("=" * 60, flush=True)

    if not os.path.isdir(DB_DIR):
        msg = (
            f"db_dir not found: {DB_DIR}\n\n"
            f"Please set a correct db_dir in config.json, or keep WeChat data in a default location "
            f"for auto-detection."
        )
        print(f"[fatal] {msg}", flush=True)
        _show_fatal_popup(msg)
        return

    session_db = os.path.join(DB_DIR, "session", "session.db")
    session_rel = os.path.join("session", "session.db")

    try:
        keys = _ensure_keys_file()
    except Exception as e:
        msg = f"Failed to load/extract keys: {e}"
        print(f"[fatal] {msg}", flush=True)
        _show_fatal_popup(msg)
        return

    global ALL_KEYS
    ALL_KEYS = keys
    try:
        _build_emoji_lookup(keys)
    except Exception as e:
        print(f"[emoji] init lookup failed: {e}", flush=True)

    enc_key_hex = _find_valid_db_enc_key(keys, session_rel, session_db)
    if not enc_key_hex:
        try:
            keys = _run_key_extractor("session key invalid or stale")
            ALL_KEYS = keys
            enc_key_hex = _find_valid_db_enc_key(keys, session_rel, session_db)
        except Exception as e:
            msg = f"Failed to refresh keys: {e}"
            print(f"[fatal] {msg}", flush=True)
            _show_fatal_popup(msg)
            return

    if not enc_key_hex:
        msg = (
            "Cannot validate key for session/session.db.\n"
            "Please run as Administrator with Weixin.exe running, then retry."
        )
        print(f"[fatal] {msg}", flush=True)
        _show_fatal_popup(msg)
        return

    try:
        enc_key = bytes.fromhex(enc_key_hex)
    except Exception:
        msg = "session key format invalid."
        print(f"[fatal] {msg}", flush=True)
        _show_fatal_popup(msg)
        return

    _ensure_ai_sessions_loaded()
    _load_live_alert_config()
    _load_live_alerts()

    print("[init] loading contacts...", flush=True)
    contact_names = load_contact_names()
    print(f"[init] contacts loaded: {len(contact_names)}", flush=True)

    t = threading.Thread(target=monitor_thread, args=(enc_key, session_db, contact_names), daemon=True)
    t.start()
    threading.Thread(target=_background_warm_message_indexes, daemon=True).start()
    _start_parent_watchdog()

    requested_port = PORT
    server, bind_errors = _bind_server(Handler, requested_port)
    if not server:
        bind_port, bind_error, owner = bind_errors[0] if bind_errors else (requested_port, RuntimeError("unknown bind error"), None)
        if owner:
            cmdline = str(owner.get('commandline', '') or '').strip()
            pid = owner.get('pid', '')
            msg = (
                f"端口 {bind_port} 已被另一个进程占用，当前这个版本没有成功启动。\n\n"
                f"占用进程 PID: {pid}\n"
                f"占用进程路径/命令:\n{cmdline or '(unknown)'}\n\n"
                "请先关闭旧版 WechatEngine，再重新打开当前版本。"
            )
        else:
            msg = f"端口 {bind_port} 无法监听：{bind_error}"
        print(f"[fatal] {msg}", flush=True)
        _show_fatal_popup(msg)
        return
    PORT = int(server.server_address[1])
    if PORT != requested_port:
        first_port, first_error, _first_owner = bind_errors[0]
        print(
            f"[init] port {first_port} unavailable ({first_error}); switched to http://{_web_host()}:{PORT}",
            flush=True,
        )
    print(f"[init] analysis page: {ANALYSIS_HTML_FILE}", flush=True)
    print(f"\n=> http://{_web_host()}:{PORT}", flush=True)
    print("Ctrl+C to stop\n", flush=True)

    if _should_open_browser():
        try:
            os.system(f'cmd.exe /c start http://{_web_host()}:{PORT}')
        except:
            pass

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")


if __name__ == '__main__':
    main()
