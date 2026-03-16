"""
Configuration loader.

Behavior:
1. Creates config.json on first run if missing.
2. Auto-detects WeChat db_storage path when config db_dir is placeholder/invalid.
3. Keeps keys_file/decrypted_dir paths absolute for stable runtime behavior.
"""

import glob
import json
import os
import sys


def _runtime_base_dir():
    # In PyInstaller one-file mode, keep writable runtime files next to the exe.
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


CONFIG_FILE = os.path.join(_runtime_base_dir(), "config.json")

_DEFAULT = {
    "db_dir": r"D:\\xwechat_files\\your_wxid\\db_storage",
    "keys_file": "all_keys.json",
    "decrypted_dir": "decrypted",
    "wechat_process": "Weixin.exe",
    "web_port": 8080,
    "image_aes_key": "",
    "image_xor_key": 136,
}


def _normalize(path):
    return os.path.normpath(os.path.abspath(path))


def _parse_port(value, default):
    try:
        port = int(value)
    except Exception:
        return int(default)
    if 0 <= port <= 65535:
        return port
    return int(default)


def _is_placeholder_db_dir(path):
    if not path:
        return True
    low = str(path).replace("/", "\\").lower()
    return "your_wxid" in low or low.endswith(r"\xwechat_files\db_storage")


def _looks_like_db_dir(db_dir):
    if not db_dir:
        return False
    session_db = os.path.join(db_dir, "session", "session.db")
    message_dir = os.path.join(db_dir, "message")
    return os.path.isfile(session_db) and os.path.isdir(message_dir)


def _candidate_patterns():
    home = os.path.expanduser("~")
    docs = os.path.join(home, "Documents")
    localapp = os.environ.get("LOCALAPPDATA", "")

    patterns = [
        os.path.join(docs, "WeChat Files", "*", "db_storage"),
        os.path.join(docs, "Tencent Files", "*", "db_storage"),
        os.path.join(docs, "xwechat_files", "*", "db_storage"),
        os.path.join(localapp, "Tencent", "WeChat", "xwechat_files", "*", "db_storage"),
    ]

    for d in "CDEFGHIJKLMNOPQRSTUVWXYZ":
        root = f"{d}:\\"
        if not os.path.exists(root):
            continue
        patterns.extend(
            [
                os.path.join(root, "wcfile", "xwechat_files", "*", "db_storage"),
                os.path.join(root, "xwechat_files", "*", "db_storage"),
            ]
        )
    return patterns


def _score_db_dir(db_dir):
    # Prefer active/recent account data folder.
    session_db = os.path.join(db_dir, "session", "session.db")
    mtime = os.path.getmtime(session_db) if os.path.isfile(session_db) else 0.0
    msg_count = len(glob.glob(os.path.join(db_dir, "message", "message_*.db")))
    return (mtime, msg_count)


def detect_wechat_db_dir():
    seen = set()
    candidates = []
    for pattern in _candidate_patterns():
        for p in glob.glob(pattern):
            n = _normalize(p)
            if n in seen:
                continue
            seen.add(n)
            if _looks_like_db_dir(n):
                candidates.append(n)

    if not candidates:
        return None
    candidates.sort(key=_score_db_dir, reverse=True)
    return candidates[0]


def _persist_config(cfg):
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=4)
    except Exception:
        # Non-fatal; runtime can still continue with in-memory cfg.
        pass


def load_config():
    base = _runtime_base_dir()

    if not os.path.exists(CONFIG_FILE):
        cfg = dict(_DEFAULT)
        _persist_config(cfg)
    else:
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                cfg = json.load(f)
        except Exception:
            cfg = dict(_DEFAULT)

    for k, v in _DEFAULT.items():
        if k not in cfg:
            cfg[k] = v

    cfg["web_port"] = _parse_port(cfg.get("web_port"), _DEFAULT["web_port"])

    # Resolve relative paths.
    for key in ("keys_file", "decrypted_dir"):
        val = str(cfg.get(key, "") or "")
        if val and not os.path.isabs(val):
            cfg[key] = os.path.join(base, val)

    db_dir = str(cfg.get("db_dir", "") or "").strip()
    if _is_placeholder_db_dir(db_dir) or not _looks_like_db_dir(db_dir):
        detected = detect_wechat_db_dir()
        if detected:
            cfg["db_dir"] = detected
            _persist_config(cfg)

    return cfg
