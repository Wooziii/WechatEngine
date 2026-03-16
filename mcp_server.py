r"""
WeChat MCP Server - query WeChat messages, contacts via Claude

Based on FastMCP (stdio transport), reuses existing decryption.
Runs on Windows Python (needs access to D:\ WeChat databases).
"""

import os, sys, json, time, sqlite3, tempfile, struct, hashlib, atexit, re, csv
import hmac as hmac_mod
from datetime import datetime
from collections import Counter, defaultdict
from Crypto.Cipher import AES
try:
    from mcp.server.fastmcp import FastMCP
except ImportError:
    class FastMCP:  # type: ignore[override]
        """Minimal fallback so local query helpers can import this module without MCP."""

        def __init__(self, *_args, **_kwargs):
            pass

        def tool(self, *_args, **_kwargs):
            def decorator(func):
                return func

            return decorator

        def run(self):
            raise RuntimeError(
                "MCP runtime is unavailable. Install the `mcp` package to run stdio server mode, "
                "or use the local CLI wrapper under .codebuddy/skills for direct queries."
            )

try:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

# ============ 鍔犲瘑甯搁噺 ============
PAGE_SZ = 4096
KEY_SZ = 32
SALT_SZ = 16
RESERVE_SZ = 80
SQLITE_HDR = b'SQLite format 3\x00'
WAL_HEADER_SZ = 32
WAL_FRAME_HEADER_SZ = 24

# ============ 閰嶇疆鍔犺浇 ============
def _runtime_base_dir():
    # In PyInstaller one-file mode, keep writable runtime files next to the exe.
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))

SCRIPT_DIR = _runtime_base_dir()
CONFIG_FILE = os.path.join(SCRIPT_DIR, "config.json")

with open(CONFIG_FILE) as f:
    _cfg = json.load(f)
for _key in ("keys_file", "decrypted_dir"):
    if _key in _cfg and not os.path.isabs(_cfg[_key]):
        _cfg[_key] = os.path.join(SCRIPT_DIR, _cfg[_key])

DB_DIR = _cfg["db_dir"]
KEYS_FILE = _cfg["keys_file"]
DECRYPTED_DIR = _cfg["decrypted_dir"]
RUNTIME_TMP_DIR = os.path.join(SCRIPT_DIR, "logs", "runtime_tmp")
EXPORT_CHAT_MD_DIR = os.path.join(SCRIPT_DIR, "exports", "chat_markdown")

with open(KEYS_FILE) as f:
    ALL_KEYS = json.load(f)

# ============ 瑙ｅ瘑鍑芥暟 ============

def decrypt_page(enc_key, page_data, pgno):
    iv = page_data[PAGE_SZ - RESERVE_SZ : PAGE_SZ - RESERVE_SZ + 16]
    if pgno == 1:
        encrypted = page_data[SALT_SZ : PAGE_SZ - RESERVE_SZ]
        cipher = AES.new(enc_key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypted)
        return bytes(bytearray(SQLITE_HDR + decrypted + b'\x00' * RESERVE_SZ))
    else:
        encrypted = page_data[: PAGE_SZ - RESERVE_SZ]
        cipher = AES.new(enc_key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypted)
        return decrypted + b'\x00' * RESERVE_SZ


def full_decrypt(db_path, out_path, enc_key):
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
    return total_pages


def decrypt_wal(wal_path, out_path, enc_key):
    if not os.path.exists(wal_path):
        return 0
    wal_size = os.path.getsize(wal_path)
    if wal_size <= WAL_HEADER_SZ:
        return 0
    frame_size = WAL_FRAME_HEADER_SZ + PAGE_SZ
    patched = 0
    with open(wal_path, 'rb') as wf, open(out_path, 'r+b') as df:
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
            if pgno == 0 or pgno > 1000000:
                continue
            if frame_salt1 != wal_salt1 or frame_salt2 != wal_salt2:
                continue
            dec = decrypt_page(enc_key, ep, pgno)
            df.seek((pgno - 1) * PAGE_SZ)
            df.write(dec)
            patched += 1
    return patched


# ============ DB 缂撳瓨 ============


def _ensure_dir(path):
    os.makedirs(path, exist_ok=True)
    return path


def _safe_filename(text, default="chat"):
    value = re.sub(r"[\\/:*?\"<>|]+", "_", str(text or "").strip())
    value = value.strip(" ._")
    return value or str(default)


def _cleanup_runtime_temp_files(max_age_hours=0.5):
    now = time.time()
    tmp_dir = _ensure_dir(RUNTIME_TMP_DIR)
    for name in os.listdir(tmp_dir):
        if not name.lower().endswith(".db"):
            continue
        if not (name.startswith("wechat_mcp_") or name.startswith("wechat_emoticon_")):
            continue
        path = os.path.join(tmp_dir, name)
        try:
            if now - os.path.getmtime(path) < max_age_hours * 3600:
                continue
            os.unlink(path)
        except OSError:
            pass

class DBCache:
    """缓存解密后的数据库，通过 mtime 判断是否需要重新解密。"""

    def __init__(self):
        self._cache = {}  # rel_key -> (db_mtime, wal_mtime, tmp_path)

    def get(self, rel_key):
        if rel_key not in ALL_KEYS:
            return None
        rel_path = rel_key.replace('\\', os.sep)
        db_path = os.path.join(DB_DIR, rel_path)
        wal_path = db_path + "-wal"
        if not os.path.exists(db_path):
            return None

        try:
            db_mtime = os.path.getmtime(db_path)
            wal_mtime = os.path.getmtime(wal_path) if os.path.exists(wal_path) else 0
        except OSError:
            return None

        if rel_key in self._cache:
            c_db_mt, c_wal_mt, c_path = self._cache[rel_key]
            if c_db_mt == db_mtime and c_wal_mt == wal_mtime and os.path.exists(c_path):
                return c_path
            try:
                os.unlink(c_path)
            except OSError:
                pass

        enc_key = bytes.fromhex(ALL_KEYS[rel_key]["enc_key"])
        _ensure_dir(RUNTIME_TMP_DIR)
        fd, tmp_path = tempfile.mkstemp(prefix='wechat_mcp_', suffix='.db', dir=RUNTIME_TMP_DIR)
        os.close(fd)
        full_decrypt(db_path, tmp_path, enc_key)
        if os.path.exists(wal_path):
            decrypt_wal(wal_path, tmp_path, enc_key)
        self._cache[rel_key] = (db_mtime, wal_mtime, tmp_path)
        return tmp_path

    def cleanup(self):
        for _, _, path in self._cache.values():
            try:
                os.unlink(path)
            except OSError:
                pass
        self._cache.clear()


_cache = DBCache()
_cleanup_runtime_temp_files()
atexit.register(_cache.cleanup)


# ============ 鑱旂郴浜虹紦瀛?============

_contact_names = None  # {username: display_name}
_contact_full = None   # [{username, nick_name, remark}]


def _load_contacts_from(db_path):
    names = {}
    full = []
    conn = sqlite3.connect(db_path)
    try:
        for r in conn.execute("SELECT username, nick_name, remark FROM contact").fetchall():
            uname, nick, remark = r
            display = remark if remark else nick if nick else uname
            names[uname] = display
            full.append({'username': uname, 'nick_name': nick or '', 'remark': remark or ''})
    finally:
        conn.close()
    return names, full


def get_contact_names():
    global _contact_names, _contact_full
    if _contact_names is not None:
        return _contact_names

    # 浼樺厛鐢ㄥ凡瑙ｅ瘑鐨?contact.db
    pre_decrypted = os.path.join(DECRYPTED_DIR, "contact", "contact.db")
    if os.path.exists(pre_decrypted):
        try:
            _contact_names, _contact_full = _load_contacts_from(pre_decrypted)
            return _contact_names
        except Exception:
            pass

    # 瀹炴椂瑙ｅ瘑
    path = _cache.get("contact\\contact.db")
    if path:
        try:
            _contact_names, _contact_full = _load_contacts_from(path)
            return _contact_names
        except Exception:
            pass

    return {}


def get_contact_full():
    global _contact_full
    if _contact_full is None:
        get_contact_names()
    return _contact_full or []


# ============ 杈呭姪鍑芥暟 ============

def format_msg_type(t):
    return {
        1: '文本', 3: '图片', 34: '语音', 42: '名片',
        43: '视频', 47: '表情', 48: '位置', 49: '链接/文件',
        50: '通话', 10000: '系统', 10002: '撤回',
    }.get(t, f'type={t}')


def _clamp_int(value, default, min_value=None, max_value=None):
    try:
        n = int(value)
    except Exception:
        n = int(default)
    if min_value is not None and n < min_value:
        n = min_value
    if max_value is not None and n > max_value:
        n = max_value
    return n


def resolve_username(chat_name):
    """将聊天名/备注名/wxid 解析为 username。"""
    names = get_contact_names()

    # 直接就是 username
    if chat_name in names or chat_name.startswith('wxid_') or '@chatroom' in chat_name:
        return chat_name

    # 模糊匹配（优先精确）
    chat_lower = chat_name.lower()
    for uname, display in names.items():
        if chat_lower == display.lower():
            return uname
    for uname, display in names.items():
        if chat_lower in display.lower():
            return uname

    return None


def _parse_message_content(content, local_type, is_group):
    """瑙ｆ瀽娑堟伅鍐呭锛岃繑鍥?(sender_id, text)"""
    if content is None:
        return '', ''
    if isinstance(content, bytes):
        return '', '(鍘嬬缉鍐呭)'

    sender = ''
    text = content
    if is_group and ':\n' in content:
        sender, text = content.split(':\n', 1)

    return sender, text


def _load_name2id_maps(conn):
    """Load Name2Id rowid<->username mappings from message DB."""
    id2username = {}
    username2ids = {}
    try:
        rows = conn.execute("SELECT rowid, user_name FROM Name2Id").fetchall()
    except Exception:
        rows = []
    for rid, uname in rows:
        if not uname:
            continue
        name = str(uname).strip()
        if not name:
            continue
        rid_i = int(rid)
        id2username[rid_i] = name
        username2ids.setdefault(name, []).append(rid_i)
    return id2username, username2ids


def _dedup_keep_order(items):
    seen = set()
    out = []
    for x in items:
        if x in seen:
            continue
        seen.add(x)
        out.append(x)
    return out


def _resolve_sender_candidates(sender_query, contact_names, known_usernames):
    """Resolve sender input to candidate usernames in a group."""
    q = str(sender_query or "").strip()
    if not q:
        return []
    ql = q.lower()
    known = [u for u in known_usernames if isinstance(u, str) and u]

    # Exact username
    exact_user = [u for u in known if u.lower() == ql]
    if exact_user:
        return _dedup_keep_order(exact_user)

    # Exact display name
    exact_display = []
    for u in known:
        d = str(contact_names.get(u, u) or u).lower()
        if d == ql:
            exact_display.append(u)
    if exact_display:
        return _dedup_keep_order(exact_display)

    # Partial match (username/display)
    partial = []
    for u in known:
        d = str(contact_names.get(u, u) or u).lower()
        if ql in u.lower() or ql in d:
            partial.append(u)
    return _dedup_keep_order(partial)


# 娑堟伅 DB 鐨?rel_keys锛堟帓闄?fts/resource/media/biz锛?
MSG_DB_KEYS = sorted([
    k for k in ALL_KEYS
    if k.startswith("message\\message_") and k.endswith(".db")
    and "fts" not in k and "resource" not in k
])


def _find_msg_table_for_user(username):
    """鍦ㄦ墍鏈?message_N.db 涓煡鎵剧敤鎴风殑娑堟伅琛紝杩斿洖 (db_path, table_name)"""
    table_hash = hashlib.md5(username.encode()).hexdigest()
    table_name = f"Msg_{table_hash}"

    for rel_key in MSG_DB_KEYS:
        path = _cache.get(rel_key)
        if not path:
            continue
        conn = sqlite3.connect(path)
        try:
            exists = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                (table_name,)
            ).fetchone()
            if exists:
                conn.close()
                return path, table_name
        except Exception:
            pass
        finally:
            conn.close()

    return None, None


# ============ 分析辅助函数 ============

_group_member_count_cache = None  # {chatroom_username: member_count}


def _json_result(data):
    """Return UTF-8 friendly JSON string for LLM tools."""
    return json.dumps(data, ensure_ascii=False)


def _norm_ts_range(start_ts, end_ts):
    start_ts = _clamp_int(start_ts, 0, 0, None)
    end_ts = _clamp_int(end_ts, 0, 0, None)
    if start_ts and end_ts and start_ts > end_ts:
        start_ts, end_ts = end_ts, start_ts
    return start_ts, end_ts


def _get_group_member_count_map():
    global _group_member_count_cache
    if _group_member_count_cache is not None:
        return _group_member_count_cache

    contact_path = _cache.get("contact\\contact.db")
    if not contact_path:
        _group_member_count_cache = {}
        return _group_member_count_cache

    conn = sqlite3.connect(contact_path)
    out = {}
    try:
        rows = conn.execute(
            """
            SELECT c.username, COUNT(m.member_id) AS member_count
            FROM chat_room c
            LEFT JOIN chatroom_member m ON m.room_id = c.id
            GROUP BY c.username
            """
        ).fetchall()
        for username, cnt in rows:
            if username and "@chatroom" in str(username):
                out[str(username)] = int(cnt or 0)
    except Exception:
        out = {}
    finally:
        conn.close()

    _group_member_count_cache = out
    return _group_member_count_cache


def _get_session_last_active_map():
    path = _cache.get("session\\session.db")
    if not path:
        return {}
    conn = sqlite3.connect(path)
    try:
        rows = conn.execute(
            """
            SELECT username, last_timestamp
            FROM SessionTable
            WHERE last_timestamp > 0
            """
        ).fetchall()
        return {str(u): int(ts or 0) for u, ts in rows if u}
    except Exception:
        return {}
    finally:
        conn.close()


def _get_group_usernames():
    # Prefer contact db chat_room table as canonical source.
    groups = set()
    member_map = _get_group_member_count_map()
    for u in member_map.keys():
        if "@chatroom" in u:
            groups.add(u)
    # Fallback: also include session entries.
    for u in _get_session_last_active_map().keys():
        if "@chatroom" in u:
            groups.add(u)
    return sorted(groups)


def _strip_sender_prefix(content, is_group):
    if content is None:
        return ""
    if isinstance(content, bytes):
        return ""
    text = str(content)
    if is_group and ":\n" in text:
        return text.split(":\n", 1)[1]
    return text


def _get_table_columns(conn, table_name):
    cols = set()
    try:
        for r in conn.execute(f"PRAGMA table_info([{table_name}])").fetchall():
            if len(r) >= 2 and r[1]:
                cols.add(str(r[1]))
    except Exception:
        pass
    return cols


def _build_msg_where(start_ts=0, end_ts=0, skip_compress=True):
    where_parts = []
    params = []
    if skip_compress:
        where_parts.append("(WCDB_CT_message_content = 0 OR WCDB_CT_message_content IS NULL)")
    if start_ts:
        where_parts.append("create_time >= ?")
        params.append(int(start_ts))
    if end_ts:
        where_parts.append("create_time <= ?")
        params.append(int(end_ts))
    if not where_parts:
        where_parts.append("1=1")
    return " AND ".join(where_parts), params


def _sender_expr_for_sql(is_group, has_sender_col):
    if is_group and has_sender_col:
        return "CAST(real_sender_id AS TEXT)"
    return "CASE WHEN status=2 THEN '__self__' ELSE '__peer__' END"


def _load_topic_stopwords():
    # Minimal stopword set tuned for group-chat topics.
    return {
        "", "的", "了", "是", "我", "你", "他", "她", "它", "我们", "你们", "他们",
        "这个", "那个", "然后", "就是", "还有", "一下", "一个", "没有", "可以", "不是",
        "今天", "昨天", "明天", "现在", "已经", "真的", "哈哈", "哈哈哈", "哈哈哈哈",
        "wxid", "chatroom", "http", "https", "com", "cn", "www", "amp",
        "大家", "老师", "同学", "朋友", "群里", "群友", "消息", "内容", "文本",
    }


def _keyword_tokens(text):
    # Keep Chinese 2+ chars and alpha-numeric words 3+.
    zh = re.findall(r"[\u4e00-\u9fff]{2,}", text)
    en = re.findall(r"[A-Za-z][A-Za-z0-9_+-]{2,}", text)
    return zh + en


def _is_noise_token(tok):
    t = str(tok or "").strip()
    if not t:
        return True
    tl = t.lower()
    if tl.startswith("wxid_"):
        return True
    if "@chatroom" in tl:
        return True
    if tl.startswith("gh_"):
        return True
    if re.fullmatch(r"[0-9_]+", tl):
        return True
    if re.fullmatch(r"[a-f0-9]{24,}", tl):
        return True
    return False


def _extract_top_keywords(texts, topn=20, min_freq=2):
    stop = _load_topic_stopwords()
    counter = Counter()
    for text in texts:
        for tok in _keyword_tokens(text):
            tok_s = tok.strip()
            if not tok_s or tok_s in stop or _is_noise_token(tok_s):
                continue
            counter[tok_s] += 1
    out = []
    for word, cnt in counter.most_common(topn * 3):
        if cnt < min_freq:
            continue
        out.append({"topic": word, "count": int(cnt)})
        if len(out) >= topn:
            break
    return out


def _media_category(local_type):
    if local_type == 1:
        return "text"
    if local_type in (3, 34, 43, 47):
        return "media"
    if local_type == 49:
        return "link_or_file"
    if local_type in (10000, 10002):
        return "system"
    return "other"


def _classify_source(text):
    # Source tagging for shared-content stats in analysis page.
    t = str(text or "")
    tl = t.lower()

    # Strong URL/domain signals first.
    if "bilibili.com" in tl or "b23.tv" in tl or "up主" in t:
        return "B站"
    if "xiaohongshu.com" in tl or "xhslink.com" in tl or "小红书" in t or "的笔记" in t or "我发布了一篇笔记" in t:
        return "小红书"
    if "music.163.com" in tl or "网易云" in t or "分享歌手" in t:
        return "网易云"
    if "meeting.tencent.com" in tl or "腾讯会议" in t or "快速会议" in t:
        return "腾讯会议"
    if "点击领取" in t or "小程序" in t:
        return "小程序"
    if "微信红包" in t:
        return "微信红包"
    if "微信转账" in t:
        return "微信转账"
    if "#接龙" in t:
        return "微信接龙"
    if "邀请你加入群聊" in t:
        return "群聊邀请"
    if "拍了拍" in t:
        return "拍一拍"
    if "的聊天记录" in t:
        return "微信聊天记录"
    if re.search(r"\.(docx?|xlsx?|pptx?|pdf|zip|rar|7z|txt|csv)\b", tl):
        return "文件"
    if "http://" in tl or "https://" in tl:
        return "链接"
    return "其他"


def _parse_time_range_alias(time_range):
    now = int(time.time())
    alias = str(time_range or "").strip().lower()
    if alias in ("", "all", "all_time"):
        return 0, 0
    if alias in ("last_7_days", "7d", "7days"):
        return now - 7 * 86400, now
    if alias in ("last_30_days", "30d", "30days"):
        return now - 30 * 86400, now
    if alias in ("last_180_days", "180d", "half_year"):
        return now - 180 * 86400, now
    if alias in ("last_365_days", "365d", "1y", "year"):
        return now - 365 * 86400, now
    return 0, 0


SCORE_RULES = [
    {"id": "r_msg_once", "name": "Message once", "points": 1, "cap_desc": "Max 5/day", "manual": False, "desc": "Score 1 per message, capped at 5 points per day."},
    {"id": "r_day_ge5", "name": "Daily messages >= 5", "points": 5, "cap_desc": "Once/day", "manual": False, "desc": "Score 5 when daily message count reaches at least 5."},
    {"id": "r_month_ge12", "name": "Active days >= 12 (30d)", "points": 20, "cap_desc": "Once/30d", "manual": False, "desc": "Score 20 when active days in range are at least 12."},
    {"id": "r_year_ge120", "name": "Active days >= 120 (365d)", "points": 30, "cap_desc": "Once/365d", "manual": False, "desc": "Score 30 when active days in range are at least 120."},
    {"id": "m_topic_start", "name": "Topic initiated", "points": 5, "cap_desc": "Max 3/day", "manual": True, "desc": "Manual rule: valid proactive topic initiation."},
    {"id": "m_topic_resp5", "name": "Topic responders >= 5", "points": 3, "cap_desc": "Max 3/day", "manual": True, "desc": "Manual rule: unique responders reach at least 5."},
    {"id": "m_high_quality", "name": "High-quality content", "points": 5, "cap_desc": "Max 1/day", "manual": True, "desc": "Manual rule: image-rich or high-value content."},
    {"id": "m_round_table", "name": "Roundtable participation", "points": 10, "cap_desc": "Per event", "manual": True, "desc": "Manual rule: online roundtable participation."},
    {"id": "m_group_admin", "name": "Community admin task", "points": 50, "cap_desc": "Max 1/year", "manual": True, "desc": "Manual rule: annual one-time admin contribution."},
    {"id": "m_forum_post", "name": "Forum post", "points": 3, "cap_desc": "Max 1/day", "manual": True, "desc": "Manual rule: forum post activity."},
    {"id": "m_forum_reply", "name": "Forum reply", "points": 1, "cap_desc": "Max 3/day", "manual": True, "desc": "Manual rule: forum reply activity."},
    {"id": "m_forum_top3", "name": "Forum weekly top3", "points": 20, "cap_desc": "Max 1/week", "manual": True, "desc": "Manual rule: weekly top-3 likes for post/reply."},
]
SCORE_RULE_MAP = {str(r.get("id", "")): r for r in SCORE_RULES}
MANUAL_SCORE_FILE = os.path.join(SCRIPT_DIR, "logs", "manual_score_entries.json")


def _load_manual_score_entries():
    if not os.path.exists(MANUAL_SCORE_FILE):
        return []
    try:
        with open(MANUAL_SCORE_FILE, "r", encoding="utf-8") as f:
            rows = json.load(f)
        return rows if isinstance(rows, list) else []
    except Exception:
        return []


def _resolve_sender_from_msg(is_group, has_sender_col, real_sender_id, parsed_sender, id2username):
    sid = ""
    if is_group and has_sender_col:
        try:
            rid = int(real_sender_id or 0)
        except Exception:
            rid = 0
        if rid > 0:
            sid = str(id2username.get(rid, "") or "")
    if not sid:
        sid = str(parsed_sender or "").strip()
    return sid


def _looks_like_topic_seed(text):
    t = str(text or "").strip()
    if len(t) < 8:
        return False
    tl = t.lower()
    if "http://" in tl or "https://" in tl:
        return False
    cues = ("?", "discuss", "anyone", "how to", "share", "experience", "thoughts")
    if any(c in tl for c in cues):
        return True
    # Also keep common Chinese question/interaction cues.
    zh_cues = ("\uFF1F", "\u8bf7\u95ee", "\u5927\u5bb6", "\u4f60\u4eec", "\u600e\u4e48\u770b", "\u6709\u6ca1\u6709", "\u8ba8\u8bba", "\u804a\u804a", "\u5206\u4eab", "\u6c42\u63a8\u8350", "\u7ecf\u9a8c")
    if any(c in t for c in zh_cues):
        return True
    return len(t) >= 24 and any(p in t for p in ("\u3002", "\uFF01", "!", "\uFF1B", ";"))


def _clean_candidate_text(text):
    t = str(text or "").strip()
    if not t:
        return ""
    t = re.sub(r"<[^>]+>", " ", t)
    t = re.sub(r"\s+", " ", t).strip()
    return t


def _is_placeholder_text(text):
    t = str(text or "").strip()
    if not t:
        return True
    if re.fullmatch(r"\[[^\]]{1,20}\]", t):
        return True
    if t in ("图片", "视频", "语音", "表情", "链接/文件"):
        return True
    return False


def _score_high_quality_text(text, local_type):
    t = _clean_candidate_text(text)
    lt = int(local_type or 0)
    tl = t.lower()
    text_len = len(t)
    has_url = bool(re.search(r"https?://|www\.", tl))
    has_bullet = bool(re.search(r"(^|[\n ])(\d+[\.、]|[-•])", t))
    punc_cnt = sum(t.count(c) for c in ("。", "；", "：", "!", "！", "?", "？", ",", "，", "\n"))
    info_terms = (
        "方案", "步骤", "总结", "建议", "实战", "经验", "工具", "配置", "部署",
        "安全", "架构", "案例", "流程", "指标", "成本", "收益", "排查", "复盘",
        "教程", "文档", "链接", "资料", "模板", "清单",
    )
    info_hits = sum(1 for kw in info_terms if kw in t)
    has_media = lt in (3, 43, 47)
    is_link = lt == 49 or has_url

    score = 0
    if text_len >= 50:
        score += 28
    elif text_len >= 30:
        score += 15
    elif text_len >= 18:
        score += 8
    if has_bullet:
        score += 12
    if punc_cnt >= 3:
        score += 8
    score += min(24, info_hits * 4)
    if has_media:
        score += 20
    if is_link:
        score += 12
    if has_url and text_len <= 14:
        score -= 12
    if _is_placeholder_text(t):
        score = max(0, score - 30)

    score = max(0, min(100, int(round(score))))
    return {
        "score": score,
        "text_len": text_len,
        "has_url": has_url,
        "has_media": has_media,
        "has_bullet": has_bullet,
        "info_hits": info_hits,
    }


_EMOTION_LEXICON = {
    "joy": ("开心", "太好了", "好耶", "收获", "感谢", "赞", "牛", "厉害", "稳", "喜欢", "兴奋", "期待"),
    "warm": ("谢谢", "辛苦", "感恩", "支持", "欢迎", "抱拳", "感谢分享", "安排上", "有帮助"),
    "anxious": ("焦虑", "担心", "慌", "怕", "顶不住", "难受", "压力", "卡住"),
    "angry": ("无语", "烦", "离谱", "生气", "恼火", "气死", "扯", "受不了"),
    "complaint": ("bug", "崩", "报错", "出问题", "不行", "失败", "翻车", "投诉", "吐槽", "垃圾"),
    "tired": ("累", "困", "熬夜", "疲惫", "顶不动", "下班", "睡了"),
}

_RISK_KEYWORDS = {
    "compliance": ("违规", "封号", "举报", "侵权", "敏感", "违法", "风险", "审核", "投诉"),
    "bug": ("bug", "报错", "崩", "挂了", "异常", "失败", "卡死", "进不去", "404", "500"),
    "refund": ("退款", "退钱", "赔付", "理赔", "售后", "维权", "差评"),
    "spam": ("加我", "私聊", "vx", "vx:", "二维码", "加群", "拉群", "代理", "兼职", "推广", "返利"),
}


def _emotion_signal_from_text(text):
    t = _clean_candidate_text(text)
    if not t:
        return {"polarity": "neutral", "label": "平稳", "score": 0}

    pos_hits = 0
    neg_hits = 0
    label_scores = {}
    for label, words in _EMOTION_LEXICON.items():
        score = 0
        for w in words:
            if w in t:
                score += 1
        if score:
            label_scores[label] = score
            if label in ("joy", "warm"):
                pos_hits += score
            else:
                neg_hits += score

    if pos_hits > neg_hits:
        polarity = "positive"
    elif neg_hits > pos_hits:
        polarity = "negative"
    else:
        polarity = "neutral"

    label_map = {
        "joy": "兴奋/认可",
        "warm": "友好/感谢",
        "anxious": "焦虑/担忧",
        "angry": "不满/冲突",
        "complaint": "吐槽/故障",
        "tired": "疲惫/收尾",
    }
    top_label = max(label_scores.items(), key=lambda x: x[1])[0] if label_scores else "joy"
    raw_score = pos_hits - neg_hits
    return {
        "polarity": polarity,
        "label": label_map.get(top_label, "平稳"),
        "score": int(raw_score),
    }


def _risk_hits_from_text(text):
    t = _clean_candidate_text(text)
    if not t:
        return []
    tl = t.lower()
    hits = []
    for key, words in _RISK_KEYWORDS.items():
        for w in words:
            if w.lower() in tl:
                hits.append(key)
                break
    return hits


def _resolve_sender_ids(conn, sender_query, contact_names):
    id2username, username2ids = _load_name2id_maps(conn)
    known_usernames = list(id2username.values())
    candidates = _resolve_sender_candidates(sender_query, contact_names, known_usernames)
    sender_query_raw = str(sender_query or "").strip()
    if (not candidates) and (sender_query_raw.startswith("wxid_") or "@chatroom" in sender_query_raw):
        candidates = [sender_query_raw]

    candidate_ids = []
    for u in candidates:
        candidate_ids.extend(username2ids.get(u, []))
    candidate_ids = _dedup_keep_order(candidate_ids)
    return candidates, candidate_ids, id2username


def _parse_bool_tokens(expr):
    # Split boolean expression into operators/tokens.
    raw = re.findall(r"\(|\)|\bAND\b|\bOR\b|\bNOT\b|[^()\s]+", expr, flags=re.IGNORECASE)
    tokens = []
    for tok in raw:
        up = tok.upper()
        if up in ("AND", "OR", "NOT", "(", ")"):
            tokens.append(up)
        else:
            tokens.append(tok)
    return tokens


def _bool_to_postfix(tokens):
    prec = {"NOT": 3, "AND": 2, "OR": 1}
    out = []
    stack = []
    for tok in tokens:
        if tok == "(":
            stack.append(tok)
        elif tok == ")":
            while stack and stack[-1] != "(":
                out.append(stack.pop())
            if stack and stack[-1] == "(":
                stack.pop()
        elif tok in ("AND", "OR", "NOT"):
            while stack and stack[-1] in prec and prec[stack[-1]] >= prec[tok]:
                out.append(stack.pop())
            stack.append(tok)
        else:
            out.append(tok)
    while stack:
        out.append(stack.pop())
    return out


def _eval_postfix_bool(postfix, text):
    s = []
    tl = text.lower()
    for tok in postfix:
        if tok == "NOT":
            a = bool(s.pop()) if s else False
            s.append(not a)
        elif tok in ("AND", "OR"):
            b = bool(s.pop()) if s else False
            a = bool(s.pop()) if s else False
            if tok == "AND":
                s.append(a and b)
            else:
                s.append(a or b)
        else:
            s.append(tok.lower() in tl)
    return bool(s[-1]) if s else False


# ============ MCP Server ============

mcp = FastMCP("wechat", instructions="查询微信消息、联系人等数据")

# 鏂版秷鎭拷韪?
_last_check_state = {}  # {username: last_timestamp}


@mcp.tool()
def get_recent_sessions(limit: int = 200) -> str:
    """获取最近会话列表（用于快速定位热点会话）。

    Args:
        limit: 返回会话数，默认 200，最大 2000
    """
    limit = _clamp_int(limit, 200, 1, 2000)

    path = _cache.get("session\\session.db")
    if not path:
        return "错误: 无法解密 session.db"

    names = get_contact_names()
    conn = sqlite3.connect(path)
    rows = conn.execute(
        """
        SELECT username, unread_count, summary, last_timestamp,
               last_msg_type, last_msg_sender, last_sender_display_name
        FROM SessionTable
        WHERE last_timestamp > 0
        ORDER BY last_timestamp DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()
    conn.close()

    results = []
    for r in rows:
        username, unread, summary, ts, msg_type, sender, sender_name = r
        display = names.get(username, username)
        is_group = "@chatroom" in username

        if isinstance(summary, str) and ":\n" in summary:
            summary = summary.split(":\n", 1)[1]
        elif isinstance(summary, bytes):
            summary = "(压缩内容)"

        sender_display = ""
        if is_group and sender:
            sender_display = names.get(sender, sender_name or sender)

        time_str = datetime.fromtimestamp(ts).strftime("%m-%d %H:%M")

        entry = f"[{time_str}] {display}"
        if is_group:
            entry += " [群]"
        if unread and unread > 0:
            entry += f" ({unread}条未读)"
        entry += f"\n  {format_msg_type(msg_type)}: "
        if sender_display:
            entry += f"{sender_display}: "
        entry += str(summary or "(无内容)")
        results.append(entry)

    return f"最近 {len(results)} 个会话:\n\n" + "\n\n".join(results)


@mcp.tool()
def get_chat_history(
    chat_name: str,
    limit: int = 40000,
    offset: int = 0,
    start_ts: int = 0,
    end_ts: int = 0,
    max_chars: int = 500000,
) -> str:
    """获取指定聊天的消息记录（支持大样本分页和时间范围）。

    Args:
        chat_name: 聊天对象的名字、备注名或 wxid
        limit: 返回消息条数，默认 40000，最大 200000；小于40000时会自动提升到40000
        offset: 分页偏移量，默认 0
        start_ts: 起始时间（unix 秒），0 表示不限制
        end_ts: 结束时间（unix 秒），0 表示不限制
        max_chars: 返回文本最大字符数，默认 500000（避免模型输入过长）
    """
    limit = _clamp_int(limit, 40000, 1, 200000)
    offset = _clamp_int(offset, 0, 0, 2_000_000)
    start_ts = _clamp_int(start_ts, 0, 0, None)
    end_ts = _clamp_int(end_ts, 0, 0, None)
    max_chars = _clamp_int(max_chars, 500000, 100000, 900000)
    if start_ts and end_ts and start_ts > end_ts:
        start_ts, end_ts = end_ts, start_ts

    username = resolve_username(chat_name)
    if not username:
        return f"找不到聊天对象: {chat_name}\n提示: 可先用 get_contacts(query='{chat_name}') 搜索"

    names = get_contact_names()
    display_name = names.get(username, username)
    is_group = '@chatroom' in username

    db_path, table_name = _find_msg_table_for_user(username)
    if not db_path:
        return f"找不到 {display_name} 的消息记录（可能未解密或无消息）"

    conn = sqlite3.connect(db_path)
    try:
        where_parts = ["(WCDB_CT_message_content = 0 OR WCDB_CT_message_content IS NULL)"]
        params = []
        if start_ts:
            where_parts.append("create_time >= ?")
            params.append(start_ts)
        if end_ts:
            where_parts.append("create_time <= ?")
            params.append(end_ts)

        where_sql = " AND ".join(where_parts)
        total_count = int(
            conn.execute(
                f"SELECT COUNT(1) FROM [{table_name}] WHERE {where_sql}",
                tuple(params),
            ).fetchone()[0]
            or 0
        )
        rows = conn.execute(
            f"""
            SELECT local_type, create_time, message_content, WCDB_CT_message_content
            FROM [{table_name}]
            WHERE {where_sql}
            ORDER BY create_time DESC
            LIMIT ? OFFSET ?
            """,
            tuple(params + [limit + 1, offset])
        ).fetchall()
    except Exception as e:
        conn.close()
        return f"查询失败: {e}"
    conn.close()

    has_more_by_limit = len(rows) > limit
    if has_more_by_limit:
        rows = rows[:limit]
    page_row_count = len(rows)

    if not rows:
        return f"{display_name} 无消息记录"

    lines = []
    emitted_chars = 0
    truncated_by_chars = False
    for local_type, create_time, content, _ct in rows:
        time_str = datetime.fromtimestamp(create_time).strftime('%m-%d %H:%M')
        sender, text = _parse_message_content(content, local_type, is_group)

        if local_type != 1:
            type_label = format_msg_type(local_type)
            text = f"[{type_label}] {text}" if text else f"[{type_label}]"

        if text and len(text) > 500:
            text = text[:500] + "..."

        if is_group and sender:
            sender_name = names.get(sender, sender)
            line = f"[{time_str}] {sender_name}: {text}"
        else:
            line = f"[{time_str}] {text}"

        need = len(line) + 1
        if emitted_chars + need > max_chars:
            truncated_by_chars = True
            break
        lines.append(line)
        emitted_chars += need

    header = (
        f"{display_name} 的消息: 总命中 {total_count} 条，"
        f"本页 {len(lines)} 条 (limit={limit}, offset={offset}"
    )
    if start_ts:
        header += f", start_ts={start_ts}"
    if end_ts:
        header += f", end_ts={end_ts}"
    header += ")"
    if is_group:
        header += " [群聊]"
    has_more = has_more_by_limit or ((offset + page_row_count) < total_count)
    if truncated_by_chars:
        header += f"\n提示: 输出达到大小上限 (max_chars={max_chars})，已截断。"
    if has_more:
        header += f"\n提示: 还有更多记录，建议继续调用 offset={offset + page_row_count}"
    return header + ":\n\n" + "\n".join(lines)


@mcp.tool()
def get_sender_messages(
    chat_name: str,
    sender: str,
    limit: int = 2000,
    offset: int = 0,
    start_ts: int = 0,
    end_ts: int = 0,
    max_chars: int = 500000,
    context_before: int = -1,
    context_after: int = -1,
) -> str:
    """按发言人筛选群聊消息，适合做人物画像/行为分析。

    Args:
        chat_name: 群名/备注/wxid
        sender: 发言人（可填备注、昵称或 wxid）
        limit: 返回条数，默认 2000，最大 20000
        offset: 分页偏移量，默认 0
        start_ts: 起始时间（unix 秒），0 表示不限制
        end_ts: 结束时间（unix 秒），0 表示不限制
        max_chars: 返回文本最大字符数，默认 500000（避免模型输入过长）
        context_before: 前置上下文条数。-1 表示自动智能调整，0 表示不带前文
        context_after: 后置上下文条数。-1 表示自动智能调整，0 表示不带后文
    """
    if not sender or not str(sender).strip():
        return "请提供 sender（发言人）"

    limit = _clamp_int(limit, 2000, 1, 20000)
    offset = _clamp_int(offset, 0, 0, 2_000_000)
    start_ts = _clamp_int(start_ts, 0, 0, None)
    end_ts = _clamp_int(end_ts, 0, 0, None)
    max_chars = _clamp_int(max_chars, 500000, 100000, 900000)
    context_before = _clamp_int(context_before, -1, -1, 60)
    context_after = _clamp_int(context_after, -1, -1, 60)
    if start_ts and end_ts and start_ts > end_ts:
        start_ts, end_ts = end_ts, start_ts

    username = resolve_username(chat_name)
    if not username:
        return f"找不到聊天对象: {chat_name}\n提示: 可先用 get_contacts(query='{chat_name}') 搜索"

    names = get_contact_names()
    display_name = names.get(username, username)
    is_group = "@chatroom" in username

    db_path, table_name = _find_msg_table_for_user(username)
    if not db_path:
        return f"找不到 {display_name} 的消息记录（可能未解密或无消息）"

    conn = sqlite3.connect(db_path)
    try:
        id2username, username2ids = _load_name2id_maps(conn)
        known_usernames = list(id2username.values())
        candidates = _resolve_sender_candidates(sender, names, known_usernames)

        sender_query_raw = str(sender).strip()
        if (not candidates) and (sender_query_raw.startswith("wxid_") or "@chatroom" in sender_query_raw):
            candidates = [sender_query_raw]

        if not candidates:
            ql = sender_query_raw.lower()
            hints = []
            for u in known_usernames:
                d = str(names.get(u, u) or u)
                if ql in u.lower() or ql in d.lower():
                    hints.append(d)
                if len(hints) >= 8:
                    break
            hint_text = f"\n可尝试: {', '.join(_dedup_keep_order(hints))}" if hints else ""
            return f"未识别到发言人: {sender_query_raw}{hint_text}"

        candidate_ids = []
        for u in candidates:
            candidate_ids.extend(username2ids.get(u, []))
        candidate_ids = _dedup_keep_order(candidate_ids)

        where_parts = ["(WCDB_CT_message_content = 0 OR WCDB_CT_message_content IS NULL)"]
        where_params = []
        if start_ts:
            where_parts.append("create_time >= ?")
            where_params.append(start_ts)
        if end_ts:
            where_parts.append("create_time <= ?")
            where_params.append(end_ts)

        sender_clauses = []
        sender_params = []
        if candidate_ids:
            placeholders = ",".join(["?"] * len(candidate_ids))
            sender_clauses.append(f"real_sender_id IN ({placeholders})")
            sender_params.extend(candidate_ids)
        for uname in candidates[:12]:
            sender_clauses.append("message_content LIKE ?")
            sender_params.append(f"{uname}:\n%")

        if sender_clauses:
            where_parts.append("(" + " OR ".join(sender_clauses) + ")")
        else:
            where_parts.append("message_content LIKE ?")
            where_params.append(f"%{sender_query_raw}:%")

        where_sql = " AND ".join(where_parts)
        all_params = tuple(where_params + sender_params)

        total_count = int(
            conn.execute(
                f"SELECT COUNT(1) FROM [{table_name}] WHERE {where_sql}",
                all_params,
            ).fetchone()[0]
            or 0
        )

        rows = conn.execute(
            f"""
            SELECT local_id, local_type, create_time, message_content, real_sender_id, WCDB_CT_message_content
            FROM [{table_name}]
            WHERE {where_sql}
            ORDER BY create_time DESC
            LIMIT ? OFFSET ?
            """,
            tuple(list(all_params) + [limit + 1, offset]),
        ).fetchall()

        anchor_rows = rows[:limit]
        anchor_ids = [int(r[0]) for r in anchor_rows if isinstance(r[0], int)]
        anchor_set = set(anchor_ids)

        # Smart context sizing:
        # - adapts to conversation density
        # - constrained by max_chars and anchor count
        auto_ctx = context_before < 0 or context_after < 0
        if auto_ctx:
            anchor_count = max(1, len(anchor_rows))
            ts_vals = [int(r[2]) for r in anchor_rows[:300] if isinstance(r[2], int)]
            deltas = []
            for i in range(1, len(ts_vals)):
                d = abs(ts_vals[i - 1] - ts_vals[i])
                if d > 0:
                    deltas.append(d)
            if deltas:
                ds = sorted(deltas)
                median_delta = ds[len(ds) // 2]
            else:
                median_delta = 3600

            if median_delta <= 20:
                base_ctx = 50
            elif median_delta <= 60:
                base_ctx = 40
            elif median_delta <= 180:
                base_ctx = 30
            elif median_delta <= 600:
                base_ctx = 22
            elif median_delta <= 1800:
                base_ctx = 14
            else:
                base_ctx = 8

            if total_count <= 200:
                base_ctx = max(base_ctx, 40)
            elif total_count <= 1000:
                base_ctx = max(base_ctx, 24)
            elif total_count >= 20000:
                base_ctx = min(base_ctx, 10)
            elif total_count >= 5000:
                base_ctx = min(base_ctx, 16)

            if anchor_count > 3000:
                base_ctx = min(base_ctx, 2)
            elif anchor_count > 1000:
                base_ctx = min(base_ctx, 4)
            elif anchor_count > 300:
                base_ctx = min(base_ctx, 8)

            max_lines_budget = max(240, int(max_chars / 120))
            per_anchor_budget = max(2, max_lines_budget // anchor_count)
            budget_ctx = max(1, min(60, per_anchor_budget // 2))
            auto_val = max(2, min(base_ctx, budget_ctx))

            if context_before < 0:
                context_before = auto_val
            if context_after < 0:
                context_after = auto_val

        context_rows = []
        if anchor_rows and (context_before > 0 or context_after > 0):
            ranges = []
            for local_id in sorted(anchor_ids):
                lo = max(0, local_id - context_before)
                hi = local_id + context_after
                ranges.append([lo, hi])
            merged = []
            for lo, hi in ranges:
                if not merged or lo > merged[-1][1] + 1:
                    merged.append([lo, hi])
                else:
                    merged[-1][1] = max(merged[-1][1], hi)
            for lo, hi in merged:
                part = conn.execute(
                    f"""
                    SELECT local_id, local_type, create_time, message_content, real_sender_id, WCDB_CT_message_content
                    FROM [{table_name}]
                    WHERE local_id >= ? AND local_id <= ?
                    ORDER BY local_id ASC
                    """,
                    (lo, hi),
                ).fetchall()
                context_rows.extend(part)
    except Exception as e:
        conn.close()
        return f"查询失败: {e}"
    conn.close()

    has_more_by_limit = len(rows) > limit
    if has_more_by_limit:
        anchor_rows = anchor_rows[:limit]

    if not anchor_rows:
        return f"{display_name} 中未找到发言人 {sender} 的消息"

    # If context disabled, keep anchor rows only; otherwise use merged context rows.
    render_rows = anchor_rows
    if context_before > 0 or context_after > 0:
        seen_ids = set()
        uniq = []
        for r in context_rows:
            lid = int(r[0]) if isinstance(r[0], int) else None
            if lid is None or lid in seen_ids:
                continue
            seen_ids.add(lid)
            uniq.append(r)
        render_rows = uniq

    lines = []
    emitted_chars = 0
    truncated_by_chars = False
    for local_id, local_type, create_time, content, real_sender_id, _ct in render_rows:
        time_str = datetime.fromtimestamp(create_time).strftime("%m-%d %H:%M")
        sender_id, text = _parse_message_content(content, local_type, True)
        if not sender_id and isinstance(real_sender_id, int) and real_sender_id > 0:
            sender_id = id2username.get(real_sender_id, "")

        if local_type != 1:
            type_label = format_msg_type(local_type)
            text = f"[{type_label}] {text}" if text else f"[{type_label}]"

        if text and len(text) > 500:
            text = text[:500] + "..."

        sender_display = names.get(sender_id, sender_id) if sender_id else sender
        is_anchor = local_id in anchor_set
        prefix = ">> " if is_anchor else "   "
        line = f"{prefix}[{time_str}] {sender_display}: {text}"
        need = len(line) + 1
        if emitted_chars + need > max_chars:
            truncated_by_chars = True
            break
        lines.append(line)
        emitted_chars += need

    candidate_display = _dedup_keep_order([names.get(u, u) for u in candidates])
    display_tip = ", ".join(candidate_display[:6])
    header = (
        f"{display_name} 中发言人 {sender} 的消息: 总命中 {total_count} 条，"
        f"本页 {len(lines)} 条 (limit={limit}, offset={offset}"
    )
    if start_ts:
        header += f", start_ts={start_ts}"
    if end_ts:
        header += f", end_ts={end_ts}"
    header += ")"
    if display_tip:
        header += f"\n匹配到发言人: {display_tip}"
    if context_before > 0 or context_after > 0:
        header += (
            f"\n上下文模式: 已附带目标发言前 {context_before} 条、后 {context_after} 条；"
            f"目标行以 '>>' 标记"
        )
    has_more = (offset + len(anchor_rows)) < total_count
    if truncated_by_chars:
        header += f"\n提示: 输出达到大小上限 (max_chars={max_chars})，已截断。"
    if has_more:
        header += f"\n提示: 还有更多记录，建议继续调用 offset={offset + len(anchor_rows)}"
    return header + ":\n\n" + "\n".join(lines)


@mcp.tool()
def search_messages(
    keyword: str,
    limit: int = 500,
    offset: int = 0,
    start_ts: int = 0,
    end_ts: int = 0,
    chat_name: str = "",
) -> str:
    """在聊天记录中搜索关键词（支持大样本、分页、时间范围、指定会话）。

    Args:
        keyword: 搜索关键词
        limit: 返回结果条数，默认 500，最大 10000
        offset: 分页偏移量，默认 0
        start_ts: 起始时间（unix 秒），0 表示不限制
        end_ts: 结束时间（unix 秒），0 表示不限制
        chat_name: 可选。指定聊天名/备注/wxid，仅搜索该会话
    """
    if not keyword or len(keyword) < 1:
        return "请提供搜索关键词"

    limit = _clamp_int(limit, 500, 1, 10000)
    offset = _clamp_int(offset, 0, 0, 2_000_000)
    start_ts = _clamp_int(start_ts, 0, 0, None)
    end_ts = _clamp_int(end_ts, 0, 0, None)
    if start_ts and end_ts and start_ts > end_ts:
        start_ts, end_ts = end_ts, start_ts

    target_username = ""
    if chat_name:
        target_username = resolve_username(chat_name)
        if not target_username:
            return f"找不到聊天对象: {chat_name}"

    names = get_contact_names()
    results = []

    # 避免全库扫描成本失控：按目标页大小做采样上限。
    target = offset + limit
    soft_cap = max(800, min(50000, target * 3))

    for rel_key in MSG_DB_KEYS:
        if len(results) >= soft_cap:
            break

        path = _cache.get(rel_key)
        if not path:
            continue

        conn = sqlite3.connect(path)
        try:
            tables = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'Msg_%'"
            ).fetchall()

            name2id = {}
            try:
                for r in conn.execute("SELECT user_name FROM Name2Id").fetchall():
                    h = hashlib.md5(r[0].encode()).hexdigest()
                    name2id[f"Msg_{h}"] = r[0]
            except Exception:
                pass

            for (tname,) in tables:
                if len(results) >= soft_cap:
                    break

                username = name2id.get(tname, "")
                if target_username and username != target_username:
                    continue

                is_group = "@chatroom" in username
                display = names.get(username, username) if username else tname

                where_parts = [
                    "message_content LIKE ?",
                    "(WCDB_CT_message_content = 0 OR WCDB_CT_message_content IS NULL)",
                ]
                params = [f"%{keyword}%"]
                if start_ts:
                    where_parts.append("create_time >= ?")
                    params.append(start_ts)
                if end_ts:
                    where_parts.append("create_time <= ?")
                    params.append(end_ts)

                per_table_left = max(50, min(2000, soft_cap - len(results)))
                try:
                    rows = conn.execute(
                        f"""
                        SELECT local_type, create_time, message_content
                        FROM [{tname}]
                        WHERE {" AND ".join(where_parts)}
                        ORDER BY create_time DESC
                        LIMIT ?
                        """,
                        tuple(params + [per_table_left]),
                    ).fetchall()
                except Exception:
                    continue

                for local_type, ts, content in rows:
                    sender, text = _parse_message_content(content, local_type, is_group)
                    time_str = datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")
                    sender_name = ""
                    if is_group and sender:
                        sender_name = names.get(sender, sender)

                    entry = f"[{time_str}] [{display}]"
                    if sender_name:
                        entry += f" {sender_name}:"
                    entry += f" {text}"
                    if len(entry) > 500:
                        entry = entry[:500] + "..."
                    results.append((ts, entry))
        finally:
            conn.close()

    results.sort(key=lambda x: x[0], reverse=True)
    page = results[offset : offset + limit]
    entries = [r[1] for r in page]

    if not entries:
        return f"未找到包含 \"{keyword}\" 的消息"

    header = f"搜索 \"{keyword}\" 命中 {len(entries)} 条 (limit={limit}, offset={offset})"
    if chat_name:
        header += f"\n会话范围: {chat_name}"
    if start_ts:
        header += f"\nstart_ts={start_ts}"
    if end_ts:
        header += f"\nend_ts={end_ts}"
    if len(results) > (offset + limit):
        header += "\n提示: 还有更多结果，可增大 offset 继续翻页"
    
    if len(results) >= soft_cap:
        header += "\n\n[系统警告]：由于单次查询限制，仅返回了最新的部分匹配结果。若未找到您需要的信息，或者需要进行全局历史画像分析，请必须分段指定更早的 start_ts 和 end_ts 进行分页继续查询。"
        
    return header + "\n\n" + "\n\n".join(entries)


@mcp.tool()
def fix_get_chat_history(
    chat_name: str,
    limit: int = 40000,
    offset: int = 0,
    start_ts: int = 0,
    end_ts: int = 0,
    max_chars: int = 500000,
) -> str:
    """兼容工具：修复版大样本历史消息读取（转调 get_chat_history）。"""
    return get_chat_history(
        chat_name=chat_name,
        limit=limit,
        offset=offset,
        start_ts=start_ts,
        end_ts=end_ts,
        max_chars=max_chars,
    )


@mcp.tool()
def get_contact_groups(query: str = "", min_members: int = 3, limit: int = 1000) -> str:
    """获取联系人中的群聊列表和元数据。"""
    min_members = _clamp_int(min_members, 3, 0, 100000)
    limit = _clamp_int(limit, 1000, 1, 10000)
    q = str(query or "").strip().lower()

    names = get_contact_names()
    member_map = _get_group_member_count_map()
    last_active_map = _get_session_last_active_map()

    out = []
    for username in _get_group_usernames():
        display = names.get(username, username)
        if q and q not in username.lower() and q not in str(display).lower():
            continue
        member_count = int(member_map.get(username, 0))
        if member_count < min_members:
            continue
        out.append(
            {
                "chat_name": str(display),
                "username": str(username),
                "member_count": member_count,
                "last_active": int(last_active_map.get(username, 0)),
            }
        )

    out.sort(key=lambda x: x.get("last_active", 0), reverse=True)
    out = out[:limit]
    return _json_result(out)


@mcp.tool()
def get_group_message_stats(
    start_ts: int = 0,
    end_ts: int = 0,
    limit: int = 500,
    min_members: int = 0,
    group_types: list = None,
) -> str:
    """获取所有群聊的消息统计，按活跃度排序。"""
    start_ts, end_ts = _norm_ts_range(start_ts, end_ts)
    limit = _clamp_int(limit, 500, 1, 5000)
    min_members = _clamp_int(min_members, 0, 0, 100000)
    group_types = group_types if isinstance(group_types, list) and group_types else ["all"]
    gt = set([str(x).lower() for x in group_types])
    if not ({"all", "group", "discussion"} & gt):
        gt = {"all"}

    names = get_contact_names()
    member_map = _get_group_member_count_map()
    last_active_map = _get_session_last_active_map()
    groups = _get_group_usernames()

    # 避免全库极端慢，按最近活跃做一个宽松扫描上限。
    groups.sort(key=lambda u: last_active_map.get(u, 0), reverse=True)
    scan_cap = min(len(groups), max(limit * 8, 200))
    groups = groups[:scan_cap]

    rows = []
    for username in groups:
        member_count = int(member_map.get(username, 0))
        if member_count < min_members:
            continue

        db_path, table_name = _find_msg_table_for_user(username)
        if not db_path:
            continue

        conn = sqlite3.connect(db_path)
        try:
            where_sql, params = _build_msg_where(start_ts=start_ts, end_ts=end_ts, skip_compress=True)
            msg_count = int(
                conn.execute(
                    f"SELECT COUNT(1) FROM [{table_name}] WHERE {where_sql}",
                    tuple(params),
                ).fetchone()[0]
                or 0
            )
        except Exception:
            msg_count = 0
        finally:
            conn.close()

        rows.append(
            {
                "chat_name": str(names.get(username, username)),
                "username": str(username),
                "message_count": msg_count,
                "member_count": member_count,
                "last_active": int(last_active_map.get(username, 0)),
            }
        )

    rows.sort(key=lambda x: (int(x.get("message_count", 0)), int(x.get("last_active", 0))), reverse=True)
    return _json_result(rows[:limit])


@mcp.tool()
def get_chat_detail_stats(
    chat_name: str,
    start_ts: int = 0,
    end_ts: int = 0,
    include_topics: bool = True,
    include_media_breakdown: bool = True,
) -> str:
    """获取单个群聊/联系人的详细统计。"""
    start_ts, end_ts = _norm_ts_range(start_ts, end_ts)
    username = resolve_username(chat_name)
    if not username:
        return _json_result({"error": f"找不到聊天对象: {chat_name}"})

    names = get_contact_names()
    display_name = names.get(username, username)
    is_group = "@chatroom" in username
    member_count = int(_get_group_member_count_map().get(username, 0)) if is_group else 2

    db_path, table_name = _find_msg_table_for_user(username)
    if not db_path:
        return _json_result({"error": f"找不到 {display_name} 的消息记录"})

    conn = sqlite3.connect(db_path)
    out = {
        "chat_name": str(display_name),
        "username": str(username),
        "is_group": bool(is_group),
        "member_count": member_count,
        "total_messages": 0,
        "message_type_breakdown": {},
        "active_hours": {"peak": None, "distribution": {}},
        "top_topics": [],
    }
    try:
        where_sql, params = _build_msg_where(start_ts=start_ts, end_ts=end_ts, skip_compress=True)
        total = conn.execute(
            f"SELECT COUNT(1) FROM [{table_name}] WHERE {where_sql}",
            tuple(params),
        ).fetchone()[0]
        out["total_messages"] = int(total or 0)

        type_rows = conn.execute(
            f"""
            SELECT local_type, COUNT(1)
            FROM [{table_name}]
            WHERE {where_sql}
            GROUP BY local_type
            """,
            tuple(params),
        ).fetchall()
        type_break = {}
        media_break = {"text": 0, "media": 0, "link_or_file": 0, "system": 0, "other": 0}
        for local_type, cnt in type_rows:
            tname = format_msg_type(int(local_type))
            type_break[tname] = int(cnt or 0)
            media_break[_media_category(int(local_type))] += int(cnt or 0)
        out["message_type_breakdown"] = type_break
        if include_media_breakdown:
            out["media_breakdown"] = media_break

        hour_rows = conn.execute(
            f"""
            SELECT strftime('%H', create_time, 'unixepoch', 'localtime') AS h, COUNT(1) AS c
            FROM [{table_name}]
            WHERE {where_sql}
            GROUP BY h
            ORDER BY h
            """,
            tuple(params),
        ).fetchall()
        hour_dist = {str(i): 0 for i in range(24)}
        peak_hour = None
        peak_count = -1
        for h, c in hour_rows:
            if h is None:
                continue
            hour_dist[str(int(h))] = int(c or 0)
            if int(c or 0) > peak_count:
                peak_count = int(c or 0)
                peak_hour = int(h)
        out["active_hours"] = {"peak": peak_hour, "distribution": hour_dist}

        if include_topics:
            text_rows = conn.execute(
                f"""
                SELECT message_content
                FROM [{table_name}]
                WHERE {where_sql} AND local_type = 1
                ORDER BY create_time DESC
                LIMIT 120000
                """,
                tuple(params),
            ).fetchall()
            texts = []
            for (content,) in text_rows:
                txt = _strip_sender_prefix(content, is_group)
                if txt:
                    texts.append(txt)
            out["top_topics"] = _extract_top_keywords(texts, topn=20, min_freq=3)
    except Exception as e:
        return _json_result({"error": f"统计失败: {e}"})
    finally:
        conn.close()

    return _json_result(out)


@mcp.tool()
def get_daily_message_trend(
    chat_name: str,
    granularity: str = "day",
    start_ts: int = 0,
    end_ts: int = 0,
) -> str:
    """获取消息时间趋势（日/周/月/小时）。"""
    start_ts, end_ts = _norm_ts_range(start_ts, end_ts)
    g = str(granularity or "day").strip().lower()
    if g not in ("day", "week", "month", "hour"):
        g = "day"

    username = resolve_username(chat_name)
    if not username:
        return _json_result({"error": f"找不到聊天对象: {chat_name}"})

    db_path, table_name = _find_msg_table_for_user(username)
    if not db_path:
        return _json_result([])

    is_group = "@chatroom" in username
    conn = sqlite3.connect(db_path)
    try:
        cols = _get_table_columns(conn, table_name)
        has_sender = "real_sender_id" in cols
        if g == "day":
            bucket_expr = "strftime('%Y-%m-%d', create_time, 'unixepoch', 'localtime')"
        elif g == "week":
            bucket_expr = "strftime('%Y-W%W', create_time, 'unixepoch', 'localtime')"
        elif g == "month":
            bucket_expr = "strftime('%Y-%m', create_time, 'unixepoch', 'localtime')"
        else:
            bucket_expr = "strftime('%Y-%m-%d %H:00', create_time, 'unixepoch', 'localtime')"

        unique_sender_expr = (
            "COUNT(DISTINCT CASE WHEN real_sender_id > 0 THEN real_sender_id END)"
            if (is_group and has_sender)
            else "COUNT(DISTINCT CASE WHEN status=2 THEN 'self' ELSE 'peer' END)"
        )

        where_sql, params = _build_msg_where(start_ts=start_ts, end_ts=end_ts, skip_compress=True)
        rows = conn.execute(
            f"""
            SELECT {bucket_expr} AS bucket,
                   COUNT(1) AS count,
                   {unique_sender_expr} AS unique_senders
            FROM [{table_name}]
            WHERE {where_sql}
            GROUP BY bucket
            ORDER BY bucket
            """,
            tuple(params),
        ).fetchall()

        out = []
        for bucket, cnt, us in rows:
            out.append(
                {
                    "date": str(bucket),
                    "count": int(cnt or 0),
                    "unique_senders": int(us or 0),
                }
            )
        return _json_result(out)
    except Exception as e:
        return _json_result({"error": f"趋势查询失败: {e}"})
    finally:
        conn.close()


@mcp.tool()
def get_group_member_stats(
    chat_name: str,
    limit: int = 50,
    start_ts: int = 0,
    end_ts: int = 0,
    include_metrics: list = None,
) -> str:
    """获取群聊成员发言统计排行榜。"""
    start_ts, end_ts = _norm_ts_range(start_ts, end_ts)
    limit = _clamp_int(limit, 50, 1, 1000)
    include_metrics = include_metrics if isinstance(include_metrics, list) and include_metrics else [
        "message_count", "word_count", "active_days", "media_count"
    ]

    username = resolve_username(chat_name)
    if not username:
        return _json_result({"error": f"找不到聊天对象: {chat_name}"})
    if "@chatroom" not in username:
        return _json_result({"error": "get_group_member_stats 仅支持群聊"})

    names = get_contact_names()
    db_path, table_name = _find_msg_table_for_user(username)
    if not db_path:
        return _json_result([])

    conn = sqlite3.connect(db_path)
    try:
        cols = _get_table_columns(conn, table_name)
        if "real_sender_id" not in cols:
            return _json_result({"error": "当前消息表缺少 real_sender_id，无法统计成员榜"})

        id2username, _username2ids = _load_name2id_maps(conn)
        where_sql, params = _build_msg_where(start_ts=start_ts, end_ts=end_ts, skip_compress=True)
        rows = conn.execute(
            f"""
            SELECT real_sender_id AS sid,
                   COUNT(1) AS message_count,
                   SUM(CASE WHEN local_type = 1 THEN LENGTH(COALESCE(message_content, '')) ELSE 0 END) AS word_count,
                   COUNT(DISTINCT strftime('%Y-%m-%d', create_time, 'unixepoch', 'localtime')) AS active_days,
                   SUM(CASE WHEN local_type != 1 THEN 1 ELSE 0 END) AS media_count,
                   MAX(create_time) AS last_active
            FROM [{table_name}]
            WHERE {where_sql} AND real_sender_id > 0
            GROUP BY real_sender_id
            ORDER BY message_count DESC
            LIMIT ?
            """,
            tuple(params + [limit]),
        ).fetchall()

        out = []
        for idx, (sid, mc, wc, ad, med, last_ts) in enumerate(rows, start=1):
            sid_i = int(sid or 0)
            sender_username = id2username.get(sid_i, str(sid_i))
            sender_name = names.get(sender_username, sender_username)
            obj = {"rank": idx, "sender": sender_name, "sender_id": sender_username}
            if "message_count" in include_metrics:
                obj["message_count"] = int(mc or 0)
            if "word_count" in include_metrics:
                obj["word_count"] = int(wc or 0)
            if "active_days" in include_metrics:
                obj["active_days"] = int(ad or 0)
            if "media_count" in include_metrics:
                obj["media_count"] = int(med or 0)
            obj["last_active"] = int(last_ts or 0)
            out.append(obj)
        return _json_result(out)
    except Exception as e:
        return _json_result({"error": f"成员统计失败: {e}"})
    finally:
        conn.close()


def _build_sender_profile_data(
    chat_name: str,
    sender: str,
    start_ts: int = 0,
    end_ts: int = 0,
    context_before: int = -1,
    context_after: int = -1,
):
    """Internal builder for sender profile; returns dict with error/data."""
    start_ts, end_ts = _norm_ts_range(start_ts, end_ts)
    username = resolve_username(chat_name)
    if not username:
        return {"error": f"找不到聊天对象: {chat_name}"}
    if "@chatroom" not in username:
        return {"error": "get_sender_profile 仅支持群聊"}

    db_path, table_name = _find_msg_table_for_user(username)
    if not db_path:
        return {"error": "找不到群聊消息记录"}

    names = get_contact_names()
    conn = sqlite3.connect(db_path)
    try:
        candidates, candidate_ids, id2username = _resolve_sender_ids(conn, sender, names)
        sender_query_raw = str(sender or "").strip()
        if not candidates:
            return {"error": f"未识别到发言人: {sender_query_raw}"}

        where_parts = []
        where_params = []
        where_base_sql, where_base_params = _build_msg_where(start_ts=start_ts, end_ts=end_ts, skip_compress=True)
        where_parts.append(where_base_sql)
        where_params.extend(where_base_params)

        sender_clauses = []
        sender_params = []
        if candidate_ids:
            placeholders = ",".join(["?"] * len(candidate_ids))
            sender_clauses.append(f"real_sender_id IN ({placeholders})")
            sender_params.extend(candidate_ids)
        for uname in candidates[:20]:
            sender_clauses.append("message_content LIKE ?")
            sender_params.append(f"{uname}:\n%")
        if sender_clauses:
            where_parts.append("(" + " OR ".join(sender_clauses) + ")")
        else:
            where_parts.append("message_content LIKE ?")
            where_params.append(f"%{sender_query_raw}:%")

        where_sql = " AND ".join(where_parts)
        all_params = tuple(where_params + sender_params)
        rows = conn.execute(
            f"""
            SELECT local_type, create_time, message_content, real_sender_id
            FROM [{table_name}]
            WHERE {where_sql}
            ORDER BY create_time DESC
            """,
            all_params,
        ).fetchall()
    except Exception as e:
        return {"error": f"查询失败: {e}"}
    finally:
        conn.close()

    if not rows:
        return {"error": f"未找到发言人 {sender} 的消息"}

    positive_words = ("好", "赞", "牛", "棒", "开心", "感谢", "支持", "厉害", "稳")
    negative_words = ("差", "烦", "难", "无语", "崩", "问题", "糟", "累", "不行")
    sentiment_count = {"positive": 0, "neutral": 0, "negative": 0}
    hour_counter = Counter()
    day_counter = Counter()
    texts = []
    mention_counter = Counter()
    earliest = None
    latest = None
    sample_quotes = []

    for local_type, ts, content, real_sender_id in rows:
        ts_i = int(ts or 0)
        if earliest is None or ts_i < earliest:
            earliest = ts_i
        if latest is None or ts_i > latest:
            latest = ts_i
        dt = datetime.fromtimestamp(ts_i)
        hour_counter[dt.hour] += 1
        day_counter[dt.strftime("%Y-%m-%d")] += 1

        txt = _strip_sender_prefix(content, True)
        if local_type != 1:
            txt = f"[{format_msg_type(int(local_type))}] {txt}".strip()
        if not txt:
            txt = ""
        texts.append(txt)
        if txt and len(sample_quotes) < 6 and not _is_placeholder_text(txt):
            quote = txt[:180] + ("..." if len(txt) > 180 else "")
            sample_quotes.append(quote)

        low = txt.lower()
        pos_hit = any(w in txt for w in positive_words)
        neg_hit = any(w in txt for w in negative_words)
        if pos_hit and not neg_hit:
            sentiment_count["positive"] += 1
        elif neg_hit and not pos_hit:
            sentiment_count["negative"] += 1
        else:
            sentiment_count["neutral"] += 1

        for m in re.findall(r"@([^\s@]{1,24})", txt):
            mention_counter[m.strip()] += 1

    total_messages = len(rows)
    active_days = max(1, len(day_counter))
    total_sentiments = sum(sentiment_count.values()) or 1

    common_topics = _extract_top_keywords(texts, topn=20, min_freq=2)
    interaction_partners = [
        {"sender": name, "count": int(cnt)}
        for name, cnt in mention_counter.most_common(20)
    ]

    # Context defaults are informative in profile mode.
    if context_before < 0:
        context_before = 8 if total_messages > 500 else 16
    if context_after < 0:
        context_after = 8 if total_messages > 500 else 16

    sender_display = names.get(candidates[0], candidates[0]) if candidates else sender
    return {
        "chat_name": chat_name,
        "sender": sender_display,
        "sender_candidates": [names.get(u, u) for u in candidates],
        "total_messages": int(total_messages),
        "avg_daily_messages": round(total_messages / active_days, 2),
        "most_active_hour": int(hour_counter.most_common(1)[0][0]) if hour_counter else None,
        "active_days": int(active_days),
        "time_range": {"start_ts": int(earliest or 0), "end_ts": int(latest or 0)},
        "common_topics": common_topics,
        "sentiment_distribution": {
            "positive": round(sentiment_count["positive"] / total_sentiments, 4),
            "neutral": round(sentiment_count["neutral"] / total_sentiments, 4),
            "negative": round(sentiment_count["negative"] / total_sentiments, 4),
        },
        "recent_quote": sample_quotes[0] if sample_quotes else "",
        "sample_quotes": sample_quotes,
        "interaction_partners": interaction_partners,
        "suggested_context": {"before": int(context_before), "after": int(context_after)},
    }


@mcp.tool()
def get_sender_profile(
    chat_name: str,
    sender: str,
    start_ts: int = 0,
    end_ts: int = 0,
    context_before: int = -1,
    context_after: int = -1,
) -> str:
    """获取指定成员在群聊中的详细画像。"""
    data = _build_sender_profile_data(
        chat_name=chat_name,
        sender=sender,
        start_ts=start_ts,
        end_ts=end_ts,
        context_before=context_before,
        context_after=context_after,
    )
    return _json_result(data)


@mcp.tool()
def compare_members(
    chat_name: str,
    senders: list,
    metrics: list = None,
) -> str:
    """对比多个成员发言特征。"""
    if not isinstance(senders, list) or len(senders) < 2:
        return _json_result({"error": "senders 至少提供 2 个成员"})
    metrics = metrics if isinstance(metrics, list) and metrics else ["message_count", "active_hours", "topics"]

    out = []
    for s in senders[:20]:
        profile = _build_sender_profile_data(chat_name=chat_name, sender=str(s))
        if "error" in profile:
            out.append({"sender": str(s), "error": profile["error"]})
            continue
        item = {"sender": profile.get("sender", str(s))}
        if "message_count" in metrics:
            item["message_count"] = profile.get("total_messages", 0)
            item["avg_daily_messages"] = profile.get("avg_daily_messages", 0)
        if "active_hours" in metrics:
            item["most_active_hour"] = profile.get("most_active_hour")
        if "topics" in metrics:
            item["top_topics"] = [x.get("topic") for x in profile.get("common_topics", [])[:8]]
        out.append(item)
    return _json_result(out)


@mcp.tool()
def get_emotion_signal_summary(
    chat_name: str,
    start_ts: int = 0,
    end_ts: int = 0,
    limit: int = 5000,
) -> str:
    """汇总群聊情绪信号：分布、日趋势、情绪成员与代表语料。"""
    username = resolve_username(chat_name)
    if not username:
        return _json_result({"error": f"找不到聊天对象: {chat_name}"})

    start_ts, end_ts = _norm_ts_range(start_ts, end_ts)
    limit = _clamp_int(limit, 5000, 200, 60000)
    db_path, table_name = _find_msg_table_for_user(username)
    if not db_path:
        return _json_result({"error": "找不到聊天消息记录"})

    names = get_contact_names()
    is_group = "@chatroom" in username
    conn = sqlite3.connect(db_path)
    try:
        cols = _get_table_columns(conn, table_name)
        has_sender_col = "real_sender_id" in cols
        id2username, _username2ids = _load_name2id_maps(conn) if has_sender_col else ({}, {})
        sender_col_sql = "real_sender_id" if has_sender_col else "NULL AS real_sender_id"
        where_sql, params = _build_msg_where(start_ts=start_ts, end_ts=end_ts, skip_compress=True)
        raw_rows = conn.execute(
            f"""
            SELECT local_type, create_time, message_content, {sender_col_sql}
            FROM [{table_name}]
            WHERE {where_sql}
            ORDER BY create_time DESC
            LIMIT ?
            """,
            tuple(params + [limit]),
        ).fetchall()
    except Exception as e:
        return _json_result({"error": f"情绪信号分析失败: {e}"})
    finally:
        conn.close()

    distribution = {"positive": 0, "neutral": 0, "negative": 0}
    label_counter = Counter()
    day_trend = defaultdict(lambda: {"positive": 0, "neutral": 0, "negative": 0})
    sender_rows = defaultdict(list)
    quotes = []

    for local_type, ts, content, real_sender_id in reversed(raw_rows):
        lt = int(local_type or 0)
        if lt in (10000, 10002):
            continue
        parsed_sender, txt = _parse_message_content(content, lt, is_group)
        sid = _resolve_sender_from_msg(is_group, has_sender_col, real_sender_id, parsed_sender, id2username)
        sender_name = names.get(sid, sid) if sid else "成员"
        clean_text = _clean_candidate_text(txt)
        if not clean_text:
            continue
        signal = _emotion_signal_from_text(clean_text)
        polarity = str(signal.get("polarity", "neutral") or "neutral")
        label = str(signal.get("label", "平稳") or "平稳")
        distribution[polarity] = int(distribution.get(polarity, 0) or 0) + 1
        label_counter[label] += 1
        day_key = datetime.fromtimestamp(int(ts or 0)).strftime("%Y-%m-%d")
        day_trend[day_key][polarity] += 1
        row = {
            "sender": sender_name,
            "time": datetime.fromtimestamp(int(ts or 0)).strftime("%Y-%m-%d %H:%M:%S"),
            "text": clean_text[:220],
            "polarity": polarity,
            "label": label,
            "score": int(signal.get("score", 0) or 0),
        }
        sender_rows[sender_name].append(row)
        if len(quotes) < 120 and not _is_placeholder_text(clean_text):
            quotes.append(row)

    trend_rows = []
    for day_key in sorted(day_trend.keys())[-30:]:
        trend_rows.append({"date": day_key, **day_trend[day_key]})

    def _member_bucket(target_polarity):
        out = []
        for sender_name, rows in sender_rows.items():
            filtered = [r for r in rows if str(r.get("polarity", "")) == target_polarity]
            if not filtered:
                continue
            avg_score = sum(int(r.get("score", 0) or 0) for r in filtered) / max(1, len(filtered))
            best_quote = max(filtered, key=lambda x: abs(int(x.get("score", 0) or 0)))
            out.append({
                "sender": sender_name,
                "count": len(filtered),
                "avg_score": round(avg_score, 2),
                "label": best_quote.get("label", ""),
                "quote": best_quote.get("text", ""),
                "time": best_quote.get("time", ""),
            })
        out.sort(key=lambda x: (abs(float(x.get("avg_score", 0) or 0)), int(x.get("count", 0) or 0)), reverse=True)
        return out[:8]

    quotes.sort(key=lambda x: abs(int(x.get("score", 0) or 0)), reverse=True)
    return _json_result(
        {
            "chat_name": names.get(username, username),
            "username": username,
            "range": {"start_ts": int(start_ts or 0), "end_ts": int(end_ts or 0)},
            "distribution": distribution,
            "emotion_labels": [{"label": k, "count": int(v)} for k, v in label_counter.most_common(8)],
            "trend": trend_rows,
            "positive_members": _member_bucket("positive"),
            "negative_members": _member_bucket("negative"),
            "representative_quotes": quotes[:12],
            "sample_size": int(sum(distribution.values())),
        }
    )


@mcp.tool()
def get_risk_alert_candidates(
    chat_name: str,
    start_ts: int = 0,
    end_ts: int = 0,
    limit: int = 4000,
) -> str:
    """聚合风险候选：风险关键词、异常链接、负向情绪样本和活跃尖峰。"""
    username = resolve_username(chat_name)
    if not username:
        return _json_result({"error": f"找不到聊天对象: {chat_name}"})

    start_ts, end_ts = _norm_ts_range(start_ts, end_ts)
    limit = _clamp_int(limit, 4000, 200, 80000)
    db_path, table_name = _find_msg_table_for_user(username)
    if not db_path:
        return _json_result({"error": "找不到聊天消息记录"})

    names = get_contact_names()
    is_group = "@chatroom" in username
    conn = sqlite3.connect(db_path)
    try:
        cols = _get_table_columns(conn, table_name)
        has_sender_col = "real_sender_id" in cols
        id2username, _username2ids = _load_name2id_maps(conn) if has_sender_col else ({}, {})
        sender_col_sql = "real_sender_id" if has_sender_col else "NULL AS real_sender_id"
        where_sql, params = _build_msg_where(start_ts=start_ts, end_ts=end_ts, skip_compress=True)
        raw_rows = conn.execute(
            f"""
            SELECT local_type, create_time, message_content, {sender_col_sql}
            FROM [{table_name}]
            WHERE {where_sql}
            ORDER BY create_time DESC
            LIMIT ?
            """,
            tuple(params + [limit]),
        ).fetchall()
    except Exception as e:
        return _json_result({"error": f"风险候选分析失败: {e}"})
    finally:
        conn.close()

    keyword_counter = Counter()
    sender_counter = Counter()
    link_counter = Counter()
    negative_quotes = []
    evidence = []
    daily_total = Counter()
    daily_link = Counter()

    for local_type, ts, content, real_sender_id in raw_rows:
        lt = int(local_type or 0)
        parsed_sender, txt = _parse_message_content(content, lt, is_group)
        sid = _resolve_sender_from_msg(is_group, has_sender_col, real_sender_id, parsed_sender, id2username)
        sender_name = names.get(sid, sid) if sid else "成员"
        clean_text = _clean_candidate_text(txt)
        day_key = datetime.fromtimestamp(int(ts or 0)).strftime("%Y-%m-%d")
        daily_total[day_key] += 1
        if lt == 49 or re.search(r"https?://|www\.", clean_text.lower()):
            daily_link[day_key] += 1
            link_counter[day_key] += 1

        risk_hits = _risk_hits_from_text(clean_text)
        emo = _emotion_signal_from_text(clean_text)
        if risk_hits:
            for hit in risk_hits:
                keyword_counter[hit] += 1
            sender_counter[sender_name] += 1
            evidence.append({
                "time": datetime.fromtimestamp(int(ts or 0)).strftime("%Y-%m-%d %H:%M:%S"),
                "sender": sender_name,
                "type": ",".join(risk_hits),
                "text": clean_text[:220],
            })
        if str(emo.get("polarity", "")) == "negative" and clean_text and len(negative_quotes) < 12:
            negative_quotes.append({
                "time": datetime.fromtimestamp(int(ts or 0)).strftime("%Y-%m-%d %H:%M:%S"),
                "sender": sender_name,
                "label": emo.get("label", ""),
                "text": clean_text[:220],
            })

    alerts = []
    for key, cnt in keyword_counter.most_common(4):
        alerts.append({
            "level": "high" if cnt >= 8 else "warn",
            "type": key,
            "title": f"{key} 风险词出现 {cnt} 次",
            "action": "回看原文并确认是否需要人工介入",
        })

    if daily_link:
        peak_day, peak_links = daily_link.most_common(1)[0]
        alerts.append({
            "level": "warn" if peak_links >= 6 else "info",
            "type": "link_spike",
            "title": f"{peak_day} 链接分享达到 {peak_links} 条",
            "action": "核查是否存在集中外链投放或导流",
        })

    if daily_total:
        avg_daily = sum(daily_total.values()) / max(1, len(daily_total))
        peak_day, peak_total = daily_total.most_common(1)[0]
        if peak_total >= avg_daily * 1.8 and peak_total >= 30:
            alerts.append({
                "level": "info",
                "type": "activity_spike",
                "title": f"{peak_day} 消息量峰值 {peak_total} 条",
                "action": "结合当天主题与投诉样本做复盘",
            })

    return _json_result(
        {
            "chat_name": names.get(username, username),
            "username": username,
            "range": {"start_ts": int(start_ts or 0), "end_ts": int(end_ts or 0)},
            "risk_counts": [{"type": k, "count": int(v)} for k, v in keyword_counter.most_common(8)],
            "top_risk_senders": [{"sender": k, "count": int(v)} for k, v in sender_counter.most_common(8)],
            "alerts": alerts[:8],
            "negative_quotes": negative_quotes[:8],
            "evidence": evidence[:16],
            "daily_total": [{"date": k, "count": int(v)} for k, v in sorted(daily_total.items())[-30:]],
            "daily_link": [{"date": k, "count": int(v)} for k, v in sorted(daily_link.items())[-30:]],
        }
    )


@mcp.tool()
def get_member_profile_cards(
    chat_name: str,
    start_ts: int = 0,
    end_ts: int = 0,
    limit: int = 12,
) -> str:
    """批量生成成员画像卡片，适合 AI 做成员分层和 KOL 分析。"""
    username = resolve_username(chat_name)
    if not username:
        return _json_result({"error": f"找不到聊天对象: {chat_name}"})
    if "@chatroom" not in username:
        return _json_result({"error": "get_member_profile_cards 仅支持群聊"})

    start_ts, end_ts = _norm_ts_range(start_ts, end_ts)
    limit = _clamp_int(limit, 12, 3, 30)
    base_rows_raw = get_group_member_stats(chat_name=chat_name, limit=max(limit * 2, 12), start_ts=start_ts, end_ts=end_ts)
    try:
        base_rows = json.loads(base_rows_raw)
    except Exception:
        base_rows = []
    if not isinstance(base_rows, list):
        return _json_result({"error": "成员统计结果异常"})

    cards = []
    for idx, row in enumerate(base_rows[:limit], start=1):
        sender_name = str((row or {}).get("sender", "") or "").strip()
        if not sender_name:
            continue
        profile = _build_sender_profile_data(
            chat_name=chat_name,
            sender=sender_name,
            start_ts=start_ts,
            end_ts=end_ts,
        )
        if not isinstance(profile, dict) or profile.get("error"):
            continue
        total_messages = int(profile.get("total_messages", 0) or 0)
        active_days = int(profile.get("active_days", 0) or 0)
        if idx <= 3 or total_messages >= 150:
            role = "核心放大器"
        elif active_days >= 7:
            role = "稳定参与者"
        elif total_messages >= 30:
            role = "话题跟随者"
        else:
            role = "潜力成员"

        sent_dist = profile.get("sentiment_distribution", {}) if isinstance(profile.get("sentiment_distribution", {}), dict) else {}
        dominant_sentiment = max(
            ("positive", "neutral", "negative"),
            key=lambda k: float(sent_dist.get(k, 0) or 0),
        )
        sentiment_label = {
            "positive": "正向表达偏多",
            "neutral": "表达较平稳",
            "negative": "需关注情绪波动",
        }.get(dominant_sentiment, "表达较平稳")
        common_topics = [str(x.get("topic", "") or "") for x in profile.get("common_topics", [])[:3] if isinstance(x, dict)]
        cards.append(
            {
                "rank": idx,
                "sender": sender_name,
                "role": role,
                "message_count": int((row or {}).get("message_count", 0) or profile.get("total_messages", 0) or 0),
                "active_days": int((row or {}).get("active_days", 0) or active_days),
                "avg_daily_messages": float(profile.get("avg_daily_messages", 0) or 0),
                "most_active_hour": profile.get("most_active_hour"),
                "recent_quote": str(profile.get("recent_quote", "") or ""),
                "sample_quotes": profile.get("sample_quotes", [])[:3],
                "topics": common_topics,
                "interaction_partners": profile.get("interaction_partners", [])[:4],
                "sentiment_distribution": sent_dist,
                "sentiment_label": sentiment_label,
                "insight": f"{role}，常见主题：{' / '.join(common_topics) if common_topics else '暂无明显主题'}",
            }
        )

    return _json_result(
        {
            "chat_name": chat_name,
            "username": username,
            "range": {"start_ts": int(start_ts or 0), "end_ts": int(end_ts or 0)},
            "cards": cards,
            "summary": {
                "card_count": len(cards),
                "core_count": int(sum(1 for x in cards if x.get("role") == "核心放大器")),
                "stable_count": int(sum(1 for x in cards if x.get("role") == "稳定参与者")),
            },
        }
    )


@mcp.tool()
def smart_search_messages(
    chat_name: str,
    query: str,
    search_mode: str = "boolean",
    start_ts: int = 0,
    end_ts: int = 0,
    limit: int = 1000,
) -> str:
    """智能搜索：支持 simple / boolean / regex。"""
    if not query or not str(query).strip():
        return _json_result({"error": "query 不能为空"})
    username = resolve_username(chat_name)
    if not username:
        return _json_result({"error": f"找不到聊天对象: {chat_name}"})
    start_ts, end_ts = _norm_ts_range(start_ts, end_ts)
    limit = _clamp_int(limit, 1000, 1, 20000)
    mode = str(search_mode or "boolean").strip().lower()
    if mode not in ("simple", "boolean", "regex"):
        mode = "simple"

    db_path, table_name = _find_msg_table_for_user(username)
    if not db_path:
        return _json_result([])

    names = get_contact_names()
    is_group = "@chatroom" in username
    conn = sqlite3.connect(db_path)
    try:
        where_sql, params = _build_msg_where(start_ts=start_ts, end_ts=end_ts, skip_compress=True)
        out = []

        if mode == "simple":
            rows = conn.execute(
                f"""
                SELECT local_type, create_time, message_content
                FROM [{table_name}]
                WHERE {where_sql} AND message_content LIKE ?
                ORDER BY create_time DESC
                LIMIT ?
                """,
                tuple(params + [f"%{query}%", limit]),
            ).fetchall()
            for local_type, ts, content in rows:
                sender_id, txt = _parse_message_content(content, int(local_type), is_group)
                out.append(
                    {
                        "ts": int(ts or 0),
                        "time": datetime.fromtimestamp(int(ts or 0)).strftime("%Y-%m-%d %H:%M:%S"),
                        "sender": names.get(sender_id, sender_id) if sender_id else "",
                        "local_type": int(local_type or 0),
                        "text": _strip_sender_prefix(txt, False),
                    }
                )
            res_str = _json_result(out)
            if len(out) >= limit:
                res_str += "\n\n[系统警告]：由于单次查询限制，仅返回了最新的部分匹配结果。若未找到您需要的信息，或者需要进行全局历史画像分析，请必须分段指定更早的 start_ts 和 end_ts 进行分页继续查询。"
            return res_str

        scan_limit = min(max(limit * 30, 3000), 120000)
        rows = conn.execute(
            f"""
            SELECT local_type, create_time, message_content
            FROM [{table_name}]
            WHERE {where_sql}
            ORDER BY create_time DESC
            LIMIT ?
            """,
            tuple(params + [scan_limit]),
        ).fetchall()

        regex_obj = None
        postfix = None
        if mode == "regex":
            try:
                regex_obj = re.compile(query, flags=re.IGNORECASE)
            except Exception as e:
                return _json_result({"error": f"regex 编译失败: {e}"})
        elif mode == "boolean":
            postfix = _bool_to_postfix(_parse_bool_tokens(query))

        for local_type, ts, content in rows:
            sender_id, txt = _parse_message_content(content, int(local_type), is_group)
            text = _strip_sender_prefix(txt, False)
            hit = False
            if mode == "regex":
                hit = bool(regex_obj.search(text or ""))
            else:
                hit = _eval_postfix_bool(postfix, text or "")
            if not hit:
                continue
            out.append(
                {
                    "ts": int(ts or 0),
                    "time": datetime.fromtimestamp(int(ts or 0)).strftime("%Y-%m-%d %H:%M:%S"),
                    "sender": names.get(sender_id, sender_id) if sender_id else "",
                    "local_type": int(local_type or 0),
                    "text": text,
                }
            )
            if len(out) >= limit:
                break
        
        res_str = _json_result(out)
        if len(out) >= limit or len(rows) >= scan_limit:
            res_str += "\n\n[系统警告]：由于单次查询限制，仅返回了最新的部分匹配结果。若未找到您需要的信息，或者需要进行全局历史画像分析，请必须分段指定更早的 start_ts 和 end_ts 进行分页继续查询。"
        return res_str
    except Exception as e:
        return _json_result({"error": f"搜索失败: {e}"})
    finally:
        conn.close()


@mcp.tool()
def get_topic_distribution(
    chat_name: str,
    start_ts: int = 0,
    end_ts: int = 0,
    min_topic_frequency: int = 10,
    clustering_method: str = "keyword",
) -> str:
    """分析会话话题分布（当前支持 keyword，其他方式自动降级）。"""
    username = resolve_username(chat_name)
    if not username:
        return _json_result({"error": f"找不到聊天对象: {chat_name}"})
    start_ts, end_ts = _norm_ts_range(start_ts, end_ts)
    min_topic_frequency = _clamp_int(min_topic_frequency, 10, 1, 100000)
    method = str(clustering_method or "keyword").strip().lower()
    method_used = "keyword" if method not in ("keyword", "lda", "embedding") else method
    if method_used != "keyword":
        method_used = "keyword"

    db_path, table_name = _find_msg_table_for_user(username)
    if not db_path:
        return _json_result([])

    is_group = "@chatroom" in username
    conn = sqlite3.connect(db_path)
    try:
        where_sql, params = _build_msg_where(start_ts=start_ts, end_ts=end_ts, skip_compress=True)
        rows = conn.execute(
            f"""
            SELECT message_content
            FROM [{table_name}]
            WHERE {where_sql} AND local_type = 1
            ORDER BY create_time DESC
            LIMIT 200000
            """,
            tuple(params),
        ).fetchall()
    except Exception as e:
        return _json_result({"error": f"话题分析失败: {e}"})
    finally:
        conn.close()

    texts = []
    for (content,) in rows:
        t = _strip_sender_prefix(content, is_group)
        if t:
            texts.append(t)
    top = _extract_top_keywords(texts, topn=120, min_freq=min_topic_frequency)
    total = sum(int(x.get("count", 0)) for x in top) or 1
    out = []
    for x in top:
        out.append(
            {
                "topic": x["topic"],
                "message_count": int(x["count"]),
                "percentage": round(100.0 * float(x["count"]) / float(total), 2),
            }
        )
    return _json_result({"method_used": method_used, "topics": out})


@mcp.tool()
def get_score_rules() -> str:
    """Return score-rule definitions (auto + manual)."""
    return _json_result({"rules": SCORE_RULES})


@mcp.tool()
def get_score_leaderboard(
    chat_name: str,
    start_ts: int = 0,
    end_ts: int = 0,
    include_manual: bool = True,
    limit: int = 120,
) -> str:
    """Compute score leaderboard (auto points + optional manual points)."""
    username = resolve_username(chat_name)
    if not username:
        return _json_result({"error": f"chat not found: {chat_name}"})
    if "@chatroom" not in username:
        return _json_result({"error": "get_score_leaderboard only supports group chats"})

    start_ts, end_ts = _norm_ts_range(start_ts, end_ts)
    limit = _clamp_int(limit, 120, 1, 500)
    include_manual = bool(include_manual)

    db_path, table_name = _find_msg_table_for_user(username)
    if not db_path:
        return _json_result({"error": "group message table not found"})

    names = get_contact_names()
    conn = sqlite3.connect(db_path)
    sender_rows = {}
    try:
        cols = _get_table_columns(conn, table_name)
        has_sender_col = "real_sender_id" in cols
        id2username, _username2ids = _load_name2id_maps(conn) if has_sender_col else ({}, {})
        sender_col_sql = "real_sender_id" if has_sender_col else "NULL AS real_sender_id"
        where_sql, params = _build_msg_where(start_ts=start_ts, end_ts=end_ts, skip_compress=True)
        rows = conn.execute(
            f"""
            SELECT local_type, create_time, message_content, {sender_col_sql}
            FROM [{table_name}]
            WHERE {where_sql}
            ORDER BY create_time ASC
            LIMIT 300000
            """,
            tuple(params),
        ).fetchall()
    except Exception as e:
        return _json_result({"error": f"score query failed: {e}"})
    finally:
        conn.close()

    for local_type, ts, content, real_sender_id in rows:
        lt = int(local_type or 0)
        if lt in (10000, 10002):
            continue
        parsed_sender, _txt = _parse_message_content(content, lt, True)
        sid = _resolve_sender_from_msg(True, has_sender_col, real_sender_id, parsed_sender, id2username)
        if not sid:
            continue

        ts_i = int(ts or 0)
        if ts_i <= 0:
            continue
        day_key = datetime.fromtimestamp(ts_i).strftime("%Y-%m-%d")

        item = sender_rows.get(sid)
        if not item:
            display = names.get(sid, sid)
            item = {
                "sender_id": sid,
                "sender": display,
                "messages": 0,
                "active_days": 0,
                "last_ts": 0,
                "auto_points": 0,
                "manual_points": 0,
                "total_points": 0,
                "auto_breakdown": [],
                "manual_items": [],
                "_daily_counter": Counter(),
                "_active_days": set(),
            }
            sender_rows[sid] = item

        item["messages"] = int(item.get("messages", 0) or 0) + 1
        item["_daily_counter"][day_key] += 1
        item["_active_days"].add(day_key)
        if ts_i > int(item.get("last_ts", 0) or 0):
            item["last_ts"] = ts_i

    for row in sender_rows.values():
        daily_counts = [int(v or 0) for v in row.get("_daily_counter", Counter()).values()]
        active_days = len(row.get("_active_days", set()))
        msg_once_points = int(sum(min(v, 5) for v in daily_counts))
        day_ge5_points = int(sum(1 for v in daily_counts if v >= 5) * 5)
        month_points = 20 if active_days >= 12 else 0
        year_points = 30 if active_days >= 120 else 0
        auto_total = int(msg_once_points + day_ge5_points + month_points + year_points)

        row["active_days"] = int(active_days)
        row["auto_points"] = auto_total
        row["total_points"] = auto_total
        row["auto_breakdown"] = [
            {"rule_id": "r_msg_once", "label": "message-once (daily cap=5)", "points": msg_once_points},
            {"rule_id": "r_day_ge5", "label": "daily messages >= 5", "points": day_ge5_points},
            {"rule_id": "r_month_ge12", "label": "active days >= 12", "points": month_points},
            {"rule_id": "r_year_ge120", "label": "active days >= 120", "points": year_points},
        ]

    manual_rows = []
    manual_by_rule = Counter()
    if include_manual:
        for r in _load_manual_score_entries():
            if not isinstance(r, dict):
                continue
            if str(r.get("username", "")).strip() != str(username):
                continue
            ts_i = int(r.get("ts", 0) or 0)
            if start_ts and ts_i and ts_i < int(start_ts):
                continue
            if end_ts and ts_i and ts_i > int(end_ts):
                continue

            sid = str(r.get("sender_id", "") or "").strip()
            if not sid:
                continue
            pts = int(r.get("points", 0) or 0)
            if pts == 0:
                continue
            rid = str(r.get("rule_id", "") or "").strip()
            entry = {
                "id": str(r.get("id", "") or ""),
                "sender_id": sid,
                "sender": str(r.get("sender", "") or names.get(sid, sid) or sid),
                "rule_id": rid,
                "rule_name": SCORE_RULE_MAP.get(rid, {}).get("name", rid),
                "points": pts,
                "note": str(r.get("note", "") or ""),
                "ts": ts_i,
                "created_at": int(r.get("created_at", 0) or 0),
            }
            manual_rows.append(entry)
            manual_by_rule[rid] += pts

            row = sender_rows.get(sid)
            if not row:
                row = {
                    "sender_id": sid,
                    "sender": entry["sender"],
                    "messages": 0,
                    "active_days": 0,
                    "last_ts": ts_i,
                    "auto_points": 0,
                    "manual_points": 0,
                    "total_points": 0,
                    "auto_breakdown": [],
                    "manual_items": [],
                    "_daily_counter": Counter(),
                    "_active_days": set(),
                }
                sender_rows[sid] = row
            row["manual_points"] = int(row.get("manual_points", 0) or 0) + pts
            row["total_points"] = int(row.get("total_points", 0) or 0) + pts
            if ts_i > int(row.get("last_ts", 0) or 0):
                row["last_ts"] = ts_i
            row["manual_items"].append(entry)

    board = list(sender_rows.values())
    for row in board:
        row.pop("_daily_counter", None)
        row.pop("_active_days", None)
        row["manual_items"].sort(key=lambda x: int(x.get("ts", 0) or 0), reverse=True)
        row["manual_items"] = row["manual_items"][:30]

    board.sort(
        key=lambda x: (
            int(x.get("total_points", 0) or 0),
            int(x.get("manual_points", 0) or 0),
            int(x.get("messages", 0) or 0),
            int(x.get("last_ts", 0) or 0),
        ),
        reverse=True,
    )
    for i, row in enumerate(board, start=1):
        row["rank"] = i

    summary = {
        "member_count": len(board),
        "auto_points_total": int(sum(int(x.get("auto_points", 0) or 0) for x in board)),
        "manual_points_total": int(sum(int(x.get("manual_points", 0) or 0) for x in board)),
        "total_points": int(sum(int(x.get("total_points", 0) or 0) for x in board)),
    }

    return _json_result(
        {
            "chat_name": names.get(username, username),
            "username": username,
            "range": {"start_ts": int(start_ts or 0), "end_ts": int(end_ts or 0)},
            "rules": SCORE_RULES,
            "summary": summary,
            "leaderboard": board[:limit],
            "manual_rule_points": [
                {
                    "rule_id": rid,
                    "rule_name": SCORE_RULE_MAP.get(rid, {}).get("name", rid),
                    "points": int(pts),
                }
                for rid, pts in manual_by_rule.most_common()
            ],
            "manual_entry_count": len(manual_rows),
            "calc_note": "Auto points are computed from message frequency and active days. Manual points are loaded from logs/manual_score_entries.json.",
        }
    )


@mcp.tool()
def get_topic_score_candidates(
    chat_name: str,
    start_ts: int = 0,
    end_ts: int = 0,
    window_minutes: int = 180,
    min_unique_responders: int = 5,
    limit: int = 60,
) -> str:
    """Detect candidate topic events for score rules (heuristic)."""
    username = resolve_username(chat_name)
    if not username:
        return _json_result({"error": f"chat not found: {chat_name}"})
    if "@chatroom" not in username:
        return _json_result({"error": "get_topic_score_candidates only supports group chats"})

    start_ts, end_ts = _norm_ts_range(start_ts, end_ts)
    window_minutes = _clamp_int(window_minutes, 180, 30, 1440)
    min_unique_responders = _clamp_int(min_unique_responders, 5, 1, 200)
    limit = _clamp_int(limit, 60, 1, 300)

    db_path, table_name = _find_msg_table_for_user(username)
    if not db_path:
        return _json_result({"error": "group message table not found"})

    names = get_contact_names()
    conn = sqlite3.connect(db_path)
    try:
        cols = _get_table_columns(conn, table_name)
        has_sender_col = "real_sender_id" in cols
        id2username, _username2ids = _load_name2id_maps(conn) if has_sender_col else ({}, {})
        sender_col_sql = "real_sender_id" if has_sender_col else "NULL AS real_sender_id"
        where_sql, params = _build_msg_where(start_ts=start_ts, end_ts=end_ts, skip_compress=True)
        raw_rows = conn.execute(
            f"""
            SELECT local_type, create_time, message_content, {sender_col_sql}
            FROM [{table_name}]
            WHERE {where_sql}
            ORDER BY create_time ASC
            LIMIT 220000
            """,
            tuple(params),
        ).fetchall()
    except Exception as e:
        return _json_result({"error": f"topic candidate query failed: {e}"})
    finally:
        conn.close()

    rows = []
    for local_type, ts, content, real_sender_id in raw_rows:
        lt = int(local_type or 0)
        if lt != 1:
            continue
        parsed_sender, txt = _parse_message_content(content, lt, True)
        sid = _resolve_sender_from_msg(True, has_sender_col, real_sender_id, parsed_sender, id2username)
        if not sid:
            continue
        ts_i = int(ts or 0)
        if ts_i <= 0:
            continue
        text = str(txt or "").strip()
        if not text:
            continue
        rows.append(
            {
                "ts": ts_i,
                "sender_id": sid,
                "sender": names.get(sid, sid),
                "text": text,
            }
        )

    if not rows:
        return _json_result(
            {
                "chat_name": names.get(username, username),
                "username": username,
                "candidates": [],
                "summary": {"topic_start_candidates": 0, "resp5_candidates": 0},
            }
        )

    window_sec = int(window_minutes) * 60
    events = []
    last_seed_by_sender = {}
    for i, seed in enumerate(rows):
        seed_text = seed["text"]
        if not _looks_like_topic_seed(seed_text):
            continue

        prev_ts = int(last_seed_by_sender.get(seed["sender_id"], 0) or 0)
        if prev_ts and (int(seed["ts"]) - prev_ts) < 15 * 60:
            continue

        end_at = int(seed["ts"]) + window_sec
        unique_responders = {}
        response_count = 0
        evidence = []

        j = i + 1
        while j < len(rows):
            r = rows[j]
            if int(r["ts"]) > end_at:
                break
            if str(r["sender_id"]) != str(seed["sender_id"]):
                response_count += 1
                unique_responders.setdefault(str(r["sender_id"]), str(r["sender"]))
                if len(evidence) < 6:
                    evidence.append(
                        {
                            "time": datetime.fromtimestamp(int(r["ts"])).strftime("%Y-%m-%d %H:%M:%S"),
                            "sender": r["sender"],
                            "text": str(r["text"])[:160],
                        }
                    )
            j += 1

        unique_cnt = len(unique_responders)
        if unique_cnt < 2 and response_count < 3:
            continue

        qualifies_resp5 = unique_cnt >= int(min_unique_responders)
        events.append(
            {
                "initiator": seed["sender"],
                "initiator_id": seed["sender_id"],
                "start_ts": int(seed["ts"]),
                "start_time": datetime.fromtimestamp(int(seed["ts"])).strftime("%Y-%m-%d %H:%M:%S"),
                "topic_seed": str(seed_text)[:180],
                "response_messages": int(response_count),
                "response_unique_senders": int(unique_cnt),
                "responders": list(unique_responders.values())[:12],
                "qualifies_topic_start": True,
                "qualifies_topic_resp5": bool(qualifies_resp5),
                "suggested_points": {
                    "m_topic_start": int(SCORE_RULE_MAP.get("m_topic_start", {}).get("points", 5) or 5),
                    "m_topic_resp5": int(SCORE_RULE_MAP.get("m_topic_resp5", {}).get("points", 3) or 3) if qualifies_resp5 else 0,
                },
                "evidence": evidence,
            }
        )
        last_seed_by_sender[seed["sender_id"]] = int(seed["ts"])

    events.sort(
        key=lambda x: (
            1 if x.get("qualifies_topic_resp5") else 0,
            int(x.get("response_unique_senders", 0) or 0),
            int(x.get("response_messages", 0) or 0),
            int(x.get("start_ts", 0) or 0),
        ),
        reverse=True,
    )

    top_events = events[:limit]
    summary = {
        "topic_start_candidates": len(events),
        "resp5_candidates": int(sum(1 for x in events if x.get("qualifies_topic_resp5"))),
    }
    return _json_result(
        {
            "chat_name": names.get(username, username),
            "username": username,
            "range": {"start_ts": int(start_ts or 0), "end_ts": int(end_ts or 0)},
            "window_minutes": int(window_minutes),
            "min_unique_responders": int(min_unique_responders),
            "candidates": top_events,
            "summary": summary,
            "method_note": "Heuristic candidate detection; confirm with AI + manual review before final scoring.",
        }
    )


@mcp.tool()
def get_high_quality_candidates(
    chat_name: str,
    start_ts: int = 0,
    end_ts: int = 0,
    min_text_length: int = 50,
    min_quality_score: int = 60,
    context_window_seconds: int = 120,
    limit: int = 120,
) -> str:
    """Detect high-quality content candidates for score rule m_high_quality (heuristic)."""
    username = resolve_username(chat_name)
    if not username:
        return _json_result({"error": f"chat not found: {chat_name}"})
    if "@chatroom" not in username:
        return _json_result({"error": "get_high_quality_candidates only supports group chats"})

    start_ts, end_ts = _norm_ts_range(start_ts, end_ts)
    min_text_length = _clamp_int(min_text_length, 50, 20, 300)
    min_quality_score = _clamp_int(min_quality_score, 60, 30, 95)
    context_window_seconds = _clamp_int(context_window_seconds, 120, 30, 600)
    limit = _clamp_int(limit, 120, 1, 500)

    db_path, table_name = _find_msg_table_for_user(username)
    if not db_path:
        return _json_result({"error": "group message table not found"})

    names = get_contact_names()
    conn = sqlite3.connect(db_path)
    try:
        cols = _get_table_columns(conn, table_name)
        has_sender_col = "real_sender_id" in cols
        id2username, _username2ids = _load_name2id_maps(conn) if has_sender_col else ({}, {})
        sender_col_sql = "real_sender_id" if has_sender_col else "NULL AS real_sender_id"
        where_sql, params = _build_msg_where(start_ts=start_ts, end_ts=end_ts, skip_compress=True)
        raw_rows = conn.execute(
            f"""
            SELECT local_type, create_time, message_content, {sender_col_sql}
            FROM [{table_name}]
            WHERE {where_sql}
            ORDER BY create_time ASC
            LIMIT 250000
            """,
            tuple(params),
        ).fetchall()
    except Exception as e:
        return _json_result({"error": f"high-quality candidate query failed: {e}"})
    finally:
        conn.close()

    rows = []
    for local_type, ts, content, real_sender_id in raw_rows:
        lt = int(local_type or 0)
        if lt in (10000, 10002):
            continue
        parsed_sender, txt = _parse_message_content(content, lt, True)
        sid = _resolve_sender_from_msg(True, has_sender_col, real_sender_id, parsed_sender, id2username)
        if not sid:
            continue
        ts_i = int(ts or 0)
        if ts_i <= 0:
            continue
        text = _clean_candidate_text(txt)
        rows.append(
            {
                "ts": ts_i,
                "sender_id": sid,
                "sender": names.get(sid, sid),
                "local_type": lt,
                "text": text,
            }
        )

    if not rows:
        return _json_result(
            {
                "chat_name": names.get(username, username),
                "username": username,
                "candidates": [],
                "summary": {"candidate_count": 0, "qualified_count": 0},
            }
        )

    last_text_by_sender = {}
    candidates = []
    for r in rows:
        sid = str(r.get("sender_id", ""))
        ts_i = int(r.get("ts", 0) or 0)
        lt = int(r.get("local_type", 0) or 0)
        text = _clean_candidate_text(r.get("text", ""))

        context_text = ""
        if (not text or _is_placeholder_text(text)):
            prev = last_text_by_sender.get(sid)
            if prev:
                prev_ts = int(prev.get("ts", 0) or 0)
                if 0 <= (ts_i - prev_ts) <= context_window_seconds:
                    context_text = str(prev.get("text", "") or "")

        merged_text = text if (text and not _is_placeholder_text(text)) else context_text
        metrics = _score_high_quality_text(merged_text, lt)
        score = int(metrics.get("score", 0) or 0)
        text_len = int(metrics.get("text_len", 0) or 0)
        has_media = bool(metrics.get("has_media", False))
        has_url = bool(metrics.get("has_url", False))

        qualifies = (
            score >= min_quality_score
            and (
                text_len >= min_text_length
                or has_media
                or has_url
            )
        )

        if qualifies:
            candidates.append(
                {
                    "time": datetime.fromtimestamp(ts_i).strftime("%Y-%m-%d %H:%M:%S"),
                    "ts": ts_i,
                    "sender": r.get("sender", ""),
                    "sender_id": sid,
                    "local_type": lt,
                    "msg_type": format_msg_type(lt),
                    "quality_score": score,
                    "text_length": text_len,
                    "has_media": has_media,
                    "has_link": has_url or (lt == 49),
                    "practical_hits": int(metrics.get("info_hits", 0) or 0),
                    "structured": bool(metrics.get("has_bullet", False)),
                    "text_preview": str(merged_text or "")[:220],
                    "raw_text_preview": str(text or "")[:220],
                    "context_preview": str(context_text or "")[:220],
                    "qualifies_m_high_quality": True,
                    "suggested_points": int(SCORE_RULE_MAP.get("m_high_quality", {}).get("points", 5) or 5),
                }
            )

        if lt == 1 and text and not _is_placeholder_text(text):
            last_text_by_sender[sid] = {"ts": ts_i, "text": text}

    candidates.sort(
        key=lambda x: (
            int(x.get("quality_score", 0) or 0),
            int(x.get("has_media", False)),
            int(x.get("text_length", 0) or 0),
            int(x.get("ts", 0) or 0),
        ),
        reverse=True,
    )

    top_rows = candidates[:limit]
    return _json_result(
        {
            "chat_name": names.get(username, username),
            "username": username,
            "range": {"start_ts": int(start_ts or 0), "end_ts": int(end_ts or 0)},
            "params": {
                "min_text_length": int(min_text_length),
                "min_quality_score": int(min_quality_score),
                "context_window_seconds": int(context_window_seconds),
            },
            "summary": {
                "candidate_count": len(candidates),
                "qualified_count": len(top_rows),
            },
            "candidates": top_rows,
            "method_note": "Heuristic scoring only. Confirm with full context before manual scoring.",
        }
    )


@mcp.tool()
def get_round_table_candidates(
    chat_name: str,
    start_ts: int = 0,
    end_ts: int = 0,
    window_minutes: int = 180,
    min_participants: int = 5,
    keywords: str = "",
    limit: int = 80,
) -> str:
    """Detect online roundtable/discussion participation candidates for m_round_table (heuristic)."""
    username = resolve_username(chat_name)
    if not username:
        return _json_result({"error": f"chat not found: {chat_name}"})
    if "@chatroom" not in username:
        return _json_result({"error": "get_round_table_candidates only supports group chats"})

    start_ts, end_ts = _norm_ts_range(start_ts, end_ts)
    window_minutes = _clamp_int(window_minutes, 180, 30, 720)
    min_participants = _clamp_int(min_participants, 5, 2, 200)
    limit = _clamp_int(limit, 80, 1, 500)

    default_kw = [
        "圆桌", "讨论", "分享会", "沙龙", "研讨", "连麦", "直播", "问答", "AMA", "Q&A",
    ]
    kw_raw = [x.strip() for x in re.split(r"[,\s，、;；]+", str(keywords or "")) if x.strip()]
    kw_list = kw_raw if kw_raw else default_kw
    kw_lower = [k.lower() for k in kw_list]

    db_path, table_name = _find_msg_table_for_user(username)
    if not db_path:
        return _json_result({"error": "group message table not found"})

    names = get_contact_names()
    conn = sqlite3.connect(db_path)
    try:
        cols = _get_table_columns(conn, table_name)
        has_sender_col = "real_sender_id" in cols
        id2username, _username2ids = _load_name2id_maps(conn) if has_sender_col else ({}, {})
        sender_col_sql = "real_sender_id" if has_sender_col else "NULL AS real_sender_id"
        where_sql, params = _build_msg_where(start_ts=start_ts, end_ts=end_ts, skip_compress=True)
        raw_rows = conn.execute(
            f"""
            SELECT local_type, create_time, message_content, {sender_col_sql}
            FROM [{table_name}]
            WHERE {where_sql}
            ORDER BY create_time ASC
            LIMIT 260000
            """,
            tuple(params),
        ).fetchall()
    except Exception as e:
        return _json_result({"error": f"round-table candidate query failed: {e}"})
    finally:
        conn.close()

    rows = []
    for local_type, ts, content, real_sender_id in raw_rows:
        lt = int(local_type or 0)
        if lt in (10000, 10002):
            continue
        parsed_sender, txt = _parse_message_content(content, lt, True)
        sid = _resolve_sender_from_msg(True, has_sender_col, real_sender_id, parsed_sender, id2username)
        if not sid:
            continue
        ts_i = int(ts or 0)
        if ts_i <= 0:
            continue
        text = _clean_candidate_text(txt)
        rows.append(
            {
                "ts": ts_i,
                "sender_id": sid,
                "sender": names.get(sid, sid),
                "local_type": lt,
                "text": text,
            }
        )

    if not rows:
        return _json_result(
            {
                "chat_name": names.get(username, username),
                "username": username,
                "candidates": [],
                "summary": {"candidate_count": 0, "qualified_count": 0},
            }
        )

    window_sec = int(window_minutes) * 60
    candidates = []
    last_seed_by_sender = {}

    for i, seed in enumerate(rows):
        seed_text = str(seed.get("text", "") or "").strip()
        if not seed_text:
            continue
        seed_low = seed_text.lower()
        if not any(k in seed_text or k in seed_low for k in kw_lower):
            continue

        sid = str(seed.get("sender_id", "") or "")
        prev_ts = int(last_seed_by_sender.get(sid, 0) or 0)
        if prev_ts and (int(seed["ts"]) - prev_ts) < 20 * 60:
            continue

        end_at = int(seed["ts"]) + window_sec
        participants = {sid: str(seed.get("sender", "") or sid)}
        msg_count = 1
        responder_counter = Counter()
        evidence = [
            {
                "time": datetime.fromtimestamp(int(seed["ts"])).strftime("%Y-%m-%d %H:%M:%S"),
                "sender": str(seed.get("sender", "")),
                "text": seed_text[:180],
            }
        ]

        j = i + 1
        while j < len(rows):
            r = rows[j]
            r_ts = int(r.get("ts", 0) or 0)
            if r_ts > end_at:
                break
            r_sid = str(r.get("sender_id", "") or "")
            if not r_sid:
                j += 1
                continue
            msg_count += 1
            participants.setdefault(r_sid, str(r.get("sender", "") or r_sid))
            if r_sid != sid:
                responder_counter[r_sid] += 1
                if len(evidence) < 8:
                    evidence.append(
                        {
                            "time": datetime.fromtimestamp(r_ts).strftime("%Y-%m-%d %H:%M:%S"),
                            "sender": str(r.get("sender", "")),
                            "text": str(r.get("text", "") or "")[:160],
                        }
                    )
            j += 1

        participant_count = len(participants)
        qualifies = participant_count >= min_participants
        if not qualifies and msg_count >= max(min_participants * 3, 12):
            qualifies = True
        if participant_count < 3 and msg_count < 8:
            continue

        top_participants = []
        for pid, cnt in responder_counter.most_common(12):
            top_participants.append(
                {
                    "sender_id": pid,
                    "sender": participants.get(pid, pid),
                    "messages": int(cnt),
                }
            )

        candidates.append(
            {
                "start_time": datetime.fromtimestamp(int(seed["ts"])).strftime("%Y-%m-%d %H:%M:%S"),
                "start_ts": int(seed["ts"]),
                "initiator": str(seed.get("sender", "")),
                "initiator_id": sid,
                "topic_seed": seed_text[:200],
                "window_minutes": int(window_minutes),
                "participant_count": int(participant_count),
                "message_count": int(msg_count),
                "participants": list(participants.values())[:20],
                "top_participants": top_participants,
                "qualifies_m_round_table": bool(qualifies),
                "suggested_points": int(SCORE_RULE_MAP.get("m_round_table", {}).get("points", 10) or 10) if qualifies else 0,
                "evidence": evidence,
            }
        )
        last_seed_by_sender[sid] = int(seed["ts"])

    candidates.sort(
        key=lambda x: (
            1 if x.get("qualifies_m_round_table") else 0,
            int(x.get("participant_count", 0) or 0),
            int(x.get("message_count", 0) or 0),
            int(x.get("start_ts", 0) or 0),
        ),
        reverse=True,
    )

    top_rows = candidates[:limit]
    return _json_result(
        {
            "chat_name": names.get(username, username),
            "username": username,
            "range": {"start_ts": int(start_ts or 0), "end_ts": int(end_ts or 0)},
            "keywords": kw_list,
            "window_minutes": int(window_minutes),
            "min_participants": int(min_participants),
            "summary": {
                "candidate_count": len(candidates),
                "qualified_count": int(sum(1 for x in candidates if x.get("qualifies_m_round_table"))),
            },
            "candidates": top_rows,
            "method_note": "Heuristic candidate detection for online roundtable participation. Please manually verify event semantics before scoring.",
        }
    )


@mcp.tool()
def extract_shared_files(
    chat_name: str,
    media_type: str = "all",
    start_ts: int = 0,
    end_ts: int = 0,
    limit: int = 5000,
) -> str:
    """提取会话中的分享内容（文件/链接/图片/视频）。"""
    username = resolve_username(chat_name)
    if not username:
        return _json_result({"error": f"找不到聊天对象: {chat_name}"})
    start_ts, end_ts = _norm_ts_range(start_ts, end_ts)
    limit = _clamp_int(limit, 5000, 1, 50000)
    mt = str(media_type or "all").strip().lower()
    if mt not in ("all", "file", "link", "image", "video"):
        mt = "all"

    db_path, table_name = _find_msg_table_for_user(username)
    if not db_path:
        return _json_result([])

    is_group = "@chatroom" in username
    names = get_contact_names()
    conn = sqlite3.connect(db_path)
    try:
        where_sql, params = _build_msg_where(start_ts=start_ts, end_ts=end_ts, skip_compress=True)
        rows = conn.execute(
            f"""
            SELECT local_type, create_time, message_content
            FROM [{table_name}]
            WHERE {where_sql}
            ORDER BY create_time DESC
            LIMIT ?
            """,
            tuple(params + [max(limit * 8, 2000)]),
        ).fetchall()
    except Exception as e:
        return _json_result({"error": f"提取失败: {e}"})
    finally:
        conn.close()

    out = []
    for local_type, ts, content in rows:
        lt = int(local_type or 0)
        sender_id, txt = _parse_message_content(content, lt, is_group)
        text = _strip_sender_prefix(txt, False)
        text_l = (text or "").lower()

        is_file = bool(lt == 49 and re.search(r"\.(docx?|xlsx?|pptx?|pdf|zip|rar|7z|txt|csv)\b", text_l))
        is_link = bool(lt == 49 and ("http://" in text_l or "https://" in text_l or "www." in text_l))
        is_image = lt == 3
        is_video = lt == 43

        if mt == "file" and not is_file:
            continue
        if mt == "link" and not is_link:
            continue
        if mt == "image" and not is_image:
            continue
        if mt == "video" and not is_video:
            continue
        if mt == "all" and not (is_file or is_link or is_image or is_video or lt == 49):
            continue

        urls = re.findall(r"https?://[^\s]+", text or "")
        out.append(
            {
                "time": datetime.fromtimestamp(int(ts or 0)).strftime("%Y-%m-%d %H:%M:%S"),
                "ts": int(ts or 0),
                "sender": names.get(sender_id, sender_id) if sender_id else "",
                "local_type": lt,
                "media_type": (
                    "file" if is_file else
                    "link" if is_link else
                    "image" if is_image else
                    "video" if is_video else
                    "all"
                ),
                "source": _classify_source(text),
                "url": urls[0] if urls else "",
                "text": text,
            }
        )
        if len(out) >= limit:
            break

    return _json_result(out)


@mcp.tool()
def get_activity_alerts(
    chat_name: str = "all",
    alert_type: str = "all",
    threshold_multiplier: float = 2.0,
    lookback_days: int = 30,
) -> str:
    """获取活跃度异常预警（spike/drop/mention）。"""
    lookback_days = _clamp_int(lookback_days, 30, 3, 365)
    try:
        th = float(threshold_multiplier)
    except Exception:
        th = 2.0
    if th < 1.2:
        th = 1.2
    if th > 10:
        th = 10.0
    at = str(alert_type or "all").strip().lower()
    if at not in ("all", "spike", "drop", "mention"):
        at = "all"

    if str(chat_name).strip().lower() == "all":
        usernames = _get_group_usernames()
    else:
        u = resolve_username(chat_name)
        if not u:
            return _json_result({"error": f"找不到聊天对象: {chat_name}"})
        usernames = [u]

    now = int(time.time())
    start_ts = now - lookback_days * 86400
    names = get_contact_names()
    alerts = []

    for username in usernames[:800]:
        db_path, table_name = _find_msg_table_for_user(username)
        if not db_path:
            continue
        conn = sqlite3.connect(db_path)
        try:
            where_sql, params = _build_msg_where(start_ts=start_ts, end_ts=now, skip_compress=True)
            daily = conn.execute(
                f"""
                SELECT strftime('%Y-%m-%d', create_time, 'unixepoch', 'localtime') AS d,
                       COUNT(1) AS c
                FROM [{table_name}]
                WHERE {where_sql}
                GROUP BY d
                ORDER BY d
                """,
                tuple(params),
            ).fetchall()
            if len(daily) < 3:
                continue

            counts = [int(x[1] or 0) for x in daily]
            latest_day = str(daily[-1][0])
            latest_cnt = counts[-1]
            hist = counts[:-1]
            if not hist:
                continue
            avg = sum(hist) / len(hist)
            if avg <= 0:
                continue

            title = names.get(username, username)
            if (at in ("all", "spike")) and latest_cnt >= avg * th:
                alerts.append(
                    {
                        "chat_name": title,
                        "username": username,
                        "alert_type": "spike",
                        "date": latest_day,
                        "latest_count": latest_cnt,
                        "baseline_avg": round(avg, 2),
                        "ratio": round(latest_cnt / avg, 2),
                    }
                )
            if (at in ("all", "drop")) and latest_cnt <= (avg / th):
                alerts.append(
                    {
                        "chat_name": title,
                        "username": username,
                        "alert_type": "drop",
                        "date": latest_day,
                        "latest_count": latest_cnt,
                        "baseline_avg": round(avg, 2),
                        "ratio": round(latest_cnt / avg, 2),
                    }
                )

            if at in ("all", "mention"):
                mention_daily = conn.execute(
                    f"""
                    SELECT strftime('%Y-%m-%d', create_time, 'unixepoch', 'localtime') AS d,
                           SUM(CASE WHEN message_content LIKE '%@%' THEN 1 ELSE 0 END) AS c
                    FROM [{table_name}]
                    WHERE {where_sql}
                    GROUP BY d
                    ORDER BY d
                    """,
                    tuple(params),
                ).fetchall()
                if len(mention_daily) >= 3:
                    m_counts = [int(x[1] or 0) for x in mention_daily]
                    m_latest = m_counts[-1]
                    m_hist = m_counts[:-1]
                    m_avg = (sum(m_hist) / len(m_hist)) if m_hist else 0
                    if m_avg > 0 and m_latest >= m_avg * th:
                        alerts.append(
                            {
                                "chat_name": title,
                                "username": username,
                                "alert_type": "mention",
                                "date": str(mention_daily[-1][0]),
                                "latest_count": int(m_latest),
                                "baseline_avg": round(m_avg, 2),
                                "ratio": round(m_latest / m_avg, 2),
                            }
                        )
        except Exception:
            pass
        finally:
            conn.close()

    alerts.sort(key=lambda x: float(x.get("ratio", 0)), reverse=True)
    return _json_result(alerts[:500])


@mcp.tool()
def get_mention_analysis(
    chat_name: str,
    start_ts: int = 0,
    end_ts: int = 0,
) -> str:
    """分析 @ 提及网络与关键人物。"""
    username = resolve_username(chat_name)
    if not username:
        return _json_result({"error": f"找不到聊天对象: {chat_name}"})
    if "@chatroom" not in username:
        return _json_result({"error": "get_mention_analysis 仅支持群聊"})
    start_ts, end_ts = _norm_ts_range(start_ts, end_ts)

    db_path, table_name = _find_msg_table_for_user(username)
    if not db_path:
        return _json_result({"error": "找不到群聊消息记录"})

    names = get_contact_names()
    conn = sqlite3.connect(db_path)
    try:
        cols = _get_table_columns(conn, table_name)
        has_sender = "real_sender_id" in cols
        id2username, _username2ids = _load_name2id_maps(conn) if has_sender else ({}, {})
        where_sql, params = _build_msg_where(start_ts=start_ts, end_ts=end_ts, skip_compress=True)
        rows = conn.execute(
            f"""
            SELECT local_type, create_time, message_content, real_sender_id
            FROM [{table_name}]
            WHERE {where_sql}
            ORDER BY create_time DESC
            LIMIT 200000
            """,
            tuple(params),
        ).fetchall()
    except Exception as e:
        return _json_result({"error": f"提及分析失败: {e}"})
    finally:
        conn.close()

    mention_count = Counter()
    sent_count = Counter()
    edges = Counter()

    for local_type, _ts, content, real_sender_id in rows:
        lt = int(local_type or 0)
        sender_id = ""
        sender_name = ""
        if has_sender and isinstance(real_sender_id, int) and real_sender_id > 0:
            sender_id = id2username.get(int(real_sender_id), "")
            sender_name = names.get(sender_id, sender_id) if sender_id else ""
        parsed_sender, txt = _parse_message_content(content, lt, True)
        if not sender_name and parsed_sender:
            sender_name = names.get(parsed_sender, parsed_sender)
        if not sender_name:
            sender_name = "未知成员"
        sent_count[sender_name] += 1

        text = _strip_sender_prefix(txt, False)
        mentions = [m.strip() for m in re.findall(r"@([^\s@]{1,24})", text or "") if m.strip()]
        for m in mentions:
            mention_count[m] += 1
            edges[(sender_name, m)] += 1

    most_mentioned = [{"sender": k, "count": int(v)} for k, v in mention_count.most_common(30)]

    influencers = []
    all_names = set(sent_count.keys()) | set(mention_count.keys())
    for n in all_names:
        score = mention_count.get(n, 0) * 2 + sent_count.get(n, 0) * 0.2
        influencers.append({"sender": n, "influence_score": round(float(score), 3)})
    influencers.sort(key=lambda x: x["influence_score"], reverse=True)

    network = []
    for (frm, to), c in edges.most_common(200):
        network.append({"from": frm, "to": to, "count": int(c)})

    return _json_result(
        {
            "most_mentioned": most_mentioned,
            "influencers": influencers[:30],
            "mention_network": network,
        }
    )


@mcp.tool()
def generate_group_report(
    chat_name: str,
    report_type: str = "html",
    time_range: str = "last_30_days",
    include_sections: list = None,
) -> str:
    """生成群聊运营报告（html/markdown/json）。"""
    include_sections = include_sections if isinstance(include_sections, list) and include_sections else [
        "overview", "members", "topics", "trends"
    ]
    rtype = str(report_type or "html").strip().lower()
    if rtype == "pdf":
        return _json_result({"error": "当前版本暂不直接输出 PDF，请先导出 html/markdown 再转换"})
    if rtype not in ("html", "markdown", "json"):
        rtype = "html"

    start_ts, end_ts = _parse_time_range_alias(time_range)
    detail = json.loads(
        get_chat_detail_stats(
            chat_name=chat_name,
            start_ts=start_ts,
            end_ts=end_ts,
            include_topics=True,
            include_media_breakdown=True,
        )
    )
    if isinstance(detail, dict) and detail.get("error"):
        return _json_result(detail)

    member_stats = json.loads(
        get_group_member_stats(
            chat_name=chat_name,
            limit=30,
            start_ts=start_ts,
            end_ts=end_ts,
            include_metrics=["message_count", "word_count", "active_days", "media_count"],
        )
    )
    trend = json.loads(
        get_daily_message_trend(
            chat_name=chat_name,
            granularity="day",
            start_ts=start_ts,
            end_ts=end_ts,
        )
    )
    topics = json.loads(
        get_topic_distribution(
            chat_name=chat_name,
            start_ts=start_ts,
            end_ts=end_ts,
            min_topic_frequency=3,
            clustering_method="keyword",
        )
    )
    source_rows = json.loads(
        extract_shared_files(
            chat_name=chat_name,
            media_type="all",
            start_ts=start_ts,
            end_ts=end_ts,
            limit=5000,
        )
    )

    source_counter = Counter()
    if isinstance(source_rows, list):
        for row in source_rows:
            source_counter[str(row.get("source", "其他"))] += 1

    report = {
        "chat_name": detail.get("chat_name", chat_name),
        "username": detail.get("username", ""),
        "time_range": {
            "label": time_range,
            "start_ts": int(start_ts or 0),
            "end_ts": int(end_ts or 0),
        },
        "generated_at": int(time.time()),
        "sections": {},
    }
    if "overview" in include_sections:
        report["sections"]["overview"] = {
            "total_messages": detail.get("total_messages", 0),
            "member_count": detail.get("member_count", 0),
            "message_type_breakdown": detail.get("message_type_breakdown", {}),
            "media_breakdown": detail.get("media_breakdown", {}),
            "active_hours": detail.get("active_hours", {}),
        }
    if "members" in include_sections:
        report["sections"]["members"] = member_stats[:30] if isinstance(member_stats, list) else member_stats
    if "topics" in include_sections:
        report["sections"]["topics"] = (topics.get("topics", [])[:30] if isinstance(topics, dict) else topics)
        report["sections"]["source_distribution"] = dict(source_counter.most_common(20))
    if "trends" in include_sections:
        report["sections"]["trends"] = trend if isinstance(trend, list) else []

    export_dir = os.path.join(SCRIPT_DIR, "exports", "reports")
    os.makedirs(export_dir, exist_ok=True)
    safe_chat = re.sub(r"[\\/:*?\"<>|]+", "_", str(report.get("chat_name", "chat")))
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    if rtype == "json":
        out_path = os.path.join(export_dir, f"{safe_chat}_{stamp}.json")
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        return _json_result({"report_type": "json", "path": out_path, "summary": report.get("sections", {}).get("overview", {})})

    md_lines = [
        f"# {report['chat_name']} 运营报告",
        "",
        f"- 统计范围: `{time_range}`",
        f"- 生成时间: {datetime.fromtimestamp(report['generated_at']).strftime('%Y-%m-%d %H:%M:%S')}",
        "",
    ]
    if "overview" in report["sections"]:
        ov = report["sections"]["overview"]
        md_lines.extend([
            "## 概览",
            f"- 总消息数: {ov.get('total_messages', 0)}",
            f"- 成员数: {ov.get('member_count', 0)}",
            f"- 活跃峰值小时: {ov.get('active_hours', {}).get('peak')}",
            "",
        ])
    if "members" in report["sections"]:
        md_lines.append("## 成员活跃 TOP")
        for x in report["sections"]["members"][:20]:
            md_lines.append(
                f"- {x.get('rank', '-')}. {x.get('sender', '未知')}：{x.get('message_count', 0)} 条，活跃 {x.get('active_days', 0)} 天"
            )
        md_lines.append("")
    if "topics" in report["sections"]:
        md_lines.append("## 话题分布")
        for x in report["sections"]["topics"][:20]:
            md_lines.append(f"- {x.get('topic', '未知')}: {x.get('message_count', 0)} ({x.get('percentage', 0)}%)")
        md_lines.append("")
        md_lines.append("## 链接来源分布")
        for k, v in report["sections"].get("source_distribution", {}).items():
            md_lines.append(f"- {k}: {v}")
        md_lines.append("")
    if "trends" in report["sections"]:
        md_lines.append("## 每日消息趋势")
        for x in report["sections"]["trends"][-30:]:
            md_lines.append(f"- {x.get('date')}: 消息 {x.get('count', 0)} / 活跃成员 {x.get('unique_senders', 0)}")
        md_lines.append("")

    md_text = "\n".join(md_lines)
    if rtype == "markdown":
        out_path = os.path.join(export_dir, f"{safe_chat}_{stamp}.md")
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(md_text)
        return _json_result({"report_type": "markdown", "path": out_path, "preview": md_text[:1000]})

    # html
    out_path = os.path.join(export_dir, f"{safe_chat}_{stamp}.html")
    body = (
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<title>Group Report</title>"
        "<style>body{font-family:'Segoe UI','Microsoft YaHei',sans-serif;padding:24px;line-height:1.6;}pre{white-space:pre-wrap;}</style>"
        "</head><body><pre>"
        + md_text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        + "</pre></body></html>"
    )
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(body)
    return _json_result({"report_type": "html", "path": out_path, "preview": md_text[:1000]})


def _resolve_export_range(time_range="", start_ts=0, end_ts=0):
    alias_start, alias_end = _parse_time_range_alias(time_range)
    start_i = _clamp_int(start_ts, 0, 0, None)
    end_i = _clamp_int(end_ts, 0, 0, None)
    if not start_i and alias_start:
        start_i = alias_start
    if not end_i and alias_end:
        end_i = alias_end
    return _norm_ts_range(start_i, end_i)


def _format_ts_label(ts_value):
    ts_i = int(ts_value or 0)
    if ts_i <= 0:
        return "全部"
    return datetime.fromtimestamp(ts_i).strftime("%Y-%m-%d %H:%M:%S")


def _write_chat_markdown_part(export_dir, safe_chat, stamp, part_no, header_meta, message_blocks):
    md_lines = [
        f"# {header_meta['chat_name']} 聊天记录导出",
        "",
        f"- 统计范围: `{header_meta['time_range']}`",
        f"- 起始时间: {_format_ts_label(header_meta['start_ts'])}",
        f"- 结束时间: {_format_ts_label(header_meta['end_ts'])}",
        f"- 导出时间: {_format_ts_label(header_meta['generated_at'])}",
        f"- 分卷: {part_no}",
        f"- 本卷消息数: {len(message_blocks)}",
        "",
    ]
    for block in message_blocks:
        md_lines.extend(block)
    out_path = os.path.join(export_dir, f"{safe_chat}_{stamp}_part{part_no:02d}.md")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(md_lines).strip() + "\n")
    return out_path


@mcp.tool()
def export_chat_markdown(
    chat_name: str,
    time_range: str = "last_7_days",
    start_ts: int = 0,
    end_ts: int = 0,
    per_file_messages: int = 4000,
    max_chars_per_file: int = 700000,
    include_media: bool = True,
    include_system: bool = False,
) -> str:
    """导出聊天记录为 markdown 多分卷文件，适合 7/30 天全量深度分析。"""
    username = resolve_username(chat_name)
    if not username:
        return _json_result({"error": f"找不到聊天对象: {chat_name}"})

    start_ts, end_ts = _resolve_export_range(time_range=time_range, start_ts=start_ts, end_ts=end_ts)
    per_file_messages = _clamp_int(per_file_messages, 4000, 200, 10000)
    max_chars_per_file = _clamp_int(max_chars_per_file, 700000, 50000, 1200000)
    include_media = bool(include_media)
    include_system = bool(include_system)

    names = get_contact_names()
    display_name = names.get(username, username)
    is_group = "@chatroom" in username
    db_path, table_name = _find_msg_table_for_user(username)
    if not db_path:
        return _json_result({"error": "找不到消息表"})

    conn = sqlite3.connect(db_path)
    try:
        where_sql, params = _build_msg_where(start_ts=start_ts, end_ts=end_ts, skip_compress=True)
        rows = conn.execute(
            f"""
            SELECT local_id, local_type, create_time, status, real_sender_id, message_content
            FROM [{table_name}]
            WHERE {where_sql}
            ORDER BY create_time ASC
            """,
            tuple(params),
        ).fetchall()
        cols = _get_table_columns(conn, table_name)
        has_sender = "real_sender_id" in cols
        id2username, _username2ids = _load_name2id_maps(conn) if (is_group and has_sender) else ({}, {})
    except Exception as e:
        return _json_result({"error": f"导出 markdown 失败: {e}"})
    finally:
        conn.close()

    export_dir = _ensure_dir(EXPORT_CHAT_MD_DIR)
    safe_chat = _safe_filename(display_name, "chat")
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    header_meta = {
        "chat_name": display_name,
        "time_range": str(time_range or "custom"),
        "start_ts": int(start_ts or 0),
        "end_ts": int(end_ts or 0),
        "generated_at": int(time.time()),
    }

    files = []
    current_blocks = []
    current_chars = 0
    total_rows = 0
    part_no = 1

    def flush_part():
        nonlocal current_blocks, current_chars, part_no
        if not current_blocks:
            return
        out_path = _write_chat_markdown_part(export_dir, safe_chat, stamp, part_no, header_meta, current_blocks)
        files.append({
            "path": out_path,
            "part": part_no,
            "rows": len(current_blocks),
        })
        part_no += 1
        current_blocks = []
        current_chars = 0

    for _local_id, local_type, ts, status, real_sender_id, content in rows:
        lt = int(local_type or 0)
        if lt in (10000, 10002) and not include_system:
            continue
        if lt != 1 and lt not in (10000, 10002) and not include_media:
            continue

        sender_id, txt = _parse_message_content(content, lt, is_group)
        if not sender_id and is_group and isinstance(real_sender_id, int) and real_sender_id > 0:
            sender_id = id2username.get(int(real_sender_id), "")
        sender_name = names.get(sender_id, sender_id) if sender_id else ""
        if not sender_name:
            if is_group:
                sender_name = "未知成员"
            else:
                sender_name = "我" if int(status or 0) == 2 else display_name

        body = _strip_sender_prefix(txt, False).strip()
        if lt != 1:
            label = format_msg_type(lt)
            body = f"[{label}] {body}" if body else f"[{label}]"
        elif not body:
            body = "(空文本)"
        if len(body) > 5000:
            body = body[:5000] + "\n...(截断)"

        time_label = datetime.fromtimestamp(int(ts or 0)).strftime("%Y-%m-%d %H:%M:%S")
        block = [
            f"### {time_label} | {sender_name} | {format_msg_type(lt)}",
            "",
            body,
            "",
        ]
        block_chars = sum(len(x) + 1 for x in block)
        if current_blocks and (len(current_blocks) >= per_file_messages or (current_chars + block_chars) > max_chars_per_file):
            flush_part()
        current_blocks.append(block)
        current_chars += block_chars
        total_rows += 1

    flush_part()
    if not files:
        return _json_result({
            "chat_name": display_name,
            "path": "",
            "files": [],
            "rows": 0,
            "message": "当前时间范围内无可导出的消息",
        })
    preview_path = files[0]["path"]
    return _json_result({
        "chat_name": display_name,
        "username": username,
        "time_range": str(time_range or "custom"),
        "start_ts": int(start_ts or 0),
        "end_ts": int(end_ts or 0),
        "rows": int(total_rows),
        "files": files,
        "path": preview_path,
    })


def _resolve_export_read_path(path):
    raw = str(path or "").strip()
    if not raw:
        raise RuntimeError("path 不能为空")
    candidate = raw
    if not os.path.isabs(candidate):
        candidate = os.path.join(SCRIPT_DIR, candidate)
    candidate = os.path.abspath(candidate)
    exports_root = os.path.abspath(os.path.join(SCRIPT_DIR, "exports"))
    try:
        if os.path.commonpath([candidate, exports_root]) != exports_root:
            raise RuntimeError("只允许读取 exports 目录下的导出文件")
    except ValueError:
        raise RuntimeError("导出文件路径非法")
    if not os.path.exists(candidate):
        raise RuntimeError(f"文件不存在: {candidate}")
    if not candidate.lower().endswith(".md"):
        raise RuntimeError("当前只支持读取 markdown 导出文件")
    return candidate


@mcp.tool()
def read_exported_markdown(path: str, start_line: int = 1, max_lines: int = 1200) -> str:
    """读取 export_chat_markdown 导出的 markdown 文件，支持按行分页。"""
    file_path = _resolve_export_read_path(path)
    start_line = _clamp_int(start_line, 1, 1, 10_000_000)
    max_lines = _clamp_int(max_lines, 1200, 50, 4000)
    with open(file_path, "r", encoding="utf-8") as f:
        lines = f.read().splitlines()
    total = len(lines)
    start_idx = max(0, start_line - 1)
    end_idx = min(total, start_idx + max_lines)
    chunk = "\n".join(lines[start_idx:end_idx])
    return _json_result({
        "path": file_path,
        "start_line": start_idx + 1,
        "end_line": end_idx,
        "total_lines": total,
        "has_more": end_idx < total,
        "next_start_line": (end_idx + 1) if end_idx < total else None,
        "content": chunk,
    })


@mcp.tool()
def export_chat_data(
    chat_name: str,
    format: str = "csv",
    start_ts: int = 0,
    end_ts: int = 0,
    include_metadata: bool = True,
) -> str:
    """导出聊天原始数据（csv/json/excel）。"""
    username = resolve_username(chat_name)
    if not username:
        return _json_result({"error": f"找不到聊天对象: {chat_name}"})
    start_ts, end_ts = _norm_ts_range(start_ts, end_ts)
    fmt = str(format or "csv").strip().lower()
    if fmt not in ("csv", "json", "excel"):
        fmt = "csv"

    names = get_contact_names()
    is_group = "@chatroom" in username
    db_path, table_name = _find_msg_table_for_user(username)
    if not db_path:
        return _json_result({"error": "找不到消息表"})

    conn = sqlite3.connect(db_path)
    try:
        where_sql, params = _build_msg_where(start_ts=start_ts, end_ts=end_ts, skip_compress=True)
        rows = conn.execute(
            f"""
            SELECT local_id, local_type, create_time, status, real_sender_id, message_content
            FROM [{table_name}]
            WHERE {where_sql}
            ORDER BY create_time DESC
            """,
            tuple(params),
        ).fetchall()
        id2username, _username2ids = _load_name2id_maps(conn)
    except Exception as e:
        return _json_result({"error": f"导出查询失败: {e}"})
    finally:
        conn.close()

    export_dir = os.path.join(SCRIPT_DIR, "exports", "chat_data")
    os.makedirs(export_dir, exist_ok=True)
    display_name = names.get(username, username)
    safe_chat = re.sub(r"[\\/:*?\"<>|]+", "_", str(display_name))
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    data_rows = []
    for local_id, local_type, ts, status, real_sender_id, content in rows:
        lt = int(local_type or 0)
        sender_id, txt = _parse_message_content(content, lt, is_group)
        if not sender_id and isinstance(real_sender_id, int) and real_sender_id > 0:
            sender_id = id2username.get(int(real_sender_id), "")
        text = _strip_sender_prefix(txt, False)
        row = {
            "local_id": int(local_id or 0),
            "create_time": int(ts or 0),
            "time": datetime.fromtimestamp(int(ts or 0)).strftime("%Y-%m-%d %H:%M:%S"),
            "local_type": lt,
            "msg_type": format_msg_type(lt),
            "sender_id": sender_id or "",
            "sender": names.get(sender_id, sender_id) if sender_id else "",
            "status": int(status or 0),
            "content": text,
        }
        if include_metadata:
            urls = re.findall(r"https?://[^\s]+", text or "")
            row["source_tag"] = _classify_source(text)
            row["url"] = urls[0] if urls else ""
        data_rows.append(row)

    if fmt == "json":
        out_path = os.path.join(export_dir, f"{safe_chat}_{stamp}.json")
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(data_rows, f, ensure_ascii=False, indent=2)
        return _json_result({"path": out_path, "format": "json", "rows": len(data_rows)})

    if fmt == "excel":
        try:
            import openpyxl  # type: ignore
            from openpyxl import Workbook  # type: ignore
            out_path = os.path.join(export_dir, f"{safe_chat}_{stamp}.xlsx")
            wb = Workbook()
            ws = wb.active
            ws.title = "chat_data"
            headers = list(data_rows[0].keys()) if data_rows else [
                "local_id", "create_time", "time", "local_type", "msg_type", "sender_id", "sender", "status", "content"
            ]
            ws.append(headers)
            for row in data_rows:
                ws.append([row.get(h, "") for h in headers])
            wb.save(out_path)
            return _json_result({"path": out_path, "format": "excel", "rows": len(data_rows)})
        except Exception:
            # Fallback to CSV when openpyxl is unavailable.
            fmt = "csv"

    out_path = os.path.join(export_dir, f"{safe_chat}_{stamp}.csv")
    headers = list(data_rows[0].keys()) if data_rows else [
        "local_id", "create_time", "time", "local_type", "msg_type", "sender_id", "sender", "status", "content"
    ]
    with open(out_path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        for row in data_rows:
            writer.writerow(row)
    return _json_result({"path": out_path, "format": "csv", "rows": len(data_rows)})


@mcp.tool()
def get_contacts(query: str = "", limit: int = 120) -> str:
    """搜索或列出微信联系人。

    Args:
        query: 搜索关键字（匹配昵称、备注、wxid），留空则列出全部
        limit: 返回数量，默认 120，最大 2000
    """
    limit = _clamp_int(limit, 120, 1, 2000)
    contacts = get_contact_full()
    if not contacts:
        return "错误: 无法加载联系人数据"

    if query:
        q = query.lower()
        filtered = [
            c for c in contacts
            if q in c['nick_name'].lower()
            or q in c['remark'].lower()
            or q in c['username'].lower()
        ]
    else:
        filtered = contacts

    filtered = filtered[:limit]

    if not filtered:
        return f"未找到匹配 \"{query}\" 的联系人"

    lines = []
    for c in filtered:
        line = c['username']
        if c['remark']:
            line += f"  备注: {c['remark']}"
        if c['nick_name']:
            line += f"  昵称: {c['nick_name']}"
        lines.append(line)

    header = f"找到 {len(filtered)} 个联系人"
    if query:
        header += f"（搜索: {query}）"
    return header + ":\n\n" + "\n".join(lines)


@mcp.tool()
def get_new_messages() -> str:
    """获取自上次调用以来的新消息。首次调用返回当前未读会话。"""
    global _last_check_state

    path = _cache.get("session\\session.db")
    if not path:
        return "错误: 无法解密 session.db"

    names = get_contact_names()
    conn = sqlite3.connect(path)
    rows = conn.execute("""
        SELECT username, unread_count, summary, last_timestamp,
               last_msg_type, last_msg_sender, last_sender_display_name
        FROM SessionTable
        WHERE last_timestamp > 0
        ORDER BY last_timestamp DESC
    """).fetchall()
    conn.close()

    curr_state = {}
    for r in rows:
        username, unread, summary, ts, msg_type, sender, sender_name = r
        curr_state[username] = {
            'unread': unread, 'summary': summary, 'timestamp': ts,
            'msg_type': msg_type, 'sender': sender or '', 'sender_name': sender_name or '',
        }

    if not _last_check_state:
        _last_check_state = {u: s['timestamp'] for u, s in curr_state.items()}
        # 首次调用，返回当前未读会话
        unread_msgs = []
        for username, s in curr_state.items():
            if s['unread'] and s['unread'] > 0:
                display = names.get(username, username)
                is_group = '@chatroom' in username
                summary = s['summary']
                if isinstance(summary, str) and ':\n' in summary:
                    summary = summary.split(':\n', 1)[1]
                elif isinstance(summary, bytes):
                    summary = '(压缩内容)'
                time_str = datetime.fromtimestamp(s['timestamp']).strftime('%H:%M')
                tag = "[群]" if is_group else ""
                unread_msgs.append(f"[{time_str}] {display}{tag} ({s['unread']}条未读): {summary}")

        if unread_msgs:
            return f"当前 {len(unread_msgs)} 个未读会话:\n\n" + "\n".join(unread_msgs)
        return "当前无未读消息（已记录状态，下次调用将返回新增消息）"

    # 与上次状态做对比
    new_msgs = []
    for username, s in curr_state.items():
        prev_ts = _last_check_state.get(username, 0)
        if s['timestamp'] > prev_ts:
            display = names.get(username, username)
            is_group = '@chatroom' in username
            summary = s['summary']
            if isinstance(summary, str) and ':\n' in summary:
                summary = summary.split(':\n', 1)[1]
            elif isinstance(summary, bytes):
                summary = '(压缩内容)'

            sender_display = ''
            if is_group and s['sender']:
                sender_display = names.get(s['sender'], s['sender_name'] or s['sender'])

            time_str = datetime.fromtimestamp(s['timestamp']).strftime('%H:%M:%S')
            entry = f"[{time_str}] {display}"
            if is_group:
                entry += " [群]"
            entry += f": {format_msg_type(s['msg_type'])}"
            if sender_display:
                entry += f" ({sender_display})"
            entry += f" - {summary}"
            new_msgs.append((s['timestamp'], entry))

    _last_check_state = {u: s['timestamp'] for u, s in curr_state.items()}

    if not new_msgs:
        return "无新消息"

    new_msgs.sort(key=lambda x: x[0])
    entries = [m[1] for m in new_msgs]
    return f"{len(entries)} 条新消息:\n\n" + "\n".join(entries)


if __name__ == "__main__":
    mcp.run()
