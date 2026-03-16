import re
import unittest
from pathlib import Path


PY = Path(__file__).resolve().parents[1] / "monitor_web.py"
TEXT = PY.read_text(encoding="utf-8")


class MonitorWebHistoryFastPathTests(unittest.TestCase):
    def test_message_row_loader_pushes_limit_into_fast_sql_path(self):
        self.assertRegex(
            TEXT,
            re.compile(
                r"def _fetch_direct\(lo, hi\):.*?ORDER BY create_time \{order_dir\}, local_id \{order_dir\}.*?if int\(limit or 0\) > 0:\s*sql \+= \" LIMIT \?\"",
                re.S,
            ),
        )

    def test_chat_history_route_supports_fast_mode_without_fts_and_resource_enrichment(self):
        self.assertRegex(TEXT, re.compile(r"fast_mode = str\(query\.get\('fast', \[''\]\)\[0\] or ''\)\.strip\(\)\.lower\(\) in \{'1', 'true', 'yes', 'fast'\}"))
        self.assertRegex(
            TEXT,
            re.compile(
                r"if fast_mode:\s*resource_server_map, resource_local_map = \{\}, \{\}\s*fts_fallback_map = \{\}\s*else:\s*resource_server_map, resource_local_map = _load_resource_meta_maps",
                re.S,
            ),
        )

    def test_chat_history_route_supports_cursor_paging_metadata(self):
        self.assertRegex(TEXT, re.compile(r"paged_mode = str\(query\.get\('paged', \[''\]\)\[0\] or ''\)\.strip\(\)\.lower\(\) in \{'1', 'true', 'yes', 'paged'\}"))
        self.assertRegex(TEXT, re.compile(r"before_ts = _safe_int\(query\.get\('before_ts', \['0'\]\)\[0\], 0, 0, None\)"))
        self.assertRegex(TEXT, re.compile(r"before_local_id = _safe_int\(query\.get\('before_local_id', \['0'\]\)\[0\], 0, 0, None\)"))
        self.assertRegex(
            TEXT,
            re.compile(
                r"page_limit = limit if paged_mode else 0.*?query_limit = \(page_limit \+ 1\) if page_limit > 0 else limit",
                re.S,
            ),
        )
        self.assertRegex(
            TEXT,
            re.compile(
                r"if paged_mode:\s*self\._send_json\(\{\s*'rows': data,\s*'has_more': has_more,\s*'next_before_ts': next_before_ts,\s*'next_before_local_id': next_before_local_id,",
                re.S,
            ),
        )

    def test_chat_history_route_uses_non_blocking_message_db_ready_helper(self):
        self.assertIn("def ensure_message_db_ready_for_read(", TEXT)
        self.assertIn("refresh_info = ensure_message_db_ready_for_read(", TEXT)
        self.assertIn("prefer_stale=True", TEXT)

    def test_message_db_async_refresh_scheduler_exists(self):
        self.assertIn("def _schedule_message_db_refresh(", TEXT)
        self.assertIn("message_db_async_refresh_state", TEXT)
        self.assertIn("threading.Thread(", TEXT)


if __name__ == "__main__":
    unittest.main()
