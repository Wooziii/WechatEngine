import unittest
import json
import os
import tempfile

import monitor_web as mw


class LiveAlertTests(unittest.TestCase):
    def test_normalize_live_alert_config_dedupes_keywords(self):
        cfg = mw._normalize_live_alert_config({
            "enabled": 1,
            "notify_min_severity": "urgent",
            "watch_mode": "weird",
            "watch_usernames": ["room_a@chatroom", "room_a@chatroom", ""],
            "product_keywords": "牛马AI, 牛马AI\n会员",
        })
        self.assertTrue(cfg["enabled"])
        self.assertEqual(cfg["notify_min_severity"], "medium")
        self.assertEqual(cfg["watch_mode"], "pinned_auto")
        self.assertEqual(cfg["watch_usernames"], ["room_a@chatroom"])
        self.assertEqual(cfg["product_keywords"], ["牛马AI", "会员"])

    def test_build_candidate_for_product_question(self):
        cfg = mw._normalize_live_alert_config({
            "enabled": True,
            "watch_usernames": ["room_a@chatroom"],
            "product_keywords": ["牛马AI", "会员"],
            "question_keywords": ["怎么", "？"],
        })
        cand = mw._build_live_alert_candidate({
            "username": "room_a@chatroom",
            "is_group": True,
            "type": "文本",
            "content": "请问牛马AI会员怎么开通？",
        }, cfg)
        self.assertIsNotNone(cand)
        self.assertIn("product", cand["tags"])
        self.assertIn("question", cand["tags"])
        self.assertGreaterEqual(cand["heuristic_score"], 3)

    def test_build_candidate_skips_chatty_noise(self):
        cfg = mw._normalize_live_alert_config({
            "enabled": True,
            "watch_usernames": ["room_a@chatroom"],
            "ignore_keywords": ["哈哈", "收到"],
        })
        cand = mw._build_live_alert_candidate({
            "username": "room_a@chatroom",
            "is_group": True,
            "type": "文本",
            "content": "哈哈收到",
        }, cfg)
        self.assertIsNone(cand)

    def test_build_candidate_requires_watchlist(self):
        cfg = mw._normalize_live_alert_config({
            "enabled": True,
            "watch_usernames": [],
        })
        cand = mw._build_live_alert_candidate({
            "username": "room_a@chatroom",
            "is_group": True,
            "type": "文本",
            "content": "请问这个产品怎么开通？",
        }, cfg)
        self.assertIsNone(cand)

    def test_normalize_live_alert_config_normalizes_openclaw_fields(self):
        cfg = mw._normalize_live_alert_config({
            "openclaw_push_enabled": 1,
            "openclaw_push_min_severity": "urgent",
            "openclaw_push_categories": ["bug_report", "BUG_REPORT", "weird"],
            "openclaw_push_thread_id": 0,
            "openclaw_push_chat_id": " -100123 ",
            "openclaw_push_topic_label": "  notes  ",
        })
        self.assertTrue(cfg["openclaw_push_enabled"])
        self.assertEqual(cfg["openclaw_push_min_severity"], "medium")
        self.assertEqual(cfg["openclaw_push_categories"], ["bug_report"])
        self.assertEqual(cfg["openclaw_push_thread_id"], 88)
        self.assertEqual(cfg["openclaw_push_chat_id"], "-100123")
        self.assertEqual(cfg["openclaw_push_topic_label"], "notes")

    def test_should_push_live_alert_to_openclaw_checks_threshold_and_category(self):
        cfg = mw._normalize_live_alert_config({
            "openclaw_push_enabled": True,
            "openclaw_push_chat_id": "-100123",
            "openclaw_push_min_severity": "high",
            "openclaw_push_categories": ["bug_report"],
        })
        ok, reason = mw._should_push_live_alert_to_openclaw({
            "severity": "medium",
            "category": "bug_report",
        }, cfg)
        self.assertFalse(ok)
        self.assertEqual(reason, "below_threshold")

        ok, reason = mw._should_push_live_alert_to_openclaw({
            "severity": "high",
            "category": "product_question",
        }, cfg)
        self.assertFalse(ok)
        self.assertEqual(reason, "category_filtered")

        ok, reason = mw._should_push_live_alert_to_openclaw({
            "severity": "high",
            "category": "bug_report",
        }, cfg)
        self.assertTrue(ok)
        self.assertEqual(reason, "ready")

    def test_format_openclaw_message_contains_core_fields(self):
        cfg = mw._normalize_live_alert_config({
            "openclaw_push_topic_label": "notes",
        })
        text = mw._format_openclaw_live_alert_message({
            "title": "用户反馈购买后未到账",
            "severity": "medium",
            "category": "negative_feedback",
            "confidence": 90,
            "chat": "野人开智教化小队",
            "sender": "Alice",
            "content": "用户表示已经购买但权限未开通",
            "reason": "明显是售后问题",
            "suggested_action": "尽快核对订单",
        }, cfg)
        self.assertIn("【社群问题提醒】负反馈", text)
        self.assertIn("群聊：野人开智教化小队", text)
        self.assertIn("发送者：Alice", text)
        self.assertIn("建议：尽快核对订单", text)


class LiveAlertHistoryTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.orig_alerts_file = mw.LIVE_ALERTS_FILE
        self.orig_live_alerts = list(mw.live_alerts)
        self.orig_broadcast_sse = mw.broadcast_sse
        mw.LIVE_ALERTS_FILE = os.path.join(self.tmpdir.name, "live_alerts.json")
        mw.live_alerts = []
        mw.broadcast_sse = lambda payload: None

    def tearDown(self):
        mw.LIVE_ALERTS_FILE = self.orig_alerts_file
        mw.live_alerts = self.orig_live_alerts
        mw.broadcast_sse = self.orig_broadcast_sse
        self.tmpdir.cleanup()

    def _seed_alerts(self, rows):
        with open(mw.LIVE_ALERTS_FILE, "w", encoding="utf-8") as f:
            json.dump(rows, f, ensure_ascii=False, indent=2)
        mw.live_alerts = []

    def test_acknowledged_alert_is_kept_in_history_listing(self):
        row = {
            "id": "alert_ack_1",
            "status": "open",
            "category": "product_question",
            "title": "产品咨询 · Alice: 会员怎么开",
            "content": "请问会员怎么开通？",
            "chat": "产品答疑群",
            "sender": "Alice",
            "message_ts": 1710000000,
            "created_at": 1710000001,
        }

        mw._append_live_alert(row)
        updated = mw._update_live_alert_status("alert_ack_1", "acknowledged")
        history_rows = mw._list_live_alerts(limit=20, status="history")

        self.assertIsNotNone(updated)
        self.assertEqual(updated["status"], "acknowledged")
        self.assertEqual([item["id"] for item in history_rows], ["alert_ack_1"])
        self.assertEqual(history_rows[0]["status"], "acknowledged")

    def test_list_live_alerts_filters_by_history_keyword_category_and_time_range(self):
        self._seed_alerts([
            {
                "id": "alert_1",
                "status": "acknowledged",
                "category": "product_question",
                "title": "产品咨询 · Alice: 会员怎么开",
                "content": "请问牛马AI会员怎么开通？",
                "chat": "产品答疑群",
                "sender": "Alice",
                "message_ts": 1710000600,
                "created_at": 1710000601,
            },
            {
                "id": "alert_2",
                "status": "dismissed",
                "category": "bug_report",
                "title": "故障反馈 · Bob: 接口报错",
                "content": "调用接口一直报错 500",
                "chat": "Bug群",
                "sender": "Bob",
                "message_ts": 1710001200,
                "created_at": 1710001201,
            },
            {
                "id": "alert_3",
                "status": "open",
                "category": "product_question",
                "title": "产品咨询 · Carol: 支持微信对接吗",
                "content": "Workbuddy 能不能接微信？",
                "chat": "售前群",
                "sender": "Carol",
                "message_ts": 1710001800,
                "created_at": 1710001801,
            },
        ])

        rows = mw._list_live_alerts(
            limit=20,
            status="history",
            keyword="会员",
            category="product_question",
            start_ts=1710000000,
            end_ts=1710000900,
        )

        self.assertEqual([item["id"] for item in rows], ["alert_1"])


if __name__ == "__main__":
    unittest.main()
