import re
import unittest
from pathlib import Path

import monitor_web as mw


CHATLOG_SAMPLE = """<msg><appmsg><title>群聊的聊天记录</title><type>19</type><recorditem><![CDATA[<recordinfo><datalist count="4"><dataitem><sourcename>nunmocsae</sourcename><datadesc>@teammate OPENCLAW</datadesc></dataitem><dataitem><sourcename>nunmocsae</sourcename><datadesc>又是什么东西</datadesc></dataitem><dataitem><sourcename>nunmocsae</sourcename><datadesc>要把我淘汰了吗</datadesc></dataitem><dataitem><sourcename>nunmocsae</sourcename><datadesc>我们A总很闹麻的</datadesc></dataitem></datalist></recordinfo>]]></recorditem><refermsg><displayname>nunmocsae</displayname><content>@teammate OPENCLAW</content></refermsg></appmsg></msg>"""

HTML = Path(__file__).resolve().parents[1] / "monitor_web.html"
HTML_TEXT = HTML.read_text(encoding="utf-8")


class MonitorWebChatlogRegressionTests(unittest.TestCase):
    def test_forwarded_chatlog_prefers_chatlog_card_over_quote_card(self):
        rich = mw._build_appmsg_rich_media("", source_blob=CHATLOG_SAMPLE)
        self.assertEqual(rich["kind"], "chatlog")
        self.assertEqual(rich["badge"], "聊天记录")
        self.assertEqual(rich["title"], "群聊的聊天记录")
        self.assertEqual(rich["source"], "微信聊天记录")
        self.assertTrue(rich["suppress_content"])
        self.assertEqual(
            rich["items"][:2],
            [
                {"name": "nunmocsae", "text": "@teammate OPENCLAW"},
                {"name": "nunmocsae", "text": "又是什么东西"},
            ],
        )

    def test_forwarded_chatlog_uses_chatlog_message_type_not_quote(self):
        self.assertEqual(mw._display_msg_type(49, "", CHATLOG_SAMPLE), "聊天记录")
        self.assertEqual(mw._display_msg_type_icon(49, "", CHATLOG_SAMPLE), "CHATLOG")

    def test_forwarded_chatlog_preview_logic_keeps_chatlog_out_of_quote_bucket(self):
        py_text = Path(mw.__file__).read_text(encoding="utf-8")
        self.assertRegex(
            py_text,
            re.compile(
                r"if msg_type == 49 and source_text:.*?quote_types = \{40, 57\}.*?is_chatlog = appmsg_type == 19 or bool\(_extract_recorditem_items\(",
                re.S,
            ),
        )

    def test_chatlog_rich_media_has_dedicated_wechat_style_markup(self):
        self.assertRegex(
            HTML_TEXT,
            re.compile(
                r"if \(meta\.kind === 'chatlog'\)\s*\{.*?msg-chatlog-inline.*?msg-chatlog-inline-title.*?msg-chatlog-inline-footer",
                re.S,
            ),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.msg-chatlog-inline\s*\{", re.S),
        )


if __name__ == "__main__":
    unittest.main()
