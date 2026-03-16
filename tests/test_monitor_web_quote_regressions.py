import unittest
from pathlib import Path


PY = Path(__file__).resolve().parents[1] / "monitor_web.py"
TEXT = PY.read_text(encoding="utf-8")


class MonitorWebQuoteRegressionTests(unittest.TestCase):
    def test_refer_content_does_not_treat_display_name_as_quote_body(self):
        marker = "def _extract_refer_content(xml_text):"
        start = TEXT.index(marker)
        snippet = TEXT[start:start + 900]
        self.assertIn('_xml_tag_text(refer_block, "title")', snippet)
        self.assertNotIn('_xml_tag_text(refer_block, "displayname")', snippet)

    def test_appmsg_quote_payload_uses_refer_content_fallback_and_drops_author_only_preview(self):
        marker = "def _build_appmsg_rich_media(rendered_text, source_blob=None, link_source=\"\", link_url=\"\", media_url=\"\"):"
        start = TEXT.index(marker)
        snippet = TEXT[start:start + 2800]
        self.assertIn('_extract_refer_content(source_text)', snippet)
        self.assertIn('if ref_name and ref_preview and ref_name == ref_preview:', snippet)
        self.assertIn('ref_preview = ""', snippet)

    def test_display_type_promotes_quote_appmsg_over_generic_link_file(self):
        marker = "def _display_msg_type(msg_type, content=\"\", source_blob=None):"
        start = TEXT.index(marker)
        snippet = TEXT[start:start + 1600]
        self.assertIn("if t == 49:", snippet)
        self.assertIn("_extract_refer_content(source_text)", snippet)
        self.assertIn('appmsg_type in {40, 57}', snippet)
        self.assertIn('return "引用消息"', snippet)

    def test_display_type_icon_promotes_quote_appmsg(self):
        marker = "def _display_msg_type_icon(msg_type, content=\"\", source_blob=None):"
        start = TEXT.index(marker)
        snippet = TEXT[start:start + 1600]
        self.assertIn("if t == 49:", snippet)
        self.assertIn("_extract_refer_content(source_text)", snippet)
        self.assertIn('return "QUOTE"', snippet)


if __name__ == "__main__":
    unittest.main()
