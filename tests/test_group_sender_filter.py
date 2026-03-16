import unittest

import monitor_web as mw


class GroupSenderFilterTests(unittest.TestCase):
    def test_skip_unmapped_pseudo_sender_bucket(self):
        self.assertTrue(
            mw._should_skip_sender_aggregate(
                sender_id="rid:94",
                sender_name="成员#94",
                text_count=0,
                media_count=0,
                link_count=188,
                system_count=218,
            )
        )

    def test_keep_normal_known_sender_even_if_link_heavy(self):
        self.assertFalse(
            mw._should_skip_sender_aggregate(
                sender_id="wxid_alice",
                sender_name="Alice",
                text_count=0,
                media_count=0,
                link_count=32,
                system_count=0,
            )
        )

    def test_keep_unmapped_sender_when_text_messages_exist(self):
        self.assertFalse(
            mw._should_skip_sender_aggregate(
                sender_id="rid:128",
                sender_name="成员#128",
                text_count=5,
                media_count=0,
                link_count=2,
                system_count=0,
            )
        )


if __name__ == "__main__":
    unittest.main()
