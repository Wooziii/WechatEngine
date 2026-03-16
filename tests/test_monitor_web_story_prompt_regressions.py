import re
import unittest
from pathlib import Path


PY = Path(__file__).resolve().parents[1] / "monitor_web.py"
TEXT = PY.read_text(encoding="utf-8")


class MonitorWebStoryPromptRegressionTests(unittest.TestCase):
    def test_report_schema_hint_includes_story_fields(self):
        self.assertIn('"story_title":"", "story_dek":"", ', TEXT)
        self.assertIn('"story_points":[""], "story_tags":[""], ', TEXT)
        self.assertIn('"story_questions":[{"title":"","reason":"","evidence":"","target_hint":"peak|topic|member|quality"}]', TEXT)
        self.assertIn('"turning_points":[{"date":"","title":"","detail":"","evidence":"","topic":"","member":"","tone":"positive|neutral|warn|danger"}]', TEXT)

    def test_report_seed_calls_prioritize_raw_evidence_tools(self):
        self.assertRegex(
            TEXT,
            re.compile(
                r"if module == 'report':.*?_push\('get_round_table_candidates'.*?_push\('get_high_quality_candidates'.*?if top_keywords:.*?_push\('search_messages'.*?if top_sender:.*?_push\('get_sender_profile'.*?_push\('get_daily_message_trend'",
                re.S,
            ),
        )

    def test_topic_and_persona_seed_calls_chase_topics_people_and_quotes(self):
        self.assertRegex(
            TEXT,
            re.compile(
                r"elif module == 'topic':.*?_push\('get_topic_distribution'.*?_push\('get_round_table_candidates'.*?if top_keywords:.*?_push\('search_messages'.*?_push\('get_high_quality_candidates'",
                re.S,
            ),
        )
        self.assertRegex(
            TEXT,
            re.compile(
                r"elif module == 'persona':.*?_push\('get_member_profile_cards'.*?_push\('get_group_member_stats'.*?if top_sender:.*?_push\('get_sender_profile'.*?_push\('get_sender_messages'",
                re.S,
            ),
        )

    def test_persona_schema_and_guide_include_fun_guess_fields(self):
        self.assertIn('"mbti_guess":"","animal":"","archetype":"","vibe_tags":[""],"energy_style":""', TEXT)
        self.assertIn('"fun_title":"","mbti_guess":"","mbti_reason":"","animal":"","animal_reason":"","social_style":"","vibe_tags":[""]', TEXT)
        self.assertIn("how others followed or responded, and what interaction style supports playful MBTI/animal/archetype guesses.", TEXT)
        self.assertIn("每张成员卡都要包含代表发言 quote、insight、next_step、mbti_guess、animal、vibe_tags、social_style。", TEXT)
        self.assertIn("MBTI 和动物只能写成基于行为的轻量猜测，必须给出 mbti_reason / animal_reason，不能写成确定事实。", TEXT)

    def test_mcp_prompts_require_specific_storytelling_and_exact_entities(self):
        self.assertIn("Prefer exact dates, member names, topic names, file/link names, and trigger events over vague summaries.", TEXT)
        self.assertIn("Reconstruct what happened like a readable postmortem, not a flat dashboard dump.", TEXT)
        self.assertIn("语气要求专业但有人味，像真正读过聊天记录的人在写复盘，不要冷冰冰罗列数据，也不要文学化夸张。", TEXT)
        self.assertIn("story_points 写 3-5 条具体剧情线，尽量包含日期、人物、话题、结果。", TEXT)

    def test_report_fallback_and_normalizer_preserve_story_slots(self):
        self.assertIn("'story_title': f\"", TEXT)
        self.assertIn("'story_points': [", TEXT)
        self.assertIn("'story_questions': [", TEXT)
        self.assertIn("'turning_points': [", TEXT)
        self.assertRegex(
            TEXT,
            re.compile(
                r"_ensure_list\('story_points',\s*3\).*?_ensure_list\('story_tags',\s*3\).*?_ensure_list\('story_questions',\s*3\).*?_ensure_list\('turning_points',\s*2\)",
                re.S,
            ),
        )

    def test_ai_module_result_embeds_chat_context_scope(self):
        self.assertRegex(
            TEXT,
            re.compile(
                r"result = \{.*?'context': \{.*?'username': username,.*?'chat': full_data\.get\('chat', username\),.*?'start_ts': int\(start_ts or 0\),.*?'end_ts': int\(end_ts or 0\),",
                re.S,
            ),
        )


if __name__ == "__main__":
    unittest.main()
