import re
import unittest
from pathlib import Path


HTML = Path(__file__).resolve().parents[1] / "analysis_web.html"
HTML_TEXT = HTML.read_text(encoding="utf-8")


class AnalysisWebBrandingTests(unittest.TestCase):
    def test_analysis_branding_uses_wechatengine_and_unified_slogan(self):
        self.assertIn("<title>WechatEngine · 微信群聊监控与洞察台</title>", HTML_TEXT)
        self.assertIn(">WechatEngine</span>", HTML_TEXT)
        self.assertIn("微信群聊监控与洞察台", HTML_TEXT)
        self.assertNotIn("TopicEngine", HTML_TEXT)
        self.assertNotIn("托皮暗井", HTML_TEXT)

    def test_activity_streak_board_uses_compact_leaderboard_layout(self):
        self.assertIn("连续活跃成员排行榜", HTML_TEXT)
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.streak-row\s*\{[^}]*grid-template-columns:\s*minmax\(0,\s*1\.55fr\)\s*minmax\(112px,\s*0\.5fr\)\s*minmax\(112px,\s*0\.5fr\)\s*minmax\(112px,\s*0\.5fr\)\s*!important;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"const heatScore=Math\.max\(32,\s*Math\.min\(99,\s*Math\.round\(streakPct\*0\.58\+messagePct\*0\.42\)\)\);", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r'<div class="streak-row-kpis">.*?<div class="streak-stat emphasis">.*?连续活跃.*?累计消息.*?日均输出', re.S),
        )
        self.assertIn("function streakRankEmoji(index){", HTML_TEXT)
        self.assertIn("function streakTagEmoji(tag,idx=0){", HTML_TEXT)
        self.assertRegex(
            HTML_TEXT,
            re.compile(r'<span class="streak-rank-badge"><span class="streak-rank-glyph">\$\{esc\(rankEmoji\)\}</span><b class="streak-rank-num">\$\{i\+1\}</b></span>', re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r'<span class="streak-title-badge">\$\{esc\(titleEmoji\)\}\s+\$\{esc\(titleTag\)\}</span>', re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r'<span class="streak-ai-tag"><span class="tag-emoji">\$\{esc\(streakTagEmoji\(tag,tagIdx\)\)\}</span>\$\{esc\(tag\)\}</span>', re.S),
        )

    def test_insight_role_section_uses_responsive_single_column_fallback(self):
        self.assertIn("insight-role-section", HTML_TEXT)
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"#page-insight\s+\.insight-role-section\s+\.insight-role-grid\s*\{[^}]*grid-template-columns:\s*minmax\(0,\s*1\.1fr\)\s*minmax\(260px,\s*0\.9fr\)\s*!important;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"@media\s+\(max-width:\s*1180px\)\s*\{[^}]*#page-insight\s+\.insight-role-section\s+\.insight-role-grid\s*\{[^}]*grid-template-columns:\s*1fr\s*!important;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"@media\s+\(max-width:\s*1180px\)\s*\{.*?#page-insight\s+\.insight-role-section\s+\.insight-summary-points\s*\{[^}]*grid-template-columns:\s*1fr\s*!important;", re.S),
        )

    def test_overview_summary_uses_more_compact_type_scale(self):
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.overview-summary-line\s*\{[^}]*font-size:\s*16px;[^}]*line-height:\s*1\.58;[^}]*font-style:\s*normal;[^}]*font-weight:\s*700;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.overview-summary-badge\s*\{[^}]*font-size:\s*11px;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.overview-summary-tag\s*\{[^}]*font-size:\s*12px;", re.S),
        )

    def test_activity_fallback_no_longer_uses_misleading_unavailable_copy(self):
        self.assertIn("function renderActivityFallback(message='当前范围暂无可视化数据')", HTML_TEXT)
        self.assertNotIn("活动页部分图表暂时不可用", HTML_TEXT)
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\['ac-hourly','ac-bins','ac-trend','ac-radar','ac-heat','ac-word'\]\.forEach", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\$\('ac-emoji'\)\.innerHTML='\<div class=\"emoji-cloud-empty\">暂无表情数据，内置表情已做对应展示</div>';", re.S),
        )

    def test_chart_empty_overlay_is_removed_when_real_chart_renders(self):
        self.assertIn("function clearChartOverlay(){", HTML_TEXT)
        self.assertIn("return [{id:'chart-empty-overlay',$action:'remove'}];", HTML_TEXT)
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"function renderChartMessage\(id,text='当前范围暂无可视化数据'\)\s*\{[\s\S]*?id:'chart-empty-overlay'", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"chart\('ac-radar'\)\.setOption\(\{[\s\S]*?graphic:clearChartOverlay\(\),", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"chart\('ac-heat'\)\.setOption\(\{[\s\S]*?graphic:\[\s*\.\.\.clearChartOverlay\(\),", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"chart\('ac-net'\)\.setOption\(\{[\s\S]*?graphic:clearChartOverlay\(\),", re.S),
        )

    def test_emoji_cloud_uses_frequency_sorted_freeform_layout(self):
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.emoji-panel\s*\{[^}]*display:\s*block;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.emoji-cloud-board\s*\{[^}]*display:\s*flex;[^}]*flex-wrap:\s*wrap;[^}]*max-width:\s*760px;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\}\)\.sort\(\(a,b\)=>b\.count-a\.count\)\.slice\(0,18\);", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"const faceSize=26\+Math\.round\(Math\.pow\(ratio,0\.82\)\*34\);", re.S),
        )
