import re
import unittest
from pathlib import Path


HTML = Path(__file__).resolve().parents[1] / "analysis_web.html"
HTML_TEXT = HTML.read_text(encoding="utf-8")


class AnalysisWebLayoutRegressionTests(unittest.TestCase):
    def test_final_refresh_override_exists(self):
        self.assertIn('<style id="analysis-refresh-20260313b">', HTML_TEXT)

    def test_analysis_sidebar_and_shell_use_light_adaptive_layout(self):
        self.assertRegex(
            HTML_TEXT,
            re.compile(r":root\s*\{[^}]*--shell-sidebar:\s*376px;[^}]*--shell-resizer:\s*10px;[^}]*--shell-gap:\s*22px;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.app\s*\{[^}]*display:\s*grid\s*!important;[^}]*grid-template-columns:\s*var\(--shell-sidebar\)\s*var\(--shell-resizer\)\s*minmax\(0,\s*1fr\)\s*!important;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.side\s*\{[^}]*display:\s*flex\s*!important;[^}]*flex-direction:\s*column\s*!important;[^}]*min-height:\s*100vh\s*!important;[^}]*overflow:\s*hidden\s*!important;", re.S),
        )
        self.assertIn('id="sidebar-resizer"', HTML_TEXT)
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.sidebar-resizer\s*\{[^}]*position:\s*relative\s*!important;[^}]*cursor:\s*ew-resize\s*!important;", re.S),
        )

    def test_analysis_sidebar_resizer_persists_width_and_binds_pointer_drag(self):
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"function clampAnalysisSidebarWidth\(w\)\{", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"function applyAnalysisSidebarWidth\(w,\s*persist\s*=\s*true\)\{.*?localStorage\.setItem\('topic_engine_analysis_sidebar_width',\s*String\(v\)\)", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"function initAnalysisSidebarResizer\(\)\{.*?sidebarResizerEl\.addEventListener\('pointerdown'.*?sidebarResizerEl\.addEventListener\('dblclick'.*?window\.addEventListener\('pointermove'.*?window\.addEventListener\('pointerup',\s*finishDrag\)", re.S),
        )

    def test_analysis_has_responsive_mobile_breakpoint(self):
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"@media\s*\(max-width:\s*1180px\)\s*\{[^}]*\.app\s*\{[^}]*grid-template-columns:\s*1fr\s*!important;", re.S),
        )

    def test_filter_toolbar_keeps_date_controls_on_one_row_desktop(self):
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.top,\s*\.tools\s*\{[^}]*display:\s*flex\s*!important;[^}]*flex-wrap:\s*nowrap\s*!important;[^}]*overflow-x:\s*auto\s*!important;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.tools label\s*\{[^}]*display:\s*inline-flex\s*!important;[^}]*align-items:\s*center\s*!important;[^}]*white-space:\s*nowrap\s*!important;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.tools input\[type=date\]\s*\{[^}]*width:\s*176px\s*!important;[^}]*min-width:\s*176px\s*!important;", re.S),
        )

    def test_analysis_cards_switch_to_light_surface(self):
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.card,\s*\.ai2-left,\s*\.ai2-right\s*\{[^}]*background:\s*rgba\(255,\s*255,\s*255,\s*0\.88\)\s*!important;[^}]*border:\s*1px solid rgba\(148,\s*163,\s*184,\s*0\.22\)\s*!important;", re.S),
        )

    def test_insight_and_activity_pages_use_consistent_report_spacing(self):
        self.assertRegex(
            HTML_TEXT,
            re.compile(r":root\s*\{[^}]*--report-gap:\s*24px;[^}]*--report-card-gap:\s*14px;[^}]*--report-card-pad:\s*18px;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.page\.active#page-overview,\s*\.page\.active#page-activity,\s*\.page\.active#page-members,\s*\.page\.active#page-insight,\s*\.page\.active#page-score\s*\{[^}]*display:\s*flex\s*!important;[^}]*flex-direction:\s*column\s*!important;[^}]*gap:\s*var\(--report-gap\)\s*!important;", re.S),
        )

    def test_streak_cards_use_responsive_auto_fit_layout(self):
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.streak-list\s*\{[^}]*grid-template-columns:\s*repeat\(auto-fit,\s*minmax\(320px,\s*1fr\)\)\s*!important;[^}]*gap:\s*var\(--report-gap\)\s*!important;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.streak-top\s*\{[^}]*grid-template-columns:\s*minmax\(0,\s*1fr\)\s*auto\s*!important;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.streak-fire-icon\s*\{[^}]*font-size:\s*13px\s*!important;[^}]*line-height:\s*1\s*!important;", re.S),
        )
        self.assertNotRegex(
            HTML_TEXT,
            re.compile(r"@media\s*\(max-width:\s*1460px\)\s*\{[^}]*\.streak-list\s*\{[^}]*grid-template-columns:\s*repeat\(4,\s*minmax\(0,\s*1fr\)\)\s*!important;", re.S),
        )

    def test_activity_streak_rows_are_compact_and_ai_aware(self):
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.streak-list\s*\{[^}]*grid-template-columns:\s*repeat\(auto-fit,\s*minmax\(640px,\s*1fr\)\)\s*!important;[^}]*gap:\s*12px\s*!important;[^}]*padding:\s*16px\s*!important;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.streak-bars\s*\{[^}]*grid-template-columns:\s*repeat\(2,\s*minmax\(0,\s*1fr\)\);[^}]*gap:\s*8px;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.streak-row-stats\s*\{[^}]*grid-template-columns:\s*repeat\(2,\s*minmax\(0,\s*1fr\)\);[^}]*gap:\s*8px;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"function streakAiContext\(\)\{.*?memberAiProfileMap\(memberRows,48\).*?reportData\.member_watch", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"function streakNarrativeForMember\(sender,row,refs\)\{.*?aiSignal.*?streakFallbackSignal.*?streakFallbackAction", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"function aiRefreshCurrentContextViews\(\)\{[^}]*renderActivity\(\);[^}]*renderMembers\(\);[^}]*renderInsight\(\);", re.S),
        )
        self.assertIn('class="streak-row-quote"', HTML_TEXT)
        self.assertIn('class="streak-row-note"', HTML_TEXT)

    def test_insight_hero_is_compacted_and_highlight_cards_are_tighter(self):
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.insight-hero-shell\s*\{[^}]*padding:\s*24px;[^}]*border-radius:\s*28px;[^}]*box-shadow:\s*0 14px 32px rgba\(79,\s*70,\s*229,\s*0\.06\);", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.insight-title\s*\{[^}]*max-width:\s*620px;[^}]*font-size:\s*clamp\(26px,\s*3vw,\s*38px\);", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.insight-highlight-card\s*\{[^}]*padding:\s*16px;[^}]*border-radius:\s*18px;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.insight-highlight-detail\s*\{[^}]*font-size:\s*12px;[^}]*-webkit-line-clamp:\s*4;", re.S),
        )

    def test_insight_story_title_uses_wider_em_based_measure(self):
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.insight-story-title\s*\{[^}]*max-width:\s*min\(12em,\s*100%\);", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"#page-insight\s+\.insight-story-title\s*\{[^}]*max-width:\s*min\(12\.4em,\s*100%\);", re.S),
        )
        self.assertNotRegex(
            HTML_TEXT,
            re.compile(r"#page-insight\s+\.insight-story-title\s*\{[^}]*max-width:\s*min\(18ch,\s*100%\);", re.S),
        )

    def test_insight_hero_progress_block_and_renderer_exist(self):
        self.assertIn('class="insight-story-progress" hidden id="in-story-progress"', HTML_TEXT)
        self.assertIn('id="in-story-progress-fill"', HTML_TEXT)
        self.assertIn('id="in-story-progress-steps"', HTML_TEXT)
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"function renderInsightStoryProgress\(\)\{.*?in-story-progress-fill.*?in-story-progress-steps", re.S),
        )

    def test_insight_pulse_section_prefers_turning_points_before_plain_peaks(self):
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"const pulseEvents=\[\],pulseSeen=new Set\(\);", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"for\(const row of aiTurningPoints\.slice\(0,3\)\)\{.*?label:'转折'.*?转折复盘", re.S),
        )

    def test_members_page_has_ai_fun_persona_stage(self):
        self.assertIn("AI 趣味画像", HTML_TEXT)
        self.assertIn('id="me-ai-cards"', HTML_TEXT)
        self.assertIn('id="me-ai-note"', HTML_TEXT)
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"function renderMemberAiGallery\(\)\{.*?me-ai-cards.*?轻量猜测", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"function renderMemberList\(\)\{.*?class=\"m-ai\"", re.S),
        )

    def test_emoji_board_uses_real_emoji_mapping_cards_instead_of_word_cloud_text(self):
        self.assertIn("内置表情已做对应展示", HTML_TEXT)
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.emoji-panel\s*\{[^}]*display:\s*grid;[^}]*grid-template-columns:\s*minmax\(0,\s*1\.15fr\)\s*minmax\(240px,\s*0\.85fr\);", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"const WECHAT_EMOJI_MAP=\{[^}]*'流泪':'😭'[^}]*'旺柴':'🐶'[^}]*'发抖':'😨'", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"function renderEmojiCloudBoard\(rows\)\{.*?disposeChart\('in-word'\);.*?class=\"emoji-cloud-item tone-\$\{item\.idx%EMOJI_TONE_COUNT\}\"", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"const emojiCloud=Array\.isArray\(d\.emoji_cloud\)\?d\.emoji_cloud\.slice\(0,80\):\[\];\s*renderEmojiCloudBoard\(emojiCloud\);", re.S),
        )

    def test_score_page_uses_dedicated_grid_and_form_skin(self):
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.score-grid\s*\{[^}]*grid-template-columns:\s*repeat\(2,\s*minmax\(0,\s*1fr\)\)\s*!important;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.score-form\s*\{[^}]*grid-template-columns:\s*repeat\(2,\s*minmax\(0,\s*1fr\)\)\s*!important;[^}]*padding:\s*22px\s*!important;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.score-form select,\s*\.score-form input,\s*\.score-form textarea\s*\{[^}]*border-radius:\s*14px\s*!important;[^}]*background:\s*rgba\(255,\s*255,\s*255,\s*0\.96\)\s*!important;", re.S),
        )

    def test_score_markup_uses_dedicated_classes_for_charts_and_tables(self):
        self.assertIn('class="flex-1 p-4 w-full min-h-[260px] sm chart score-chart" id="sc-top-chart"', HTML_TEXT)
        self.assertIn('class="form score-form" id="score-form"', HTML_TEXT)
        self.assertIn('class="tw score-table-wrap"', HTML_TEXT)

    def test_generic_table_wrappers_keep_tables_inside_cards(self):
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.tw,\s*\.no-max\.tw\s*\{[^}]*overflow:\s*auto\s*!important;[^}]*padding:\s*0\s*!important;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.tw table\s*\{[^}]*width:\s*100%\s*!important;[^}]*min-width:\s*720px\s*!important;", re.S),
        )

    def test_long_member_and_score_tables_use_fixed_height_internal_scroll_areas(self):
        self.assertRegex(
            HTML_TEXT,
            re.compile(r'class="no-max tw members-table-wrap">\s*<div class="members-table-scroll">\s*<table>', re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.members-table-wrap\s*\{[^}]*grid-template-rows:\s*minmax\(0,\s*1fr\)\s*auto\s*!important;[^}]*height:\s*clamp\(480px,\s*62vh,\s*820px\)\s*!important;[^}]*overflow:\s*hidden\s*!important;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.members-table-scroll\s*\{[^}]*overflow:\s*auto\s*!important;[^}]*overscroll-behavior:\s*contain\s*!important;[^}]*scroll-behavior:\s*smooth\s*!important;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.score-table-wrap\s*\{[^}]*overflow:\s*auto\s*!important;[^}]*height:\s*clamp\(420px,\s*56vh,\s*720px\)\s*!important;[^}]*scroll-behavior:\s*smooth\s*!important;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.score-table-wrap thead th,\s*\.members-table-scroll thead th\s*\{[^}]*position:\s*sticky\s*!important;[^}]*top:\s*0\s*!important;", re.S),
        )

    def test_brand_does_not_append_duplicate_engine_suffix(self):
        self.assertNotRegex(
            HTML_TEXT,
            re.compile(r"\.brand-en::after\s*\{[^}]*content:\s*\"Engine\"", re.S),
        )

    def test_ai_page_uses_compact_split_layout_and_smaller_empty_state(self):
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.ai2\s*\{[^}]*grid-template-columns:\s*minmax\(0,\s*344px\)\s*minmax\(0,\s*1fr\)\s*!important;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.ai-empty\s*\{[^}]*min-height:\s*320px\s*!important;[^}]*max-width:\s*680px\s*!important;", re.S),
        )

    def test_session_cards_use_avatar_title_time_layout(self):
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.item\s*\{[^}]*grid-template-columns:\s*48px\s*minmax\(0,\s*1fr\)\s*!important;[^}]*min-height:\s*86px\s*!important;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.item-time\s*\{[^}]*min-width:\s*74px\s*!important;[^}]*text-align:\s*right\s*!important;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"function renderSessions\(\)\{.*?class=\"item-avatar\".*?class=\"item-headline\".*?class=\"item-title\".*?class=\"item-time\"", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.item-meta\s*\{[^}]*grid-template-columns:\s*auto\s+auto\s*!important;[^}]*min-width:\s*max-content\s*!important;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.list\s*\{[^}]*padding:\s*10px\s*12px\s*18px\s*!important;[^}]*flex:\s*1 1 auto\s*!important;[^}]*gap:\s*10px\s*!important;[^}]*overflow-y:\s*auto\s*!important;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.item-title\s*\{[^}]*white-space:\s*nowrap\s*!important;[^}]*font-size:\s*14px\s*!important;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.item-summary\s*\{[^}]*-webkit-line-clamp:\s*1\s*!important;", re.S),
        )

    def test_back_button_uses_explicit_monitor_navigation_helper(self):
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"function navigateToMonitor\(\)\s*\{.*?window\.location\.assign\(target\);.*?window\.location\.href='/'", re.S),
        )
        self.assertIn("$('btn-back').onclick=()=>navigateToMonitor();", HTML_TEXT)

    def test_analysis_settings_expose_per_surface_ai_routing(self):
        self.assertIn("消息提醒", HTML_TEXT)
        self.assertIn("AI 侧栏", HTML_TEXT)
        self.assertIn("数据洞察", HTML_TEXT)
        self.assertIn("共享 API", HTML_TEXT)
        self.assertRegex(
            HTML_TEXT,
            re.compile(r'id="ai-route-live-alert"', re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r'id="ai-route-sidebar"', re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r'id="ai-route-insight"', re.S),
        )

    def test_analysis_page_surfaces_ai_blocked_reason_and_route_summary(self):
        self.assertIn('id="ai-route-summary"', HTML_TEXT)
        self.assertIn('id="ai-route-detail"', HTML_TEXT)
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"function aiSetBlockedReason\(", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"function aiRouteSummaryText\(", re.S),
        )

    def test_ai_results_are_scoped_to_current_chat_and_range(self):
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"function aiResultMatchesCurrentContext\(result\)\{", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"function aiScopedResults\(\)\{", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"const personaData=aiObject\(aiObject\(aiScopedResults\(\)\.persona\)\.data\);", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"aiResults=aiScopedResults\(\)", re.S),
        )

    def test_member_ai_gallery_and_score_detail_use_compact_layout(self):
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.member-ai-stage-body\s*\{[^}]*gap:\s*12px;[^}]*padding:\s*16px\s+16px\s+18px;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.member-ai-stage\s+\.ai-member-grid\s*\{[^}]*gap:\s*14px\s*!important;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.score-detail-wrap\s*\{[^}]*gap:\s*12px\s*!important;[^}]*padding:\s*16px\s*!important;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.score-detail-top\s*\{[^}]*grid-template-columns:\s*minmax\(0,\s*1\.18fr\)\s*minmax\(220px,\s*0\.82fr\);[^}]*gap:\s*14px;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.score-detail-meta\s*\{[^}]*display:\s*flex;[^}]*flex-wrap:\s*wrap;[^}]*gap:\s*8px;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.score-detail-note\s*\{[^}]*padding:\s*14px\s*16px;[^}]*font-size:\s*12px;[^}]*line-height:\s*1\.5;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.score-detail-empty\s*\{[^}]*min-height:\s*124px;[^}]*padding:\s*14px;", re.S),
        )
        self.assertNotIn("score-summary-grid", HTML_TEXT)
        self.assertNotIn("const summaryCards=[", HTML_TEXT)


if __name__ == "__main__":
    unittest.main()
