import re
import unittest
from pathlib import Path


HTML = Path(__file__).resolve().parents[1] / "monitor_web.html"
HTML_TEXT = HTML.read_text(encoding="utf-8")


class MonitorWebUiRegressionTests(unittest.TestCase):
    def test_settings_footer_is_the_only_save_entrypoint_in_markup(self):
        self.assertRegex(HTML_TEXT, r'<button[^>]+id="live-alert-save-sticky-btn"')
        self.assertRegex(HTML_TEXT, r'<button[^>]+id="provider-save-sticky-btn"')
        self.assertNotRegex(HTML_TEXT, r'<button[^>]+id="live-alert-save-btn"')
        self.assertNotRegex(HTML_TEXT, r'<button[^>]+id="provider-save-btn"')

    def test_quote_rich_media_extracts_current_and_quoted_text_separately(self):
        self.assertRegex(
            HTML_TEXT,
            re.compile(
                r"function extractQuoteParts\(meta,\s*fallbackContent = ''\)\s*\{.*?const parts = normalizedFallback\.split\(/\\n引用\[:：\]/,\s*1\);.*?for \(const cand of \[meta\.quote,\s*itemText,\s*meta\.desc,\s*meta\.title\]\).*?return \{\s*currentText,\s*quoteText\s*\};",
                re.S,
            ),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(
                r"if \(meta\.kind === 'quote'\)\s*\{.*?const quoteParts = extractQuoteParts\(meta,\s*fallbackContent\);.*?suppressContent:\s*false,.*?contentOverride:\s*quoteParts\.currentText,",
                re.S,
            ),
        )

    def test_message_content_uses_quote_content_override_when_present(self):
        self.assertRegex(
            HTML_TEXT,
            re.compile(
                r"const richRender = renderRichMedia\(m\.rich_media,\s*linkMeta,\s*mediaUrl,\s*contentText\);.*?const displayContentText = String\(richRender\.contentOverride \|\| contentText \|\| ''\)\.trim\(\) \|\| `\[\$\{typeText\}\]`;",
                re.S,
            ),
        )

    def test_media_only_messages_have_a_dedicated_layout_hook(self):
        self.assertIn("mediaOnlyMessage", HTML_TEXT)
        self.assertRegex(HTML_TEXT, r"classList\.add\('media-only'\)")
        self.assertRegex(HTML_TEXT, re.compile(r"\.msg\.media-only\s*\{", re.S))

    def test_ai_markdown_tables_use_light_surface_and_bubbles_can_shrink(self):
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.ai-bubble\s*\{[^}]*min-width:\s*0\s*!important;[^}]*overflow:\s*hidden\s*!important;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.ai-md-table-wrap\s*\{[^}]*background:\s*#ffffff\s*!important;", re.S),
        )

    def test_sidebar_action_buttons_do_not_wrap(self):
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.side-actions \.btn\s*\{[^}]*white-space:\s*nowrap\s*!important;", re.S),
        )

    def test_sidebar_actions_use_icon_ui_buttons(self):
        self.assertNotRegex(HTML_TEXT, r'<button[^>]+id="btn-filter-pop"[^>]*>\s*筛选\s*</button>')
        self.assertNotRegex(HTML_TEXT, r'<button[^>]+id="btn-realtime"[^>]*>\s*实时总览\s*</button>')
        self.assertNotRegex(HTML_TEXT, r'<button[^>]+id="btn-refresh-sessions"[^>]*>\s*刷新会话\s*</button>')
        self.assertRegex(
            HTML_TEXT,
            r'<button[^>]+id="btn-filter-pop"[^>]+class="btn action-ui"[^>]+aria-label="筛选"[^>]*>\s*<span class="action-ui-icon"',
        )
        self.assertRegex(
            HTML_TEXT,
            r'<button[^>]+id="btn-realtime"[^>]+class="btn main action-ui"[^>]+aria-label="实时总览"[^>]*>\s*<span class="action-ui-icon"',
        )
        self.assertRegex(
            HTML_TEXT,
            r'<button[^>]+id="btn-refresh-sessions"[^>]+class="btn action-ui"[^>]+aria-label="刷新会话"[^>]*>\s*<span class="action-ui-icon"',
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.side-actions \.btn\.action-ui\s*\{[^}]*width:\s*32px\s*!important;[^}]*font-size:\s*0\s*!important;", re.S),
        )

    def test_alert_history_filter_controls_are_width_constrained(self):
        self.assertRegex(HTML_TEXT, re.compile(r"\.alert-history-filters\s*>\s*\*\s*\{[^}]*min-width:\s*0\s*!important;", re.S))

    def test_compact_alert_board_empty_state_is_supported(self):
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"alertBoardEl\.classList\.toggle\('is-compact',\s*boardState !== 'active'\)", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.alert-board\.is-compact\s+\.alert-board-list\s+\.side-empty\s*\{[^}]*padding:\s*10px 12px\s*!important;", re.S),
        )

    def test_pinned_sessions_render_inside_sticky_zone(self):
        self.assertIn('<div class="session-pinned-zone', HTML_TEXT)
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.session-pinned-zone\s*\{[^}]*position:\s*sticky\s*!important;[^}]*top:\s*0\s*!important;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.session-pinned-list\s*\{[^}]*max-height:\s*min\(36vh,\s*260px\)\s*!important;[^}]*overflow-y:\s*auto\s*!important;", re.S),
        )

    def test_pin_button_is_right_aligned_overlay(self):
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.session-pin-btn\s*\{[^}]*position:\s*absolute\s*!important;[^}]*right:\s*8px\s*!important;[^}]*top:\s*8px\s*!important;[^}]*pointer-events:\s*none\s*!important;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.session-item\s*\{[^}]*overflow:\s*visible\s*!important;", re.S),
        )

    def test_ai_composer_shell_wraps_input_and_actions(self):
        self.assertIn('<div class="ai-compose-shell">', HTML_TEXT)
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.ai-compose-shell\s*\{[^}]*position:\s*relative\s*!important;[^}]*border-radius:\s*22px\s*!important;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.ai-send-row\s*\{[^}]*position:\s*absolute\s*!important;[^}]*bottom:\s*12px\s*!important;", re.S),
        )

    def test_ai_header_uses_compact_new_history_switch_and_inline_stop_button(self):
        self.assertRegex(
            HTML_TEXT,
            re.compile(r'<div class="ai-head-switch"[^>]*>.*?id="ai-new-btn".*?id="ai-refresh-btn"', re.S),
        )
        self.assertNotRegex(HTML_TEXT, r'<button[^>]+id="ai-reconnect-btn"')
        self.assertRegex(
            HTML_TEXT,
            re.compile(r'<div class="ai-send-actions">.*?id="ai-send-btn".*?id="ai-stop-btn"[^>]*hidden', re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.ai-send-actions\s*\{[^}]*margin-left:\s*auto\s*!important;[^}]*display:\s*inline-flex\s*!important;[^}]*justify-content:\s*flex-end\s*!important;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.ai-send-stop\s*\{[^}]*width:\s*38px\s*!important;[^}]*height:\s*38px\s*!important;[^}]*margin-left:\s*0\s*!important;[^}]*flex:\s*0\s+0\s+38px\s*!important;", re.S),
        )

    def test_ai_branding_uses_wechatengine_and_wechatcopilot(self):
        self.assertIn("<title>WechatEngine</title>", HTML_TEXT)
        self.assertIn(">WechatEngine</span>", HTML_TEXT)
        self.assertIn("微信群聊监控与洞察台", HTML_TEXT)
        self.assertIn(">WechatCopilot</div>", HTML_TEXT)
        self.assertIn("你好，我是 WechatCopilot", HTML_TEXT)
        self.assertIn(">实时消息监控</div>", HTML_TEXT)

    def test_ai_progress_card_supports_full_hide_after_generation(self):
        self.assertIn('id="ai-progress-hide"', HTML_TEXT)
        self.assertRegex(HTML_TEXT, re.compile(r"progressHidden:\s*false", re.S))
        self.assertRegex(HTML_TEXT, re.compile(r"function setAiProgressHidden\(hidden\)\s*\{", re.S))
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"const shouldShow = hasData && !state\.ai\.progressHidden;", re.S),
        )

    def test_ai_progress_hidden_state_exposes_restore_ui(self):
        self.assertIn('id="ai-progress-restore"', HTML_TEXT)
        self.assertIn('id="ai-progress-restore-btn"', HTML_TEXT)
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"const restoreVisible = hasData && state\.ai\.progressHidden;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"aiProgressRestoreEl\.hidden = !restoreVisible;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"aiProgressRestoreBtn\.addEventListener\('click',\s*\(ev\)\s*=>\s*\{[^}]*setAiProgressHidden\(false\);", re.S),
        )

    def test_ai_assistant_messages_expose_copy_and_regenerate_actions(self):
        self.assertRegex(
            HTML_TEXT,
            re.compile(r'data-ai-copy="\$\{idx\}".*?data-ai-regenerate="\$\{idx\}"', re.S),
        )
        self.assertRegex(HTML_TEXT, re.compile(r"async function aiCopyMessageByIndex\(index\)\s*\{", re.S))
        self.assertRegex(HTML_TEXT, re.compile(r"async function aiRegenerateMessageByIndex\(index\)\s*\{", re.S))
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"const copyBtn = ev\.target instanceof Element \? ev\.target\.closest\('\[data-ai-copy\]'\) : null;", re.S),
        )

    def test_history_toolbar_relies_on_enter_and_drops_redundant_buttons(self):
        self.assertNotIn('id="btn-keyword-search"', HTML_TEXT)
        self.assertNotIn('id="btn-keyword-clear"', HTML_TEXT)
        self.assertNotIn('id="clear-filter-btn"', HTML_TEXT)
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"historyKeywordEl\.addEventListener\('keydown',\s*\(ev\)\s*=>\s*\{[^}]*ev\.key === 'Enter'[^}]*applyHistoryKeywordSearch\(\)", re.S),
        )

    def test_header_status_badges_do_not_shrink_or_wrap_awkwardly(self):
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.header-status-group\s*>\s*\.status,\s*\.header-status-group\s*>\s*\.head-info\s*\{[^}]*flex:\s*0 0 auto\s*!important;[^}]*white-space:\s*nowrap\s*!important;", re.S),
        )

    def test_sidebar_uses_split_scroll_for_pinned_and_regular_sessions(self):
        self.assertIn('class="session-scroll"', HTML_TEXT)
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.session-list\s*\{[^}]*display:\s*flex\s*!important;[^}]*flex-direction:\s*column\s*!important;[^}]*overflow:\s*hidden\s*!important;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.session-scroll\s*\{[^}]*flex:\s*1 1 auto\s*!important;[^}]*overflow-y:\s*auto\s*!important;", re.S),
        )

    def test_status_badges_scroll_horizontally_instead_of_collapsing(self):
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.header-status-group\s*\{[^}]*flex-wrap:\s*nowrap\s*!important;[^}]*overflow-x:\s*auto\s*!important;", re.S),
        )

    def test_message_bubbles_keep_shadow_visible(self):
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.messages\s*\{[^}]*overflow-y:\s*auto\s*!important;[^}]*overflow-x:\s*hidden\s*!important;[^}]*padding:\s*28px 32px 64px\s*!important;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.msg,\s*\.msg-bubble,\s*\.msg-main\s*\{[^}]*overflow:\s*visible\s*!important;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.msg\s*\{[^}]*overflow:\s*visible\s*!important;[^}]*contain:\s*none\s*!important;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.msg-body\s*\{[^}]*overflow:\s*visible\s*!important;[^}]*contain:\s*none\s*!important;", re.S),
        )

    def test_sidebar_width_is_compacted_in_final_override(self):
        self.assertRegex(
            HTML_TEXT,
            re.compile(r":root\s*\{[^}]*--sidebar-width:\s*286px;[^}]*--ai-width:\s*372px;", re.S),
        )

    def test_alert_board_uses_tighter_compact_card_treatment(self):
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.alert-board\s*\{[^}]*position:\s*relative\s*!important;[^}]*padding:\s*8px 9px\s*!important;[^}]*border-radius:\s*15px\s*!important;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.alert-board-list\s*\{[^}]*position:\s*absolute\s*!important;[^}]*top:\s*calc\(100%\s*\+\s*8px\)\s*!important;[^}]*max-height:\s*min\(44vh,\s*360px\)\s*!important;", re.S),
        )

    def test_session_time_is_right_aligned_without_stealing_name_width(self):
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.session-top\s*\{[^}]*display:\s*grid\s*!important;[^}]*grid-template-columns:\s*minmax\(0,\s*1fr\)\s*52px\s*!important;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.session-time\s*\{[^}]*min-width:\s*52px\s*!important;[^}]*text-align:\s*right\s*!important;", re.S),
        )

    def test_session_pin_and_unread_are_overlayed_not_layout_columns(self):
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.session-item\s*\{[^}]*grid-template-columns:\s*32px\s*minmax\(0,\s*1fr\)\s*!important;[^}]*padding:\s*8px 34px 8px 6px\s*!important;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.session-pin-btn\s*\{[^}]*position:\s*absolute\s*!important;[^}]*right:\s*8px\s*!important;[^}]*top:\s*8px\s*!important;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.session-tail\s*\{[^}]*position:\s*absolute\s*!important;[^}]*right:\s*8px\s*!important;[^}]*bottom:\s*9px\s*!important;", re.S),
        )

    def test_session_list_compacts_right_side_badges_to_protect_name_and_time(self):
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"body\s+\.session-item\s*\{[^}]*grid-template-columns:\s*32px\s*minmax\(0,\s*1fr\)\s*!important;[^}]*padding:\s*8px 36px 8px 6px\s*!important;[^}]*overflow:\s*visible\s*!important;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"body\s+\.session-top\s*\{[^}]*grid-template-columns:\s*minmax\(0,\s*1fr\)\s*46px\s*!important;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"body\s+\.session-time\s*\{[^}]*min-width:\s*46px\s*!important;[^}]*text-align:\s*right\s*!important;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"body\s+\.session-unread\s*\{[^}]*min-width:\s*14px\s*!important;[^}]*height:\s*14px\s*!important;[^}]*font-size:\s*8px\s*!important;", re.S),
        )

    def test_system_notice_rows_are_clickable_and_open_preview_modal(self):
        self.assertIn('<div class="notice-preview-mask" id="notice-preview-mask" hidden>', HTML_TEXT)
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"<button class=\"msg-notice\" type=\"button\" data-notice-preview=\"1\"[^>]*aria-haspopup=\"dialog\"", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"function setNoticePreviewOpen\(open,\s*msg = null\)\s*\{", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"noticeBtn\.addEventListener\('click',\s*\(\)\s*=>\s*setNoticePreviewOpen\(true,\s*m\)\)", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"noticePreviewMaskEl\.addEventListener\('click',\s*\(ev\)\s*=>\s*\{[^}]*setNoticePreviewOpen\(false\);", re.S),
        )

    def test_alert_board_is_tight_compact_card(self):
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.alert-board\s*\{[^}]*margin-left:\s*12px\s*!important;[^}]*padding:\s*8px 9px\s*!important;[^}]*background:\s*linear-gradient\(180deg,\s*rgba\(255,\s*249,\s*240,\s*0\.96\),\s*rgba\(255,\s*245,\s*233,\s*0\.92\)\)\s*!important;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.alert-board-list\s+\.side-empty\s*\{[^}]*padding:\s*8px 10px\s*!important;[^}]*border-radius:\s*14px\s*!important;", re.S),
        )

    def test_alert_board_defaults_to_collapsed_popover_mode(self):
        self.assertRegex(HTML_TEXT, re.compile(r"liveAlert:\s*\{[^}]*collapsed:\s*true,", re.S))
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"state\.liveAlert\.collapsed\s*=\s*collapsedPref == null \? true : collapsedPref === '1';", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"alertBoardToggleEl\.textContent\s*=\s*state\.liveAlert\.collapsed \? '查看' : '收起';", re.S),
        )

    def test_compact_alert_board_hides_expander_when_no_active_alerts(self):
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"const allowExpand = boardState === 'active';", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"alertBoardEl\.classList\.toggle\('collapsed',\s*!allowExpand \|\| !!state\.liveAlert\.collapsed\);", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"alertBoardToggleEl\.hidden = !allowExpand;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.alert-board\[data-state=\"empty\"\]\s+\.alert-board-list,\s*\.alert-board\[data-state=\"setup\"\]\s+\.alert-board-list,\s*\.alert-board\[data-state=\"disabled\"\]\s+\.alert-board-list\s*\{[^}]*display:\s*none\s*!important;", re.S),
        )

    def test_alert_board_matches_compact_reference_card(self):
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.alert-board\s*\{[^}]*padding:\s*8px 9px\s*!important;[^}]*border-radius:\s*15px\s*!important;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.alert-board-title::before\s*\{[^}]*content:\s*\"!\";[^}]*width:\s*15px\s*!important;[^}]*height:\s*15px\s*!important;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.alert-board-count\s*\{[^}]*min-width:\s*38px\s*!important;[^}]*height:\s*22px\s*!important;[^}]*border-radius:\s*999px\s*!important;", re.S),
        )

    def test_chat_tools_and_sidebar_actions_are_reduced_to_compact_density(self):
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.side-actions\s*\{[^}]*gap:\s*5px\s*!important;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.side-actions \.btn\s*\{[^}]*min-height:\s*32px\s*!important;[^}]*padding:\s*0 8px\s*!important;[^}]*font-size:\s*11px\s*!important;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.chat-tools\s*\{[^}]*padding:\s*7px 14px 9px\s*!important;[^}]*gap:\s*6px 7px\s*!important;[^}]*align-items:\s*center\s*!important;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.control\s*\{[^}]*min-height:\s*32px\s*!important;[^}]*padding:\s*0 9px\s*!important;[^}]*border-radius:\s*10px\s*!important;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.control input\s*\{[^}]*min-width:\s*96px\s*!important;[^}]*height:\s*30px\s*!important;[^}]*font-size:\s*11px\s*!important;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.range-shortcuts\s*\{[^}]*gap:\s*5px\s*!important;[^}]*padding-left:\s*4px\s*!important;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.range-btn,\s*\.chat-tools > \.btn\s*\{[^}]*min-height:\s*32px\s*!important;[^}]*padding:\s*0 11px\s*!important;[^}]*font-size:\s*11px\s*!important;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.keyword-control\s*\{[^}]*grid-template-columns:\s*auto minmax\(0,\s*1fr\)\s*!important;[^}]*width:\s*168px\s*!important;[^}]*max-width:\s*168px\s*!important;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            r'<div class="control keyword-control"><span class="keyword-prefix">关键词</span><input id="history-keyword" type="text" placeholder="匹配关键词"></div>',
        )

    def test_detail_header_exposes_a_dedicated_chat_tools_toggle(self):
        self.assertRegex(
            HTML_TEXT,
            re.compile(r'<div class="top-icon-wrap" id="chat-tools-toggle-wrap" hidden>\s*<button class="top-action-btn" id="btn-chat-tools-toggle" aria-label="展开筛选" aria-controls="chat-tools" aria-expanded="false">', re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"setIcon\('btn-chat-tools-toggle',\s*'filter',\s*'展开筛选'\);", re.S),
        )

    def test_chat_tools_default_to_collapsed_and_sync_with_detail_mode(self):
        self.assertRegex(HTML_TEXT, re.compile(r"historyKeyword:\s*'',\s*chatToolsOpen:\s*false,", re.S))
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"function syncChatToolsUI\(\)\s*\{.*?const inDetail = !!state\.targetUsername;.*?const visible = inDetail && !!state\.chatToolsOpen;.*?chatToolsToggleWrapEl\.hidden = !inDetail;.*?chatToolsToggleBtnEl\.setAttribute\('aria-expanded',\s*visible \? 'true' : 'false'\);", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"function updateDetailModeUI\(\)\s*\{.*?syncChatToolsUI\(\);.*?updateExportModeHint\(\);", re.S),
        )

    def test_chat_tools_reset_when_entering_or_leaving_session_detail(self):
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"function openSession\(username,\s*chatName\)\s*\{.*?const wasInDetail = !!state\.targetUsername;.*?if \(!wasInDetail\) state\.chatToolsOpen = false;.*?updateDetailModeUI\(\);", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"function clearChatFilter\(\)\s*\{.*?state\.chatToolsOpen = false;.*?updateDetailModeUI\(\);", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"if \(chatToolsToggleBtnEl\)\s*\{\s*chatToolsToggleBtnEl\.addEventListener\('click',\s*\(\)\s*=>\s*\{\s*setChatToolsOpen\(!state\.chatToolsOpen\);", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"if \(ev\.key === 'Escape' && state\.chatToolsOpen\)\s*\{\s*setChatToolsOpen\(false\);", re.S),
        )

    def test_chat_tools_use_collapsible_toolbar_shell_in_detail_mode(self):
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"body\.detail-mode \.chat-tools\s*\{[^}]*max-height:\s*0\s*!important;[^}]*min-height:\s*0\s*!important;[^}]*opacity:\s*0\s*!important;[^}]*overflow:\s*hidden\s*!important;[^}]*pointer-events:\s*none\s*!important;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"body\.detail-mode\.chat-tools-open \.chat-tools,\s*body\.detail-mode \.chat-tools\.is-open\s*\{[^}]*max-height:\s*124px\s*!important;[^}]*opacity:\s*1\s*!important;[^}]*pointer-events:\s*auto\s*!important;", re.S),
        )

    def test_date_controls_use_fixed_compact_shell_and_hidden_native_input(self):
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.control\.date-control\s*\{[^}]*grid-template-columns:\s*auto minmax\(0,\s*1fr\) auto\s*!important;[^}]*width:\s*146px\s*!important;[^}]*max-width:\s*146px\s*!important;[^}]*overflow:\s*hidden\s*!important;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.control\.date-control input\[type=\"hidden\"\]\s*\{[^}]*display:\s*none\s*!important;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            r'<div class="control date-control is-empty" data-date-target="start-date">\s*<span class="date-prefix">从</span>\s*<span class="date-value" data-date-label-for="start-date">不限日期</span>',
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.date-picker-pop\s*\{[^}]*position:\s*absolute\s*!important;[^}]*width:\s*258px\s*!important;[^}]*max-width:\s*258px\s*!important;[^}]*overflow:\s*hidden\s*!important;", re.S),
        )

    def test_date_control_labels_are_synced_from_input_values(self):
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"function formatDateControlLabelValue\(value\)\s*\{.*?return `\$\{m\[1\]\}\.\$\{m\[2\]\}\.\$\{m\[3\]\}`;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"function syncDateControlLabel\(input\)\s*\{.*?label\.textContent = formatDateControlLabelValue\(value\);.*?wrap\.classList\.toggle\('is-empty',\s*!value\);", re.S),
        )
        self.assertIn("syncAllDateControlLabels();", HTML_TEXT)

    def test_settings_footer_buttons_have_explicit_width_and_do_not_wrap(self):
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.settings-footer-actions\s*\{[^}]*grid-auto-flow:\s*column\s*!important;[^}]*grid-auto-columns:\s*max-content\s*!important;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.settings-footer-actions \.btn\s*\{[^}]*min-width:\s*118px\s*!important;[^}]*white-space:\s*nowrap\s*!important;", re.S),
        )

    def test_realtime_status_uses_explicit_dot_and_text_markup(self):
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"function setRealtimeConnectionState\(kind = 'ok', text = ''\)\s*\{.*?statusEl\.innerHTML = `<span class=\"status-dot\"", re.S),
        )
        self.assertRegex(HTML_TEXT, re.compile(r"\.status-dot\s*\{[^}]*width:\s*7px\s*!important;[^}]*height:\s*7px\s*!important;", re.S))

    def test_session_updates_are_debounced_and_use_event_delegation(self):
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"sessionRenderTimer:\s*0", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"function queueRenderSessions\(\)\s*\{.*?clearTimeout\(state\.sessionRenderTimer\);.*?setTimeout\(", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"if \(sessionListEl\)\s*\{.*?sessionListEl\.addEventListener\('click',\s*\(ev\)\s*=>\s*\{", re.S),
        )

    def test_self_messages_render_on_the_right_and_bubbles_shrink_to_content(self):
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"const isSelfMessage = !!\([^)]*m\.is_me", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"if \(isSelfMessage\) d\.classList\.add\('self'\);", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.msg-main\s*\{[^}]*width:\s*fit-content\s*!important;[^}]*max-width:\s*min\(82%,\s*calc\(100%\s*-\s*44px\)\)\s*!important;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.msg\.self\s*\{[^}]*flex-direction:\s*row-reverse\s*!important;", re.S),
        )

    def test_session_and_message_scroll_lanes_are_compacted_for_more_text(self):
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.session-scroll\s*\{[^}]*padding:\s*0 0 12px 0\s*!important;[^}]*margin-right:\s*-10px\s*!important;[^}]*scrollbar-width:\s*none\s*!important;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.session-scroll::-webkit-scrollbar\s*\{[^}]*width:\s*0\s*!important;[^}]*display:\s*none\s*!important;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.session-item\s*\{[^}]*grid-template-columns:\s*32px\s*minmax\(0,\s*1fr\)\s*!important;[^}]*padding:\s*8px 34px 8px 6px\s*!important;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.messages\s*\{[^}]*padding:\s*18px 16px 36px 18px\s*!important;[^}]*scrollbar-gutter:\s*auto\s*!important;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.messages::-webkit-scrollbar\s*\{[^}]*width:\s*6px\s*!important;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.msg-main\s*\{[^}]*max-width:\s*min\(82%,\s*calc\(100% - 44px\)\)\s*!important;", re.S),
        )

    def test_session_scroll_rebinds_wheel_handler_after_list_rerender(self):
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"function renderSessions\(preserveScroll = false\)\s*\{.*?const scrollEl = document\.getElementById\('session-scroll'\) \|\| sessionScrollEl \|\| sessionListEl;.*?bindWheelScroll\(document\.getElementById\('session-scroll'\)\);.*?const nextScrollEl = document\.getElementById\('session-scroll'\);\s*bindWheelScroll\(nextScrollEl\);", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"function bindWheelScroll\(el\)\s*\{.*?if \(el\.dataset && el\.dataset\.wheelBound === '1'\) return;.*?el\.dataset\.wheelBound = '1';", re.S),
        )

    def test_pin_button_only_appears_on_hover_in_compact_session_cards(self):
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.session-pin-btn\s*\{[^}]*opacity:\s*0\s*!important;[^}]*visibility:\s*hidden\s*!important;[^}]*pointer-events:\s*none\s*!important;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.session-item:hover \.session-pin-btn,\s*\.session-item\.is-hovered \.session-pin-btn,\s*\.session-item:focus-within \.session-pin-btn,\s*\.session-pin-btn:hover,\s*\.session-pin-btn:focus-visible\s*\{[^}]*opacity:\s*1\s*!important;[^}]*visibility:\s*visible\s*!important;[^}]*pointer-events:\s*auto\s*!important;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.session-pin-btn\.pinned\s*\{[^}]*color:\s*#4f46e5\s*!important;[^}]*background:\s*#eef2ff\s*!important;[^}]*border-color:\s*rgba\(99,\s*102,\s*241,\s*0\.24\)\s*!important;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r'<button class="session-pin-btn\$\{pinned \? \' pinned\' : \'\'\}" type="button" title="\$\{pinTip\}" aria-label="\$\{pinTip\}" data-pin="\$\{esc\(s\.username\)\}">📌</button>'),
        )

    def test_session_hover_state_survives_sidebar_rerenders(self):
        self.assertRegex(HTML_TEXT, re.compile(r"hoverSessionUsername:\s*''", re.S))
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"function syncHoveredSessionRow\(\)\s*\{.*?querySelectorAll\('\.session-item'\).*?classList\.toggle\('is-hovered',", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"function setHoveredSession\(username\)\s*\{.*?state\.hoverSessionUsername = nextUsername;.*?syncHoveredSessionRow\(\);", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r'<div class="session-item\$\{active\}\$\{pinnedCls\}\$\{hoveredCls\}\$\{extraClass\}"', re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"sessionListEl\.addEventListener\('pointerover',\s*\(ev\)\s*=>\s*\{.*?setHoveredSession\(row \? \(row\.getAttribute\('data-username'\) \|\| ''\) : ''\);", re.S),
        )

    def test_toggle_pin_session_expands_pinned_zone_and_scrolls_to_top_when_adding(self):
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"function togglePinSession\(username\)\s*\{.*?const wasPinned = state\.pinnedSet\.has\(u\);.*?if \(wasPinned\)\s*\{\s*state\.pinnedSet\.delete\(u\);\s*\}\s*else\s*\{\s*state\.pinnedSet\.add\(u\);\s*state\.pinnedCollapsed = false;\s*\}.*?renderSessions\(wasPinned\);.*?if \(!wasPinned\)\s*\{.*?const scrollEl = document\.getElementById\('session-scroll'\) \|\| sessionScrollEl \|\| sessionListEl;.*?scrollEl\.scrollTo\(\{\s*top:\s*0,\s*behavior:\s*'smooth'\s*\}\)", re.S),
        )

    def test_alert_board_is_tighter_and_uses_larger_text_density(self):
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.alert-board\s*\{[^}]*margin:\s*0 14px 8px\s*!important;[^}]*padding:\s*10px 11px 8px\s*!important;[^}]*border-radius:\s*16px\s*!important;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.alert-board-title\s*\{[^}]*font-size:\s*16px\s*!important;[^}]*font-weight:\s*800\s*!important;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.alert-board-sub\s*\{[^}]*font-size:\s*13px\s*!important;[^}]*line-height:\s*1\.3\s*!important;", re.S),
        )

    def test_date_controls_have_clickable_wrapper_and_picker_support(self):
        self.assertRegex(HTML_TEXT, r'class="control date-control is-empty" data-date-target="start-date"')
        self.assertRegex(HTML_TEXT, r'class="control date-control is-empty" data-date-target="end-date"')
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.control\.date-control\s*\{[^}]*width:\s*146px\s*!important;[^}]*max-width:\s*146px\s*!important;[^}]*cursor:\s*pointer\s*!important;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r'<div class="date-picker-pop" id="date-picker-pop">.*?<div class="date-picker-grid" id="date-picker-grid"></div>', re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"function initDateControls\(\)\s*\{.*?openDatePicker\(input,\s*wrap\);", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"function openDatePicker\(input,\s*anchorEl\)\s*\{.*?state\.datePicker\.open = true;.*?renderDatePicker\(\);", re.S),
        )

    def test_settings_modal_drops_blur_effects_for_stability(self):
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.settings-mask\s*\{[^}]*backdrop-filter:\s*none\s*!important;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.settings-footer\s*\{[^}]*position:\s*static\s*!important;[^}]*backdrop-filter:\s*none\s*!important;", re.S),
        )

    def test_export_popover_can_escape_header_stack(self):
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.header\s*\{[^}]*position:\s*relative\s*!important;[^}]*overflow:\s*visible\s*!important;[^}]*z-index:\s*12\s*!important;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.header-right,\s*\.header-actions,\s*\.top-icon-wrap\s*\{[^}]*overflow:\s*visible\s*!important;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.top-pop\s*\{[^}]*top:\s*calc\(100% \+ 10px\)\s*!important;[^}]*z-index:\s*80\s*!important;", re.S),
        )

    def test_export_popover_uses_custom_option_list_instead_of_native_select(self):
        self.assertNotIn('<select id="export-mode"', HTML_TEXT)
        self.assertRegex(
            HTML_TEXT,
            re.compile(r'<input id="export-mode" type="hidden" value="session_range">', re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r'<div class="export-option-list" id="export-option-list">.*?data-export-mode="session_range".*?data-export-mode="session_all".*?data-export-mode="current".*?data-export-mode="pinned_zip"', re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.top-pop\s*\{[^}]*overflow:\s*hidden\s*!important;[^}]*height:\s*auto\s*!important;[^}]*max-height:\s*none\s*!important;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"function syncExportModeUI\(\)\s*\{.*?document\.querySelectorAll\('\[data-export-mode\]'\)", re.S),
        )

    def test_opening_session_clears_unread_badges_locally(self):
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"function clearUnreadForSession\(username,\s*\{\s*render\s*=\s*true,\s*clearVisibleMessages\s*=\s*true\s*\}\s*=\s*\{\}\)\s*\{", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"function openSession\(username,\s*chatName\)\s*\{.*?clearUnreadForSession\(username\);.*?state\.targetUsername = username;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"if \(state\.targetUsername\) \{\s*if \(data\.username !== state\.targetUsername\) return;.*?data\.unread = 0;.*?clearUnreadForSession\(data\.username,\s*\{\s*render:\s*true,\s*clearVisibleMessages:\s*false\s*\}\);", re.S),
        )

    def test_initial_boot_defers_noncritical_live_alert_and_ai_loading(self):
        self.assertNotIn(
            "Promise.allSettled([loadSessions(), loadRealtimeHistory(), loadLiveAlertConfig(), loadLiveAlerts(true), loadProviderConfig()]).finally(() => {",
            HTML_TEXT,
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(
                r"function startInitialBoot\(\)\s*\{.*?const sessionsBoot = loadSessions\(\)\.finally\(\(\) => \{.*?const historyBoot = loadRealtimeHistory\(\)\.finally\(\(\) => \{.*?Promise\.allSettled\(\[\s*sessionsBoot,\s*historyBoot,\s*\]\)\.finally\(\(\) => \{.*?connectSSE\(\);.*?ensureSecondaryBootstrap\(\)\.catch\(\(\) => \{\}\);.*?ensureAiBootstrap\(\{\s*openFirst:\s*true\s*\}\)\.catch\(\(\) => \{\}\);",
                re.S,
            ),
        )

    def test_active_pane_requests_are_aborted_before_loading_new_history(self):
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"function beginActivePaneRequest\(\)\s*\{.*?abortActivePaneRequest\(\);.*?new AbortController\(\);", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"async function loadRealtimeHistory\(\)\s*\{.*?const requestController = beginActivePaneRequest\(\);.*?signal:\s*requestController\.signal", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"async function loadChatHistory\(username,\s*chatName,\s*opts = \{\}\)\s*\{.*?const requestController = beginActivePaneRequest\(\);.*?signal:\s*requestController\.signal", re.S),
        )

    def test_fetch_json_supports_external_abort_signal(self):
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"async function fetchJson\(url,\s*timeoutMs = 45000,\s*opts = \{\}\)\s*\{.*?const externalSignal = opts && opts\.signal instanceof AbortSignal \? opts\.signal : null;.*?externalSignal\.addEventListener\('abort',\s*abortHandler,\s*\{\s*once:\s*true\s*\}\);.*?throw new Error\('请求已取消'\);", re.S),
        )

    def test_session_search_reuses_debounced_render_queue_and_search_index(self):
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"searchInput\.addEventListener\('input',\s*\(\) => \{\s*state\.sessionDisplayLimit = 500;\s*queueRenderSessions\(\);", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"function updateSessionSearchIndex\(session\)\s*\{.*?session\.searchIndex = \[.*?\.join\('\\n'\)\.toLowerCase\(\);", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"function sessionVisible\(s\)\s*\{.*?return String\(s\.searchIndex \|\| ''\)\.includes\(kw\);", re.S),
        )

    def test_history_open_uses_fast_preview_before_full_backfill(self):
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"const previewLimit = \(!forceReload && isAllRange && !keyword\) \? 80 : 0;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"const previewPage = await fetchChatHistoryPage\(\s*username,\s*keyword,\s*\{.*?limit:\s*previewLimit,\s*fast:\s*1,", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"applyRows\(previewPage\.rows\.map\(bindMsg\),\s*previewPage\);", re.S),
        )

    def test_history_state_tracks_cursor_paging_and_scroll_loading(self):
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"historyPage:\s*\{\s*rows:\s*\[\],\s*hasMore:\s*false,\s*loadingMore:\s*false,\s*nextBeforeTs:\s*0,\s*nextBeforeLocalId:\s*0,", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"function resetHistoryPageState\(\)\s*\{.*?state\.historyPage\.rows = \[\];.*?state\.historyPage\.hasMore = false;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"function maybeLoadMoreHistory\(\)\s*\{.*?state\.historyPage\.hasMore.*?container\.scrollTop \+ container\.clientHeight >= container\.scrollHeight - 160.*?loadOlderHistoryPage\(\)\.catch\(\(\) => \{\}\);", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"container\.addEventListener\('scroll',\s*maybeLoadMoreHistory,\s*\{\s*passive:\s*true\s*\}\);", re.S),
        )

    def test_history_requests_use_paged_chat_history_endpoint(self):
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"function fetchChatHistoryPage\(username,\s*keyword,\s*opts = \{\}\)\s*\{.*?paged:\s*1,.*?if \(opts\.fast\) params\.fast = 1;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"const initialPage = await fetchChatHistoryPage\(\s*username,\s*keyword,\s*\{.*?limit:\s*initialPageLimit,", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"const page = await fetchChatHistoryPage\(username,\s*keyword,\s*\{.*?limit:\s*pageSize,.*?beforeTs:\s*state\.historyPage\.nextBeforeTs,.*?beforeLocalId:\s*state\.historyPage\.nextBeforeLocalId,", re.S),
        )

    def test_loading_strip_uses_visual_progress_panel_layout(self):
        self.assertRegex(
            HTML_TEXT,
            re.compile(r'<div class="loading-strip indeterminate" id="loading-strip">\s*<div class="loading-badge" id="loading-badge">处理中</div>\s*<div class="loading-main">', re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r'<div class="loading-track"><div class="loading-bar" id="loading-bar"></div></div>\s*<div class="loading-meta">', re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.loading-strip\s*\{[^}]*border-radius:\s*18px\s*!important;[^}]*box-shadow:\s*0 18px 40px", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"function setLoading\(on,\s*text = '正在加载\.\.\.',\s*opts = \{\}\)\s*\{.*?loadingBadge\.textContent = .*?loadingSub\.textContent =", re.S),
        )

    def test_initial_boot_uses_fullscreen_progress_overlay(self):
        self.assertRegex(
            HTML_TEXT,
            re.compile(r'<div class="boot-overlay active" id="boot-overlay">\s*<div class="boot-card">', re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r'<div class="boot-track"><div class="boot-fill" id="boot-fill"></div></div>', re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.boot-overlay\s*\{[^}]*position:\s*fixed\s*!important;[^}]*inset:\s*0\s*!important;[^}]*z-index:\s*140\s*!important;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"boot:\s*\{\s*active:\s*true,\s*percent:\s*12,\s*step:\s*'启动中'", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"function setBootOverlayState\(active,\s*title = '',\s*detail = '',\s*opts = \{\}\)\s*\{", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"function startInitialBoot\(\)\s*\{.*?setBootOverlayState\(true,\s*'正在准备主界面'.*?const sessionsBoot = loadSessions\(\)\.finally\(\(\) => \{\s*setBootOverlayState\(true,\s*'最近会话已就绪'.*?const historyBoot = loadRealtimeHistory\(\)\.finally\(\(\) => \{\s*setBootOverlayState\(true,\s*'实时消息已就绪'.*?setTimeout\(\(\) => setBootOverlayState\(false,\s*'准备完成'", re.S),
        )

    def test_ai_progress_panel_has_compact_summary_and_detail_popover(self):
        self.assertIn('<button type="button" class="ai-progress-summary" id="ai-progress-summary"', HTML_TEXT)
        self.assertRegex(
            HTML_TEXT,
            re.compile(r'<div class="ai-progress-meter-track"><div class="ai-progress-meter-fill" id="ai-progress-fill"></div></div>', re.S),
        )
        self.assertRegex(HTML_TEXT, r'<div class="ai-progress-inline-meta" id="ai-progress-inline-meta"></div>')
        self.assertRegex(HTML_TEXT, r'<div class="ai-progress-pop" id="ai-progress-pop">')
        self.assertRegex(HTML_TEXT, r'<div class="ai-progress-stage-row" id="ai-progress-stages"></div>')
        self.assertRegex(HTML_TEXT, r'<div class="ai-progress-stats" id="ai-progress-stats"></div>')
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"progressPct:\s*0", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"function deriveAiProgressModel\(\)\s*\{.*?const rawPct = Math.max\(0,\s*Math.min\(100,\s*Number\(state\.ai\.progressPct \|\| 0\)\)\);.*?const inferredPct = Math.max\(derivedPct,\s*stateFloor\);.*?const pct = Math.max\(rawPct,\s*inferredPct\);", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"aiProgressFillEl\.style\.width = `\$\{model\.pct\}%`;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"aiProgressInlineMetaEl\.innerHTML = inlineMeta\.map", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"stageIndex = 3;.*?stageIndex = 2;.*?stageIndex = 1;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"const hasSignals = !!\(events\.length \|\| partial \|\| state\.ai\.busy \|\| Number\(state\.ai\.progressPct \|\| 0\) > 0 \|\| meaningfulStatus\);.*?const hasData = hasSignals;", re.S),
        )

    def test_ai_progress_stages_use_per_phase_color_classes(self):
        self.assertRegex(
            HTML_TEXT,
            re.compile(r'<div class="ai-progress-stage stage-\$\{stage\.key\} \$\{stage\.state\}">', re.S),
        )
        self.assertIn(".ai-progress-stage.stage-queue {", HTML_TEXT)
        self.assertIn(".ai-progress-stage.stage-fetch {", HTML_TEXT)
        self.assertIn(".ai-progress-stage.stage-analyze {", HTML_TEXT)
        self.assertIn(".ai-progress-stage.stage-reply {", HTML_TEXT)
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.ai-progress-stage\s*\{[^}]*--stage-rgb:", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.ai-progress-stage\.active\s*\{[^}]*rgba\(var\(--stage-rgb\),\s*0\.(?:2|3|4)", re.S),
        )

    def test_ai_progress_popover_supports_internal_scroll(self):
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"\.ai-progress-pop\s*\{[^}]*max-height:\s*min\(68vh,\s*560px\)\s*!important;[^}]*overflow-y:\s*auto\s*!important;[^}]*overflow-x:\s*hidden\s*!important;[^}]*overscroll-behavior:\s*contain\s*!important;", re.S),
        )
        self.assertRegex(
            HTML_TEXT,
            re.compile(r"bindWheelScroll\(aiProgressPopEl\);", re.S),
        )

    def test_monitor_settings_expose_per_surface_ai_routing(self):
        self.assertIn("消息提醒", HTML_TEXT)
        self.assertIn("AI 侧栏", HTML_TEXT)
        self.assertIn("数据洞察", HTML_TEXT)
        self.assertIn("共享 API", HTML_TEXT)
        self.assertRegex(HTML_TEXT, re.compile(r'id="provider-route-live-alert"', re.S))
        self.assertRegex(HTML_TEXT, re.compile(r'id="provider-route-sidebar"', re.S))
        self.assertRegex(HTML_TEXT, re.compile(r'id="provider-route-insight"', re.S))


if __name__ == "__main__":
    unittest.main()
