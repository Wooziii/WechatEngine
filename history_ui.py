import streamlit as st
import sqlite3
import os
import hashlib
from datetime import datetime

# 设置工作目录为脚本所在的目录，防止相对路径问题
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DECRYPTED_DIR = os.path.join(SCRIPT_DIR, "decrypted")

st.set_page_config(
    page_title="微信聊天记录可视化",
    page_icon="💬",
    layout="wide",
    initial_sidebar_state="expanded"
)

# 自定义 CSS 样式
st.markdown("""
<style>
/* 高级感现代浅色 UI (Apple/Telegram 风格) */
:root {
    --bg-primary: #f2f4f5;
    --bg-secondary: #ffffff;
    --bg-tertiary: #f8f9fa;
    --border-primary: #eaecf0;
    --text-primary: #101828;
    --text-secondary: #667085;
    --accent-cyan: #0ea5e9;
    --accent-green: #dcf8c6;
    --bubble-me: #dcf8c6; /* WhatsApp 绿 */
    --bubble-other: #ffffff;
    --font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
}

/* 隐藏 Streamlit 默认元素 */
#MainMenu {visibility: hidden;}
footer {visibility: hidden;}
header {visibility: hidden;}

/* 主背景与字体 */
.stApp {
    background: var(--bg-primary);
    font-family: var(--font-family);
}

/* 侧边栏样式 */
[data-testid="stSidebar"] {
    background: var(--bg-secondary);
    border-right: 1px solid var(--border-primary);
    box-shadow: 1px 0 15px rgba(0,0,0,0.02);
}
[data-testid="stSidebar"] .stMarkdown,
[data-testid="stSidebar"] label {
    color: var(--text-primary) !important;
    font-family: var(--font-family);
}

/* 标题样式 */
h1, h2, h3 {
    color: var(--text-primary) !important;
    font-weight: 700;
    letter-spacing: -0.02em;
}

/* 输入框样式 */
.stTextInput > div > div > input {
    background: var(--bg-tertiary);
    border: 1px solid var(--border-primary);
    border-radius: 10px;
    color: var(--text-primary);
    padding: 10px 14px;
}
.stTextInput > div > div > input:focus {
    border-color: var(--accent-cyan);
    box-shadow: 0 0 0 3px rgba(14,165,233,0.15);
}

/* Radio 按钮现代样式 */
.stRadio > div { background: transparent; gap: 4px; }
.stRadio label {
    color: var(--text-primary) !important;
    padding: 10px 14px;
    border-radius: 10px;
    margin-bottom: 2px;
    transition: all 0.2s ease-in-out;
    cursor: pointer;
}
.stRadio label:hover {
    background: var(--bg-tertiary);
}
.stRadio input[type="radio"]:checked + span {
    color: var(--accent-cyan) !important;
    font-weight: 600;
}
.stRadio label[data-selected="true"] {
    background: #e0f2fe;
}

/* 消息气泡基础样式 */
.chat-row {
    display: flex;
    margin-bottom: 18px;
    padding: 0 10px;
    font-family: var(--font-family);
}
.chat-row.me {
    flex-direction: row-reverse;
}

.avatar {
    width: 38px;
    height: 38px;
    border-radius: 50%;
    background: linear-gradient(135deg, #a8c0ff 0%, #3f2b96 100%);
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 16px;
    font-weight: 600;
    color: #fff;
    flex-shrink: 0;
    box-shadow: 0 2px 5px rgba(0,0,0,0.1);
}
.chat-row.me .avatar {
    background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
    margin-left: 14px;
}
.chat-row.other .avatar {
    background: linear-gradient(135deg, #e0c3fc 0%, #8ec5fc 100%);
    margin-right: 14px;
}

.msg-content-wrapper {
    display: flex;
    flex-direction: column;
    max-width: 70%;
}
.chat-row.me .msg-content-wrapper {
    align-items: flex-end;
}
.chat-row.other .msg-content-wrapper {
    align-items: flex-start;
}

.msg-name {
    font-size: 12px;
    color: var(--text-secondary);
    margin-bottom: 4px;
    margin-left: 4px;
    font-weight: 500;
}
.chat-row.me .msg-name {
    display: none; /* 自己发的消息隐藏名字 */
}

.msg-bubble {
    padding: 10px 14px 12px 14px;
    border-radius: 18px;
    font-size: 15px;
    line-height: 1.5;
    word-break: break-word;
    color: var(--text-primary);
    box-shadow: 0 2px 8px rgba(0,0,0,0.04);
    position: relative;
    min-width: 60px;
}

.chat-row.me .msg-bubble {
    background-color: var(--bubble-me);
    border-top-right-radius: 4px;
}

.chat-row.other .msg-bubble {
    background-color: var(--bubble-other);
    border-top-left-radius: 4px;
}

.msg-time {
    font-size: 10px;
    color: #8fa0a5;
    float: right;
    margin-top: 6px;
    margin-left: 12px;
    margin-bottom: -4px;
}

.msg-system {
    text-align: center;
    margin: 20px 0;
}
.msg-system-text {
    display: inline-block;
    background: rgba(0,0,0,0.06);
    color: var(--text-secondary);
    font-size: 12px;
    padding: 4px 12px;
    border-radius: 12px;
}

/* 滚动条美化 */
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb {
    background: #d0d5dd;
    border-radius: 10px;
}
::-webkit-scrollbar-thumb:hover { background: #98a2b3; }
</style>
""", unsafe_allow_html=True)

# 标题
st.markdown("<h1 style='margin-bottom: 20px;'>💬 微信历史聊天记录可视化</h1>", unsafe_allow_html=True)

@st.cache_data
def get_contact_names():
    names = {}
    contact_db_path = os.path.join(DECRYPTED_DIR, "contact", "contact.db")
    if os.path.exists(contact_db_path):
        conn = sqlite3.connect(contact_db_path)
        try:
            for r in conn.execute("SELECT username, nick_name, remark FROM contact").fetchall():
                uname, nick, remark = r
                display = remark if remark else nick if nick else uname
                names[uname] = display
        except Exception as e:
            st.error(f"读取联系人失败：{e}")
        finally:
            conn.close()
    return names

names = get_contact_names()

@st.cache_data
def get_sessions():
    session_db = os.path.join(DECRYPTED_DIR, "session", "session.db")
    sessions = []
    if os.path.exists(session_db):
        conn = sqlite3.connect(session_db)
        try:
            rows = conn.execute("SELECT username, last_timestamp FROM SessionTable WHERE last_timestamp > 0 ORDER BY last_timestamp DESC").fetchall()
            for r in rows:
                uname = r[0]
                display = names.get(uname, uname)
                sessions.append((uname, display))
        except Exception as e:
            st.error(f"读取会话列表失败：{e}")
        finally:
            conn.close()
    return sessions

sessions = get_sessions()

def find_msg_table(username):
    table_hash = hashlib.md5(username.encode()).hexdigest()
    table_name = f"Msg_{table_hash}"
    message_dir = os.path.join(DECRYPTED_DIR, "message")

    if os.path.exists(message_dir):
        for db_file in os.listdir(message_dir):
            if db_file.startswith("message_") and db_file.endswith(".db"):
                db_path = os.path.join(message_dir, db_file)
                conn = sqlite3.connect(db_path)
                try:
                    exists = conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table_name,)).fetchone()
                    if exists:
                        conn.close()
                        return db_path, table_name
                except Exception:
                    pass
                finally:
                    conn.close()
    return None, None

def format_msg_type(t):
    type_map = {
        1: ('💬', '文本'),
        3: ('🖼️', '图片'),
        34: ('🎤', '语音'),
        42: ('👤', '名片'),
        43: ('🎬', '视频'),
        47: ('😀', '表情'),
        48: ('📍', '位置'),
        49: ('📎', '链接/文件'),
        50: ('📞', '通话'),
        10000: ('⚙️', '系统'),
        10002: ('↩️', '撤回'),
    }
    icon, label = type_map.get(t, ('📨', f'type={t}'))
    return icon, label

def render_message(local_type, ts, content, sender_display, is_group, status):
    time_str = datetime.fromtimestamp(ts).strftime('%H:%M') # 只有时分
    full_time_str = datetime.fromtimestamp(ts).strftime('%m-%d %H:%M')
    icon, type_label = format_msg_type(local_type)

    if local_type == 10000:
        import html
        safe_content = html.escape(str(content or ''))
        html_str = f"""<div class="msg-system">
<span class="msg-system-text">{full_time_str} {safe_content}</span>
</div>"""
        st.markdown(html_str, unsafe_allow_html=True)
    else:
        is_me = (status == 2)
        display_content = content
        if content is None:
            display_content = ""
        elif isinstance(content, bytes):
            display_content = "📦 压缩/多媒体/二进制内容"
        elif is_group and not is_me and ':\n' in content:
            parts = content.split(':\n', 1)
            if len(parts) == 2:
                sender_display = names.get(parts[0], parts[0])
                display_content = parts[1]

        import html
        import re
        display_name = sender_display if sender_display else '我'
        avatar_text = display_name[0:1] if display_name else "?"
        
        if isinstance(display_content, str):
            display_content = re.sub(r'<[^>]+>', '', display_content)
            
        display_content = html.escape(str(display_content)).replace('\n', '<br>')
        row_class = "me" if is_me else "other"
        
        if local_type != 1:
            display_content = f"<span style='opacity:0.6;font-size:0.9em;'>{icon} {type_label}</span><br>{display_content}"

        html_str = f"""<div class="chat-row {row_class}">
<div class="avatar">{avatar_text}</div>
<div class="msg-content-wrapper">
<div class="msg-name">{display_name} · {datetime.fromtimestamp(ts).strftime('%m-%d')}</div>
<div class="msg-bubble">
{display_content}
<span class="msg-time">{time_str}</span>
</div>
</div>
</div>"""
        st.markdown(html_str, unsafe_allow_html=True)

def generate_export_md(rows, selected_session_name, is_group, names):
    md_lines = [f"# {selected_session_name} 聊天记录导出\n", f"导出时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n---\n"]
    for local_type, ts, content, status in rows:
        time_str = datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
        is_me = (status == 2)
        sender = ""
        text = content
        if content is None: text = ""
        elif isinstance(content, bytes): text = "[多媒体二进制数据]"
        elif is_group and not is_me and ':\n' in content:
            parts = content.split(':\n', 1)
            if len(parts) == 2:
                sender = parts[0]
                text = parts[1]
                
        import re
        if isinstance(text, str):
            text = re.sub(r'<[^>]+>', '', text)
            
        display_name = "我" if is_me else (names.get(sender, sender) if sender else selected_session_name)
        if local_type == 10000:
            md_lines.append(f"> ⚙️ {time_str} [系统] {text}\n")
        else:
            _, t_label = format_msg_type(local_type)
            if local_type != 1: text = f"[{t_label}] {text}"
            md_lines.append(f"**{display_name}** `[{time_str}]`\n{text}\n")
    return "\n".join(md_lines)

# 侧边栏
with st.sidebar:
    st.markdown("### 📇 会话列表")

    if not sessions:
        st.warning("⚠️ 未找到聊天数据，请确保已经执行了解密脚本！")
    else:
        search_query = st.text_input("🔍 搜索联系人", placeholder="输入昵称或备注...")
        
        hide_official = st.checkbox("🚫 隐藏公众号/服务号", value=True)

        filtered_sessions = sessions
        
        # 过滤公众号 (gh_开头) 和 一些系统号
        if hide_official:
            system_accounts = {'newsapp', 'fmessage', 'medianote', 'floatbottle', 'qmessage', 'qqmail', 'tmessage'}
            filtered_sessions = [s for s in filtered_sessions if not s[0].startswith('gh_') and s[0] not in system_accounts]

        if search_query:
            filtered_sessions = [s for s in filtered_sessions if search_query.lower() in s[1].lower()]

        if filtered_sessions:
            st.markdown(f"**共 {len(filtered_sessions)} 个会话**")

            selected_session_name = st.radio(
                "选择聊天:",
                [s[1] for s in filtered_sessions],
                label_visibility="collapsed"
            )

        else:
            st.warning("未找到匹配的联系人")
            selected_session_name = None

# 主内容区
if 'selected_session_name' in dir() and selected_session_name:
    selected_username = next(s[0] for s in filtered_sessions if s[1] == selected_session_name)
    is_group = '@chatroom' in selected_username

    db_path, table_name = find_msg_table(selected_username)
    
    total_msgs = 0
    if db_path:
        conn = sqlite3.connect(db_path)
        try:
            total_msgs = conn.execute(f"SELECT COUNT(*) FROM [{table_name}]").fetchone()[0]
        except Exception:
            pass

    col1, col2, col3 = st.columns([2.5, 1, 1])
    with col1:
        st.markdown(f"## {selected_session_name} {'`(群聊)`' if is_group else ''}")
        st.markdown(f"<span style='color:var(--text-secondary);font-size:14px;'>共 {total_msgs} 条历史消息</span>", unsafe_allow_html=True)
    with col2:
        limit = st.selectbox(
            "📜 加载数量",
            [50, 200, 500, 1000, 5000, 10000, 50000, 100000],
            index=2
        )

    if db_path:
        try:
            try:
                query = f"""
                    SELECT local_type, create_time, message_content, status
                    FROM [{table_name}]
                    WHERE WCDB_CT_message_content = 0 OR WCDB_CT_message_content IS NULL
                    ORDER BY create_time DESC
                    LIMIT ?
                """
                rows = conn.execute(query, (limit,)).fetchall()
            except sqlite3.OperationalError:
                query = f"""
                    SELECT local_type, create_time, message_content, status
                    FROM [{table_name}]
                    ORDER BY create_time DESC
                    LIMIT ?
                """
                rows = conn.execute(query, (limit,)).fetchall()

            if not rows:
                st.info("💭 该聊天内暂无消息记录")
            else:
                rows.reverse()

                # 导出按钮
                md_content = generate_export_md(rows, selected_session_name, is_group, names)
                with col3:
                    st.download_button(
                        label="⬇️ 导出 Markdown",
                        data=md_content,
                        file_name=f"{selected_session_name}_聊天记录.md",
                        mime="text/markdown",
                        use_container_width=True
                    )
                st.divider()

                # 使用容器来显示消息
                messages_container = st.container()
                with messages_container:
                    for local_type, ts, content, status in rows:
                        # 解析发送者
                        sender_display = ""
                        text = content
                        is_me = (status == 2)

                        if is_group and not is_me and content and isinstance(content, str) and ':\n' in content:
                            parts = content.split(':\n', 1)
                            if len(parts) == 2:
                                sender_display = names.get(parts[0], parts[0])
                                text = parts[1]
                        
                        if not is_group and not is_me:
                            sender_display = selected_session_name

                        render_message(local_type, ts, text, sender_display, is_group, status)

        except Exception as e:
            st.error(f"❌ 加载聊天记录时出错：{e}")
        finally:
            conn.close()
else:
    # 空状态
    st.markdown("""<div style="text-align: center; padding: 80px 20px; color: #8b949e;">
<div style="font-size: 64px; margin-bottom: 16px;">💬</div>
<h3 style="color: #f0f6fc; margin-bottom: 8px;">选择聊天查看历史消息</h3>
<p style="font-size: 14px; opacity: 0.7;">从左侧列表选择一个联系人或群聊</p>
</div>""", unsafe_allow_html=True)
