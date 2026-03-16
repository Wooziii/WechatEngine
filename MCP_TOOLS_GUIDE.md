# MCP 工具调用说明（Topic Engine / WeChat）

文件位置：`wechat-decrypt/mcp_server.py`

## 已实现工具（新增）

- `fix_get_chat_history`
- `get_contact_groups`
- `get_group_message_stats`
- `get_chat_detail_stats`
- `get_daily_message_trend`
- `get_group_member_stats`
- `get_sender_profile`
- `compare_members`
- `smart_search_messages`
- `get_topic_distribution`
- `extract_shared_files`
- `get_activity_alerts`
- `get_mention_analysis`
- `generate_group_report`
- `export_chat_data`
- `get_score_rules`
- `get_score_leaderboard`
- `get_topic_score_candidates`
- `get_high_quality_candidates`
- `get_round_table_candidates`

## 快速调用示例（Claude Code / MCP）

> 下面参数可直接作为 `mcp__wechat__<tool>` 的入参 JSON。

### 1) 修复版历史读取（大样本）

```json
{
  "chat_name": "48883307398@chatroom",
  "limit": 40000,
  "offset": 0,
  "start_ts": 0,
  "end_ts": 0,
  "max_chars": 500000
}
```

### 2) 群聊活跃榜

```json
{
  "start_ts": 0,
  "end_ts": 0,
  "limit": 200,
  "min_members": 10,
  "group_types": ["all"]
}
```

### 3) 单群详细统计

```json
{
  "chat_name": "设计师自然保护区",
  "start_ts": 0,
  "end_ts": 0,
  "include_topics": true,
  "include_media_breakdown": true
}
```

### 4) 消息趋势（日/周/月/小时）

```json
{
  "chat_name": "设计师自然保护区",
  "granularity": "day",
  "start_ts": 0,
  "end_ts": 0
}
```

### 5) 群成员榜

```json
{
  "chat_name": "设计师自然保护区",
  "limit": 50,
  "start_ts": 0,
  "end_ts": 0,
  "include_metrics": ["message_count", "word_count", "active_days", "media_count"]
}
```

### 6) 成员画像

```json
{
  "chat_name": "设计师自然保护区",
  "sender": "马小舸",
  "start_ts": 0,
  "end_ts": 0,
  "context_before": -1,
  "context_after": -1
}
```

### 7) 成员对比

```json
{
  "chat_name": "设计师自然保护区",
  "senders": ["马小舸", "Any", "流光"],
  "metrics": ["message_count", "active_hours", "topics"]
}
```

### 8) 智能搜索

```json
{
  "chat_name": "设计师自然保护区",
  "query": "PPT AND (设计 OR 模板) NOT 广告",
  "search_mode": "boolean",
  "start_ts": 0,
  "end_ts": 0,
  "limit": 1000
}
```

### 9) 话题分布

```json
{
  "chat_name": "设计师自然保护区",
  "start_ts": 0,
  "end_ts": 0,
  "min_topic_frequency": 10,
  "clustering_method": "keyword"
}
```

### 10) 分享提取（链接/文件/图片/视频）

```json
{
  "chat_name": "设计师自然保护区",
  "media_type": "all",
  "start_ts": 0,
  "end_ts": 0
}
```

### 11) 活跃预警

```json
{
  "chat_name": "all",
  "alert_type": "all",
  "threshold_multiplier": 2.0,
  "lookback_days": 30
}
```

### 12) 提及网络

```json
{
  "chat_name": "设计师自然保护区",
  "start_ts": 0,
  "end_ts": 0
}
```

### 13) 群报告生成

```json
{
  "chat_name": "设计师自然保护区",
  "report_type": "html",
  "time_range": "last_30_days",
  "include_sections": ["overview", "members", "topics", "trends"]
}
```

## 14) 原始数据导出

```json
{
  "chat_name": "设计师自然保护区",
  "format": "csv",
  "start_ts": 0,
  "end_ts": 0,
  "include_metadata": true
}
```

### 15) 群聊列表

```json
{
  "query": "",
  "min_members": 3,
  "limit": 1000
}
```

### 16) Score Rules

```json
{}
```

### 17) Score Leaderboard (Auto + Manual)

```json
{
  "chat_name": "designers_chatroom",
  "start_ts": 0,
  "end_ts": 0,
  "include_manual": true,
  "limit": 100
}
```

### 18) Topic Score Candidates (Start/Response)

```json
{
  "chat_name": "designers_chatroom",
  "start_ts": 0,
  "end_ts": 0,
  "window_minutes": 180,
  "min_unique_responders": 5,
  "limit": 60
}
```

### 19) High-Quality Content Candidates

```json
{
  "chat_name": "designers_chatroom",
  "start_ts": 0,
  "end_ts": 0,
  "min_text_length": 50,
  "min_quality_score": 60,
  "context_window_seconds": 120,
  "limit": 120
}
```

### 20) Roundtable Participation Candidates

```json
{
  "chat_name": "designers_chatroom",
  "start_ts": 0,
  "end_ts": 0,
  "window_minutes": 180,
  "min_participants": 5,
  "keywords": "圆桌,讨论,分享会,连麦",
  "limit": 80
}
```

## 可行性说明（当前版本）

- 已可直接上线：P0/P1 全部（历史读取修复、群活跃、成员榜、趋势、单群统计、画像）。
- P2 available: topic distribution, report export (html/markdown/json), score leaderboard, and topic-score candidate detection.
- 仍是“启发式”而非 NLP 模型：
  - 情绪分布、互动关系、来源识别（通过规则 + 关键词 + 正则）。
  - `clustering_method=lda/embedding` 会自动降级为 `keyword`。
- PDF 报告：目前返回提示，建议先导出 html/markdown 再转 PDF。

## 注意事项

- `get_group_message_stats` 全量统计会较重，建议先 `limit=50~200`。
- `fix_get_chat_history` 在 `max_chars` 达到上限时会提示继续翻页 `offset`。
- 导出文件默认路径：`wechat-decrypt/exports/`。
