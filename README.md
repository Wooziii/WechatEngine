# WechatEngine

<p align="center">
  <img src="./WechatEngine.png" alt="WechatEngine logo" width="160">
</p>

<p align="center">面向 Windows WeChat 4.0 的本地数据库解密、实时监控、历史检索、群聊分析与 AI 助手工具箱。</p>

WechatEngine 聚焦一件事：把你自己的微信本地数据变成可查询、可分析、可监控的工作台。

它既能从运行中的微信进程提取 SQLCipher 4 密钥并解密数据库，也能提供实时消息监控、聊天历史检索、群聊分析看板、桌面壳界面，以及给 Claude Code 使用的 MCP Server。

## Fork 说明

本仓库以 GitHub fork 的方式维护，来源于上游项目 [ylytdeng/wechat-decrypt](https://github.com/ylytdeng/wechat-decrypt)。

这样做的目的，是保留原始提交历史、作者署名和上游关系，同时在此基础上继续维护更偏日常使用的一组增强能力，例如：

- 桌面壳与托盘运行体验
- 更完整的实时监控与历史查看界面
- 群聊分析页与 AI 洞察能力
- 一些围绕性能、缓存、交互细节的持续优化

如果你想了解原始解密思路和更早的项目背景，建议同时查看上游仓库。

## 功能概览

- 提取运行中微信进程里的数据库密钥，并解密本地 SQLCipher 4 数据库
- 提供实时消息监控页，支持最近会话、会话切换、历史回看、关键词检索
- 提供群聊分析页，查看活跃度、成员画像、话题走向、趣味洞察和 AI 分析结果
- 提供 AI 侧栏，可调用本机 `claude` 命令或兼容 OpenAI / Anthropic 的接口
- 提供桌面壳程序，支持托盘驻留、最小化隐藏、打包发布
- 提供 MCP Server，让 Claude Code 直接查询最近会话、历史消息、联系人和新消息

## 软件能做什么

### 1. 本地数据库解密

微信 4.0 使用 SQLCipher 4 加密本地数据库。WechatEngine 会扫描运行中的微信进程内存，定位派生后的 raw key，匹配数据库 salt 后完成验证和解密。

- 加密算法：AES-256-CBC + HMAC-SHA512
- KDF：PBKDF2-HMAC-SHA512，256000 次
- 页面大小：4096 bytes
- 每个数据库都有独立的 salt 和 enc_key

### 2. 实时消息监控

`monitor_web.py` 会监听数据库和 WAL 变化，并通过 Web UI 把最新消息推到界面上。

- 最近会话列表
- 单会话历史浏览
- 关键词搜索与时间范围过滤
- 实时提醒
- AI 侧栏问答
- Markdown 导出

### 3. 群聊数据分析

`analysis_web.html` 提供更偏洞察和运营视角的分析页面。

- 活跃度与消息量概览
- 话题和关键词趋势
- 成员画像与行为风格
- 互动线索和高光时刻
- AI 生成的结构化洞察、情绪判断和建议动作

### 4. 桌面版壳层

`desktop_shell.py` 会把 Web UI 包进桌面窗口里，并提供更接近日常软件的体验。

- 托盘常驻
- 最小化隐藏
- 重启本地服务
- 开机启动开关
- 一键打包桌面发布包

### 5. Claude Code / MCP 集成

你可以把 WechatEngine 暴露成 MCP Server，让 Claude Code 直接查你的本地微信数据。

- `get_recent_sessions(limit)`
- `get_chat_history(chat_name, limit)`
- `search_messages(keyword, limit)`
- `get_contacts(query, limit)`
- `get_new_messages()`

更多示例见 [USAGE.md](USAGE.md)。

## 快速开始

### 环境要求

- Windows 10/11
- Python 3.10+
- 正在运行的微信 4.0
- 管理员权限

### 安装依赖

```bash
pip install pycryptodome
```

如果你要使用 MCP：

```bash
pip install mcp
```

### 1. 配置

复制模板并编辑：

```bash
copy config.example.json config.json
```

`config.json` 示例：

```json
{
  "db_dir": "D:\\xwechat_files\\your_wxid\\db_storage",
  "keys_file": "all_keys.json",
  "decrypted_dir": "decrypted",
  "wechat_process": "Weixin.exe",
  "web_port": 8080
}
```

`db_dir` 可以在微信设置的文件管理路径里找到。

### 2. 提取密钥

```bash
python find_all_keys.py
```

### 3. 解密数据库

```bash
python decrypt_db.py
```

### 4. 打开实时监控页

```bash
python monitor_web.py
```

程序会在本地启动服务，并输出实际访问地址。

### 5. 打开桌面壳

```bash
python desktop_shell.py
```

### 6. 打包桌面版

```powershell
powershell -ExecutionPolicy Bypass -File .\build_desktop_release.ps1
```

## MCP 注册示例

```bash
claude mcp add wechat -- python C:\path\to\WechatEngine\mcp_server.py
```

或者在 `~/.claude.json` 里手动配置：

```json
{
  "mcpServers": {
    "wechat": {
      "type": "stdio",
      "command": "python",
      "args": ["C:\\path\\to\\WechatEngine\\mcp_server.py"]
    }
  }
}
```

## 目录说明

| 文件 | 说明 |
|------|------|
| `find_all_keys.py` | 从微信进程内存提取数据库密钥 |
| `decrypt_db.py` | 解密数据库 |
| `monitor_web.py` | Web 服务入口，提供实时监控、历史查询、分析接口 |
| `monitor_web.html` | 监控页前端 |
| `analysis_web.html` | 分析页前端 |
| `desktop_shell.py` | 桌面壳程序 |
| `mcp_server.py` | MCP Server |
| `build_desktop_release.ps1` | 桌面版打包脚本 |
| `tests/` | 回归测试 |

## 隐私与安全

仓库默认不提交本地隐私数据。当前已忽略：

- `config.json`
- `all_keys.json`
- `decrypted/`
- 各类 `.db` / `.db-wal` / `.db-shm`
- `_archive/`、`artifacts/`、`release_desktop/`

也就是说，开源仓库里保留的是工具代码，不包含你的微信数据库、提取出的密钥或本地运行产物。

## 致谢与贡献者

本仓库保留了 fork 关系和上游提交历史，GitHub 页面顶部可以直接追溯上游来源。

另外，我也把公开可见的上游贡献者整理在了 [CONTRIBUTORS.md](CONTRIBUTORS.md)，方便在 README 外单独查看。

上游项目参考：

- [ylytdeng/wechat-decrypt](https://github.com/ylytdeng/wechat-decrypt)

## README 图片说明

可以，GitHub README 支持 PNG、JPG、GIF、WebP，也支持仓库内相对路径图片。页首 Logo 就是一个实际例子。

后续如果你想加界面截图，建议放到 `docs/images/`，然后这样引用：

```md
![监控页截图](docs/images/monitor.png)
```

## 免责声明

本项目仅用于学习、研究和处理你自己的本地数据。请遵守适用法律法规，不要用于未经授权的数据访问或传播。
