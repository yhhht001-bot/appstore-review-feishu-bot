# App Store Connect 审核飞书机器人

这个项目会轮询 App Store Connect，并且只在检测到审核状态变化时发送飞书消息。

当前监听范围：

- App 版本审核状态
- CPP（Custom Product Pages，自定义产品页）审核状态
- IAE（In-App Events，App 内活动）审核状态

## 运行逻辑

1. 使用 App Store Connect API Key 生成 JWT
2. 拉取账号下 App 列表
3. 分别拉取每个 App 的版本、CPP、IAE 数据
4. 和上一次状态快照做对比
5. 只有检测到状态变化时，才发飞书
6. 发送成功后，把最新状态快照保存到 `bot-state` 分支

## 重要说明

Apple 这类审核状态并不能直接把所有变化主动推送到 GitHub Actions。

所以这个项目采用的是：

- GitHub Actions 定时检查
- 只有变化才发送
- 没变化完全不发

当前频率是：

- 每 30 分钟检查一次

这已经是 GitHub 云端自动运行，不需要你的电脑开机。

## 首次运行行为

第一次运行时，脚本会先建立一份状态快照，不发送消息。

从第二次开始，只要版本、CPP、IAE 的状态发生变化，就会立刻在下一次轮询时发送。

## 需要配置的 GitHub Secrets

在仓库中打开：

`Settings -> Secrets and variables -> Actions`

添加以下 Secrets：

- `ASC_ISSUER_ID`
- `ASC_KEY_ID`
- `ASC_PRIVATE_KEY`
- `FEISHU_WEBHOOK_URL`
- `FEISHU_SECRET`
- `FEISHU_KEYWORD`
- `ASC_APP_IDS`

说明：

- `ASC_PRIVATE_KEY` 填 `.p8` 私钥全文
- `ASC_APP_IDS` 可留空，留空时会拉取账号下所有 App
- 如果只想监听指定多个 App，填逗号分隔的 App ID，例如 `1234567890,0987654321`
- `FEISHU_SECRET`、`FEISHU_KEYWORD` 没开就留空

## 本地测试

先复制环境变量模板：

```bash
cp .env.example .env
```

安装依赖并运行：

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python appstore_review_report.py
```

如果你还没拿到 App Store Connect API Key，可以先跑沙盒模式：

```bash
SANDBOX_MODE=true python appstore_review_report.py
```

沙盒模式特点：

- 不访问 App Store Connect
- 不调用飞书 webhook
- 第一次运行只初始化状态
- 第二次开始按状态差异输出模拟结果

## 环境变量

`.env.example` 里包含这些字段：

- `ASC_ISSUER_ID`
- `ASC_KEY_ID`
- `ASC_PRIVATE_KEY_PATH`
- `FEISHU_WEBHOOK_URL`
- `FEISHU_SECRET`
- `FEISHU_KEYWORD`
- `ASC_API_BASE_URL`
- `ASC_APP_IDS`
- `STATE_FILE_PATH`
- `SANDBOX_MODE`

其中：

- `STATE_FILE_PATH` 默认是 `./.state/appstore_review_state.json`

## 飞书消息示例

标题：

```text
App审核信息 2026-04-01 21:10
```

正文：

```text
[My App / My Other App]
【IOS】
[My App] 版本：1.2.3
旧状态：审核中
新状态：待开发者发布
[My Other App] CPP：spring_hero | v2
旧状态：等待审核
新状态：已通过
```

## 注意事项

- 飞书 webhook 泄露后要立即重新生成
- 如果飞书开启关键词校验，消息正文必须包含关键词
- 这个项目当前不是 Apple 官方直连回调，而是“云端轮询 + 变化才发”
