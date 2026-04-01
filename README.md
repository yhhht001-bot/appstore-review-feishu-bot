# App Store Connect 审核飞书机器人

这个项目会在 GitHub Actions 中定时执行，拉取 App Store Connect 中和审核相关的版本状态，并发送到飞书群机器人。

## 适用场景

- 查看哪些 App 版本已提交审核
- 查看哪些版本正在审核中
- 查看哪些版本被拒绝
- 查看哪些版本等待开发者发布

## 运行逻辑

1. 使用 App Store Connect API Key 生成 JWT
2. 拉取账号下 App 列表
3. 拉取每个 App 的 App Store Versions
4. 过滤出你关心的审核状态
5. 通过飞书自定义机器人 webhook 发送播报

## 当前默认定时

- UTC `00:00` 到 `23:00` 每小时一次
- 对应北京时间每小时整点一次

如果你想改频率，直接修改：

`/.github/workflows/appstore-review-report.yml`

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
- `ASC_REVIEW_STATES`
- `ASC_APP_IDS`
- `REPORT_EMPTY_RESULT`

说明：

- `ASC_PRIVATE_KEY` 填 `.p8` 私钥全文
- `ASC_REVIEW_STATES` 可留空，留空时会使用脚本默认值
- `ASC_APP_IDS` 可留空，留空时会拉取账号下所有 App
- `REPORT_EMPTY_RESULT=true` 表示即使当前没有命中审核状态，也发送一条“当前无审核中版本”的提示

## App Store Connect API 信息怎么获取

你需要在 App Store Connect 中创建 API Key，拿到：

- `Issuer ID`
- `Key ID`
- `.p8` 私钥文件

后台路径通常是：

`Users and Access -> Integrations -> App Store Connect API`

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
- 使用默认模拟审核数据
- 在终端输出“模拟发送成功”和预览内容

## 飞书消息示例

标题会使用飞书富文本标题区显示：

```text
App 审核播报 2026-04-01 19:00
```

正文会类似：

```text
My App | iOS | 1.2.3 | IN_REVIEW
My App | iOS | 1.2.2 | REJECTED
```

## 注意事项

- 飞书 webhook 泄露后要立即重新生成
- 如果飞书开启关键词校验，消息正文必须包含关键词
- 这个项目当前采用“轮询”方案，不是 Apple 官方 webhook 回调方案
- 如果后续你要做“状态变更时才通知”，可以在这个项目基础上加状态缓存
