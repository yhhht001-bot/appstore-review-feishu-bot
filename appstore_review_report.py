import base64
import datetime as dt
import hashlib
import hmac
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import jwt
import requests


ASC_AUD = "appstoreconnect-v1"
ENTITY_TYPE_LABELS = {
    "APP_VERSION": "版本审核",
    "CPP": "CPP 审核",
    "IAE": "IAE 审核",
}
STATE_PRIORITY = {
    "REJECTED": 0,
    "METADATA_REJECTED": 1,
    "WAITING_FOR_EXPORT_COMPLIANCE": 2,
    "INVALID_BINARY": 3,
    "IN_REVIEW": 4,
    "WAITING_FOR_REVIEW": 5,
    "READY_FOR_REVIEW": 6,
    "PENDING_DEVELOPER_RELEASE": 7,
    "PENDING_APPLE_RELEASE": 8,
    "DEVELOPER_REJECTED": 9,
    "PROCESSING_FOR_APP_STORE": 10,
    "ACCEPTED": 11,
    "APPROVED": 12,
    "PUBLISHED": 13,
    "READY_FOR_SALE": 14,
    "READY_FOR_DISTRIBUTION": 15,
    "PAST": 16,
    "REMOVED": 17,
}
STATE_LABELS = {
    "APPROVED": "已通过",
    "IN_REVIEW": "审核中",
    "METADATA_REJECTED": "元数据被拒",
    "PAST": "已结束",
    "PENDING_APPLE_RELEASE": "待苹果发布",
    "PENDING_DEVELOPER_RELEASE": "待开发者发布",
    "PUBLISHED": "已发布",
    "READY_FOR_DISTRIBUTION": "可分发",
    "READY_FOR_REVIEW": "待提交审核",
    "READY_FOR_SALE": "可销售",
    "REJECTED": "被拒绝",
    "REMOVED": "已移除",
    "WAITING_FOR_EXPORT_COMPLIANCE": "等待出口合规",
    "WAITING_FOR_REVIEW": "等待审核",
}


@dataclass
class Settings:
    asc_issuer_id: str
    asc_key_id: str
    asc_private_key_path: str
    feishu_webhook_url: str
    feishu_secret: str
    feishu_keyword: str
    asc_api_base_url: str
    asc_app_ids: tuple[str, ...]
    state_file_path: str
    sandbox_mode: bool


def load_dotenv_if_present(path: Path) -> None:
    if not path.exists():
        return

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def read_required_env(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise RuntimeError(f"缺少环境变量: {name}")
    return value


def csv_env(name: str, default: str = "") -> tuple[str, ...]:
    raw_value = os.getenv(name, default)
    if raw_value is None:
        return ()
    return tuple(item.strip() for item in raw_value.split(",") if item.strip())


def bool_env(name: str, default: bool) -> bool:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    return raw_value.strip().lower() in {"1", "true", "yes", "y", "on"}


def load_settings() -> Settings:
    sandbox_mode = bool_env("SANDBOX_MODE", False)
    return Settings(
        asc_issuer_id=os.getenv("ASC_ISSUER_ID", "sandbox-issuer").strip() if sandbox_mode else read_required_env("ASC_ISSUER_ID"),
        asc_key_id=os.getenv("ASC_KEY_ID", "sandbox-key").strip() if sandbox_mode else read_required_env("ASC_KEY_ID"),
        asc_private_key_path=os.getenv("ASC_PRIVATE_KEY_PATH", "./asc_private_key.p8").strip()
        if sandbox_mode
        else read_required_env("ASC_PRIVATE_KEY_PATH"),
        feishu_webhook_url=os.getenv("FEISHU_WEBHOOK_URL", "https://example.com/sandbox-webhook").strip()
        if sandbox_mode
        else read_required_env("FEISHU_WEBHOOK_URL"),
        feishu_secret=os.getenv("FEISHU_SECRET", "").strip(),
        feishu_keyword=os.getenv("FEISHU_KEYWORD", "").strip(),
        asc_api_base_url=os.getenv("ASC_API_BASE_URL", "https://api.appstoreconnect.apple.com").strip(),
        asc_app_ids=csv_env("ASC_APP_IDS"),
        state_file_path=os.getenv("STATE_FILE_PATH", "./.state/appstore_review_state.json").strip(),
        sandbox_mode=sandbox_mode,
    )


def build_token(settings: Settings) -> str:
    private_key = Path(settings.asc_private_key_path).read_text(encoding="utf-8")
    now = int(dt.datetime.now(dt.timezone.utc).timestamp())
    payload = {
        "iss": settings.asc_issuer_id,
        "aud": ASC_AUD,
        "iat": now,
        "exp": now + 1200,
    }
    headers = {"alg": "ES256", "kid": settings.asc_key_id, "typ": "JWT"}
    return jwt.encode(payload, private_key, algorithm="ES256", headers=headers)


def auth_headers(settings: Settings) -> dict[str, str]:
    token = build_token(settings)
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }


def fetch_paginated(url: str, headers: dict[str, str], params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    next_url = url
    next_params = params or {}

    while next_url:
        response = requests.get(next_url, headers=headers, params=next_params, timeout=30)
        if not response.ok:
            raise RuntimeError(f"App Store Connect 请求失败: status={response.status_code}, body={response.text}")

        payload = response.json()
        data = payload.get("data")
        if isinstance(data, list):
            items.extend(data)

        links = payload.get("links") or {}
        next_url = links.get("next")
        next_params = None

    return items


def fetch_apps(settings: Settings, headers: dict[str, str]) -> list[dict[str, Any]]:
    base_url = f"{settings.asc_api_base_url.rstrip('/')}/v1/apps"
    if settings.asc_app_ids:
        apps: list[dict[str, Any]] = []
        for app_id in settings.asc_app_ids:
            response = requests.get(
                f"{base_url}/{app_id}",
                headers=headers,
                params={"fields[apps]": "name,bundleId"},
                timeout=30,
            )
            if not response.ok:
                raise RuntimeError(f"获取 App 失败: app_id={app_id}, status={response.status_code}, body={response.text}")
            payload = response.json()
            data = payload.get("data")
            if isinstance(data, dict):
                apps.append(data)
        return apps

    return fetch_paginated(
        base_url,
        headers,
        params={"limit": 200, "fields[apps]": "name,bundleId"},
    )


def fetch_app_versions(settings: Settings, headers: dict[str, str], app_id: str) -> list[dict[str, Any]]:
    return fetch_paginated(
        f"{settings.asc_api_base_url.rstrip('/')}/v1/apps/{app_id}/appStoreVersions",
        headers,
        params={
            "limit": 200,
            "fields[appStoreVersions]": "versionString,platform,appStoreState,appVersionState,createdDate",
        },
    )


def fetch_app_events(settings: Settings, headers: dict[str, str], app_id: str) -> list[dict[str, Any]]:
    return fetch_paginated(
        f"{settings.asc_api_base_url.rstrip('/')}/v1/apps/{app_id}/appEvents",
        headers,
        params={"limit": 200, "fields[appEvents]": "referenceName,eventState,deepLink"},
    )


def fetch_custom_product_pages(settings: Settings, headers: dict[str, str], app_id: str) -> list[dict[str, Any]]:
    return fetch_paginated(
        f"{settings.asc_api_base_url.rstrip('/')}/v1/apps/{app_id}/appCustomProductPages",
        headers,
        params={
            "limit": 200,
            "fields[appCustomProductPages]": "name,url,visible",
        },
    )


def fetch_custom_product_page_versions(settings: Settings, headers: dict[str, str], page_id: str) -> list[dict[str, Any]]:
    return fetch_paginated(
        f"{settings.asc_api_base_url.rstrip('/')}/v1/appCustomProductPages/{page_id}/appCustomProductPageVersions",
        headers,
        params={"limit": 200},
    )


def version_state_label(attributes: dict[str, Any]) -> str:
    app_store_state = str(attributes.get("appStoreState", "")).strip()
    app_version_state = str(attributes.get("appVersionState", "")).strip()
    if app_store_state and app_version_state and app_store_state != app_version_state:
        return f"{app_store_state} / {app_version_state}"
    return app_store_state or app_version_state or "UNKNOWN"


def snapshot_key(item: dict[str, str]) -> str:
    return f"{item['entity_type']}:{item['entity_id']}"


def normalize_app_version(app: dict[str, Any], version: dict[str, Any]) -> dict[str, str]:
    app_attributes = app.get("attributes") or {}
    version_attributes = version.get("attributes") or {}
    return {
        "entity_type": "APP_VERSION",
        "entity_id": str(version.get("id", "")).strip(),
        "app_id": str(app.get("id", "")).strip(),
        "app_name": str(app_attributes.get("name", "")).strip(),
        "bundle_id": str(app_attributes.get("bundleId", "")).strip(),
        "name": str(version_attributes.get("versionString", "")).strip() or "-",
        "platform": str(version_attributes.get("platform", "")).strip() or "-",
        "state": version_state_label(version_attributes),
    }


def normalize_app_event(app: dict[str, Any], event: dict[str, Any]) -> dict[str, str]:
    app_attributes = app.get("attributes") or {}
    event_attributes = event.get("attributes") or {}
    return {
        "entity_type": "IAE",
        "entity_id": str(event.get("id", "")).strip(),
        "app_id": str(app.get("id", "")).strip(),
        "app_name": str(app_attributes.get("name", "")).strip(),
        "bundle_id": str(app_attributes.get("bundleId", "")).strip(),
        "name": str(event_attributes.get("referenceName", "")).strip() or "-",
        "platform": "IOS",
        "state": str(event_attributes.get("eventState", "")).strip() or "UNKNOWN",
    }


def normalize_custom_product_page_versions(
    app: dict[str, Any],
    page: dict[str, Any],
    versions: list[dict[str, Any]],
) -> list[dict[str, str]]:
    app_attributes = app.get("attributes") or {}
    normalized: list[dict[str, str]] = []
    page_id = str(page.get("id", "")).strip()
    page_attributes = page.get("attributes") or {}

    for version in versions:
        version_id = str(version.get("id", "")).strip()
        version_attributes = version.get("attributes") or {}
        normalized.append(
            {
                "entity_type": "CPP",
                "entity_id": version_id,
                "parent_id": page_id,
                "app_id": str(app.get("id", "")).strip(),
                "app_name": str(app_attributes.get("name", "")).strip(),
                "bundle_id": str(app_attributes.get("bundleId", "")).strip(),
                "name": str(page_attributes.get("name", "")).strip() or "-",
                "platform": "IOS",
                "state": str(version_attributes.get("state", "")).strip() or "UNKNOWN",
                "version": str(version_attributes.get("version", "")).strip() or "-",
            }
        )

    return normalized


def collect_review_items(settings: Settings) -> list[dict[str, str]]:
    headers = auth_headers(settings)
    apps = fetch_apps(settings, headers)
    review_items: list[dict[str, str]] = []

    for app in apps:
        app_id = str(app.get("id", "")).strip()
        if not app_id:
            continue

        versions = fetch_app_versions(settings, headers, app_id)
        review_items.extend(normalize_app_version(app, version) for version in versions)

        app_events = fetch_app_events(settings, headers, app_id)
        review_items.extend(normalize_app_event(app, event) for event in app_events)

        cpp_pages = fetch_custom_product_pages(settings, headers, app_id)
        for cpp_page in cpp_pages:
            page_id = str(cpp_page.get("id", "")).strip()
            if not page_id:
                continue
            cpp_versions = fetch_custom_product_page_versions(settings, headers, page_id)
            review_items.extend(normalize_custom_product_page_versions(app, cpp_page, cpp_versions))

    review_items.sort(key=lambda item: (item["entity_type"], item["app_name"], item["name"], item.get("version", "")))
    return review_items


def sandbox_review_items() -> list[dict[str, str]]:
    return [
        {
            "entity_type": "APP_VERSION",
            "entity_id": "sandbox-version-1",
            "app_id": "sandbox-app-1",
            "app_name": "Demo Reader",
            "bundle_id": "com.demo.reader",
            "name": "2.3.1",
            "platform": "IOS",
            "state": "IN_REVIEW",
        },
        {
            "entity_type": "CPP",
            "entity_id": "sandbox-cpp-1",
            "parent_id": "sandbox-cpp-page-1",
            "app_id": "sandbox-app-1",
            "app_name": "Demo Reader",
            "bundle_id": "com.demo.reader",
            "name": "Holiday Landing Page",
            "platform": "IOS",
            "version": "2",
            "state": "WAITING_FOR_REVIEW",
        },
        {
            "entity_type": "IAE",
            "entity_id": "sandbox-iae-1",
            "app_id": "sandbox-app-2",
            "app_name": "Focus Timer Pro",
            "bundle_id": "com.demo.timer",
            "name": "Spring Challenge",
            "platform": "IOS",
            "state": "PUBLISHED",
        },
    ]


def load_snapshot(path: Path) -> dict[str, dict[str, str]]:
    if not path.exists():
        return {}

    payload = json.loads(path.read_text(encoding="utf-8"))
    raw_items = payload.get("items") if isinstance(payload, dict) else None
    if not isinstance(raw_items, dict):
        return {}

    snapshot: dict[str, dict[str, str]] = {}
    for key, item in raw_items.items():
        if isinstance(key, str) and isinstance(item, dict):
            snapshot[key] = {str(item_key): str(item_value) for item_key, item_value in item.items()}
    return snapshot


def save_snapshot(path: Path, items: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    indexed_items = {snapshot_key(item): item for item in items}
    payload = {
        "updated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "items": indexed_items,
    }
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")


def build_change(previous: dict[str, str] | None, current: dict[str, str] | None) -> dict[str, Any]:
    return {
        "previous": previous,
        "current": current,
    }


def diff_snapshots(
    previous_items: dict[str, dict[str, str]],
    current_items: list[dict[str, str]],
) -> list[dict[str, Any]]:
    current_map = {snapshot_key(item): item for item in current_items}
    changes: list[dict[str, Any]] = []

    for key in sorted(set(previous_items) | set(current_map)):
        previous = previous_items.get(key)
        current = current_map.get(key)
        if previous is None and current is not None:
            changes.append(build_change(None, current))
            continue
        if previous is not None and current is None:
            changes.append(build_change(previous, None))
            continue
        if previous and current and previous.get("state") != current.get("state"):
            changes.append(build_change(previous, current))

    return changes


def feishu_signature(secret: str) -> tuple[str, str]:
    timestamp = str(int(dt.datetime.now().timestamp()))
    string_to_sign = f"{timestamp}\n{secret}"
    sign = base64.b64encode(
        hmac.new(string_to_sign.encode("utf-8"), digestmod=hashlib.sha256).digest()
    ).decode("utf-8")
    return timestamp, sign


def build_report_title() -> str:
    now = dt.datetime.now().strftime("%Y-%m-%d %H:%M")
    return f"App审核信息 {now}"


def build_snapshot_title() -> str:
    now = dt.datetime.now().strftime("%Y-%m-%d %H:%M")
    return f"App审核信息概览 {now}"


def rich_text(text: str, *, bold: bool = False) -> dict[str, Any]:
    _ = bold
    return {"tag": "text", "text": text}


def localize_state(state: str) -> str:
    parts = [part.strip() for part in state.split("/") if part.strip()]
    if not parts:
        return "未知状态"
    return " / ".join(STATE_LABELS.get(part, part) for part in parts)


def state_priority(state: str) -> int:
    parts = [part.strip() for part in state.split("/") if part.strip()]
    if not parts:
        return 999
    return min(STATE_PRIORITY.get(part, 999) for part in parts)


def item_label(item: dict[str, str]) -> str:
    entity_type = item.get("entity_type", "")
    app_name = item.get("app_name", "-")
    if entity_type == "APP_VERSION":
        return f"版本 | {app_name} | {item.get('platform', '-')} | {item.get('name', '-')}"
    if entity_type == "CPP":
        return f"CPP | {app_name} | {item.get('name', '-')} | v{item.get('version', '-')}"
    if entity_type == "IAE":
        return f"IAE | {app_name} | {item.get('name', '-')}"
    return f"对象 | {app_name} | {item.get('name', '-')}"


def primary_app_name(items: list[dict[str, str]]) -> str:
    ios_names = [item.get("app_name", "").strip() for item in items if item.get("platform") == "IOS" and item.get("app_name", "").strip()]
    if ios_names:
        return ios_names[0]
    other_names = [item.get("app_name", "").strip() for item in items if item.get("app_name", "").strip()]
    if other_names:
        return other_names[0]
    return "-"


def app_summary_label(items: list[dict[str, str]]) -> str:
    app_names = sorted({item.get("app_name", "").strip() for item in items if item.get("app_name", "").strip()})
    if not app_names:
        return "-"
    if len(app_names) == 1:
        return app_names[0]
    if len(app_names) <= 3:
        return " / ".join(app_names)
    return f"{len(app_names)} 个 App"


def group_changes_by_platform(changes: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {"IOS": [], "ANDROID": []}
    for change in changes:
        source = change.get("current") or change.get("previous") or {}
        grouped.setdefault(source.get("platform", "-"), []).append(change)
    return grouped


def group_items_by_platform(items: list[dict[str, str]]) -> dict[str, list[dict[str, str]]]:
    grouped: dict[str, list[dict[str, str]]] = {"IOS": [], "ANDROID": []}
    for item in items:
        grouped.setdefault(item.get("platform", "-"), []).append(item)
    return grouped


def entity_label(item: dict[str, str]) -> str:
    entity_type = item.get("entity_type", "")
    app_name = item.get("app_name", "-")
    if entity_type == "APP_VERSION":
        return f"[{app_name}] 版本：{item.get('name', '-')}"
    if entity_type == "CPP":
        return f"[{app_name}] CPP：{item.get('name', '-')} | v{item.get('version', '-')}"
    if entity_type == "IAE":
        return f"[{app_name}] IAE：{item.get('name', '-')}"
    return f"对象：{item_label(item)}"


def render_change_lines(change: dict[str, Any]) -> list[str]:
    previous = change.get("previous")
    current = change.get("current")
    source = current or previous or {}
    label_line = entity_label(source)

    if previous is None and current is not None:
        return [
            label_line,
            f"新状态：{localize_state(current.get('state', 'UNKNOWN'))}",
        ]
    if previous is not None and current is None:
        return [
            label_line,
            f"旧状态：{localize_state(previous.get('state', 'UNKNOWN'))}",
            f"新状态：{localize_state('REMOVED')}",
        ]
    return [
        label_line,
        f"旧状态：{localize_state((previous or {}).get('state', 'UNKNOWN'))}",
        f"新状态：{localize_state((current or {}).get('state', 'UNKNOWN'))}",
    ]


def render_item_lines(item: dict[str, str]) -> list[str]:
    return [
        entity_label(item),
        f"新状态：{localize_state(item.get('state', 'UNKNOWN'))}",
    ]


def item_sort_key(item: dict[str, str]) -> tuple[Any, ...]:
    return (
        state_priority(item.get("state", "")),
        item.get("app_name", ""),
        item.get("name", ""),
        item.get("version", ""),
    )


def change_sort_key(change: dict[str, Any]) -> tuple[Any, ...]:
    current = change.get("current") or {}
    previous = change.get("previous") or {}
    source = current or previous
    return (
        min(
            state_priority(current.get("state", "")) if current else 999,
            state_priority(previous.get("state", "")) if previous else 999,
        ),
        source.get("app_name", ""),
        source.get("name", ""),
        source.get("version", ""),
    )


def build_report_rows(settings: Settings, changes: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    rows: list[list[dict[str, Any]]] = []
    if settings.feishu_keyword:
        rows.append([rich_text(settings.feishu_keyword)])

    all_changes = sorted(changes, key=change_sort_key)
    summary_items = [(change.get("current") or change.get("previous") or {}) for change in all_changes]
    rows.append([rich_text(app_summary_label(summary_items), bold=True)])
    if all_changes:
        grouped = group_changes_by_platform(all_changes)
        for platform in ("IOS", "ANDROID"):
            platform_changes = sorted(grouped.get(platform, []), key=change_sort_key)
            if not platform_changes:
                continue
            rows.append([rich_text(f"【{platform}】", bold=True)])
            for change in platform_changes:
                for line in render_change_lines(change):
                    rows.append([rich_text(line)])

    return rows


def build_snapshot_rows(settings: Settings, items: list[dict[str, str]]) -> list[list[dict[str, Any]]]:
    rows: list[list[dict[str, Any]]] = []
    if settings.feishu_keyword:
        rows.append([rich_text(settings.feishu_keyword)])

    all_items = sorted(items, key=item_sort_key)
    rows.append([rich_text(app_summary_label(all_items), bold=True)])
    if all_items:
        grouped = group_items_by_platform(all_items)
        for platform in ("IOS", "ANDROID"):
            platform_items = sorted(grouped.get(platform, []), key=item_sort_key)
            if not platform_items:
                continue
            rows.append([rich_text(f"【{platform}】", bold=True)])
            for item in platform_items:
                for line in render_item_lines(item):
                    rows.append([rich_text(line)])

    return rows


def build_feishu_payload_from_rows(title: str, rows: list[list[dict[str, Any]]]) -> dict[str, Any]:
    return {
        "msg_type": "post",
        "content": {
            "post": {
                "zh_cn": {
                    "title": title,
                    "content": rows,
                }
            }
        },
    }


def build_feishu_payload(settings: Settings, changes: list[dict[str, Any]]) -> dict[str, Any]:
    rows = build_report_rows(settings, changes)
    return build_feishu_payload_from_rows(build_report_title(), rows)


def build_snapshot_payload(settings: Settings, items: list[dict[str, str]]) -> dict[str, Any]:
    rows = build_snapshot_rows(settings, items)
    return build_feishu_payload_from_rows(build_snapshot_title(), rows)


def build_report_lines(settings: Settings, changes: list[dict[str, Any]]) -> list[str]:
    lines: list[str] = []
    if settings.feishu_keyword:
        lines.append(settings.feishu_keyword)

    lines.append(f"检测到 {len(changes)} 项App审核信息变化")

    for change in changes:
        lines.extend(render_change_lines(change))

    return lines


def send_to_feishu(settings: Settings, payload: dict[str, Any]) -> dict[str, Any]:
    if settings.sandbox_mode:
        return {
            "code": 0,
            "msg": "success",
            "data": {
                "sandbox": True,
                "preview_title": payload["content"]["post"]["zh_cn"]["title"],
                "preview_lines": [line[0]["text"] for line in payload["content"]["post"]["zh_cn"]["content"]],
            },
        }

    if settings.feishu_secret:
        timestamp, sign = feishu_signature(settings.feishu_secret)
        payload["timestamp"] = timestamp
        payload["sign"] = sign

    response = requests.post(settings.feishu_webhook_url, json=payload, timeout=15)
    response.raise_for_status()
    result = response.json()
    code = result.get("code")
    if code not in (0, None):
        raise RuntimeError(f"飞书 webhook 返回异常: {json.dumps(result, ensure_ascii=False)}")
    return result


def main() -> int:
    try:
        load_dotenv_if_present(Path(".env"))
        settings = load_settings()
        current_items = sandbox_review_items() if settings.sandbox_mode else collect_review_items(settings)
        state_path = Path(settings.state_file_path)
        previous_items = load_snapshot(state_path)

        if not previous_items:
            save_snapshot(state_path, current_items)
            print(
                json.dumps(
                    {
                        "status": "ok",
                        "sandbox_mode": settings.sandbox_mode,
                        "message": "首次初始化状态快照，未发送消息",
                        "tracked_count": len(current_items),
                        "state_file_path": settings.state_file_path,
                    },
                    ensure_ascii=False,
                )
            )
            return 0

        changes = diff_snapshots(previous_items, current_items)
        if not changes:
            print(
                json.dumps(
                    {
                        "status": "ok",
                        "sandbox_mode": settings.sandbox_mode,
                        "message": "未检测到审核状态变化，已跳过发送",
                        "tracked_count": len(current_items),
                        "state_file_path": settings.state_file_path,
                    },
                    ensure_ascii=False,
                )
            )
            return 0

        payload = build_feishu_payload(settings, changes)
        result = send_to_feishu(settings, payload)
        save_snapshot(state_path, current_items)
        print(
            json.dumps(
                {
                    "status": "ok",
                    "sandbox_mode": settings.sandbox_mode,
                    "message": "检测到状态变化并已发送",
                    "change_count": len(changes),
                    "tracked_count": len(current_items),
                    "state_file_path": settings.state_file_path,
                    "feishu": result,
                },
                ensure_ascii=False,
            )
        )
        return 0
    except Exception as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
