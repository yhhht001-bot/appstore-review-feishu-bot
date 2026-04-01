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


@dataclass
class Settings:
    asc_issuer_id: str
    asc_key_id: str
    asc_private_key_path: str
    feishu_webhook_url: str
    feishu_secret: str
    feishu_keyword: str
    asc_api_base_url: str
    asc_review_states: tuple[str, ...]
    asc_app_ids: tuple[str, ...]
    report_empty_result: bool
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
    default_states = (
        "READY_FOR_REVIEW",
        "WAITING_FOR_REVIEW",
        "IN_REVIEW",
        "PENDING_DEVELOPER_RELEASE",
        "PENDING_APPLE_RELEASE",
        "REJECTED",
        "METADATA_REJECTED",
        "WAITING_FOR_EXPORT_COMPLIANCE",
    )
    sandbox_mode = bool_env("SANDBOX_MODE", False)
    return Settings(
        asc_issuer_id=os.getenv("ASC_ISSUER_ID", "sandbox-issuer").strip() if sandbox_mode else read_required_env("ASC_ISSUER_ID"),
        asc_key_id=os.getenv("ASC_KEY_ID", "sandbox-key").strip() if sandbox_mode else read_required_env("ASC_KEY_ID"),
        asc_private_key_path=os.getenv("ASC_PRIVATE_KEY_PATH", "./asc_private_key.p8").strip() if sandbox_mode else read_required_env("ASC_PRIVATE_KEY_PATH"),
        feishu_webhook_url=os.getenv("FEISHU_WEBHOOK_URL", "https://example.com/sandbox-webhook").strip() if sandbox_mode else read_required_env("FEISHU_WEBHOOK_URL"),
        feishu_secret=os.getenv("FEISHU_SECRET", "").strip(),
        feishu_keyword=os.getenv("FEISHU_KEYWORD", "").strip(),
        asc_api_base_url=os.getenv("ASC_API_BASE_URL", "https://api.appstoreconnect.apple.com").strip(),
        asc_review_states=csv_env("ASC_REVIEW_STATES", ",".join(default_states)) or default_states,
        asc_app_ids=csv_env("ASC_APP_IDS"),
        report_empty_result=bool_env("REPORT_EMPTY_RESULT", True),
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
        params={"limit": 200, "fields[appStoreVersions]": "versionString,platform,appStoreState,createdDate"},
    )


def normalize_app_entry(app: dict[str, Any], version: dict[str, Any]) -> dict[str, str]:
    app_attributes = app.get("attributes") or {}
    version_attributes = version.get("attributes") or {}
    return {
        "app_name": str(app_attributes.get("name", "")).strip(),
        "bundle_id": str(app_attributes.get("bundleId", "")).strip(),
        "version": str(version_attributes.get("versionString", "")).strip(),
        "platform": str(version_attributes.get("platform", "")).strip(),
        "state": str(version_attributes.get("appStoreState", "")).strip(),
        "app_id": str(app.get("id", "")).strip(),
    }


def collect_review_items(settings: Settings) -> list[dict[str, str]]:
    headers = auth_headers(settings)
    apps = fetch_apps(settings, headers)
    review_items: list[dict[str, str]] = []
    watched_states = set(settings.asc_review_states)

    for app in apps:
        app_id = str(app.get("id", "")).strip()
        if not app_id:
            continue

        versions = fetch_app_versions(settings, headers, app_id)
        for version in versions:
            item = normalize_app_entry(app, version)
            if item["state"] in watched_states:
                review_items.append(item)

    review_items.sort(key=lambda item: (item["app_name"], item["platform"], item["version"]), reverse=False)
    return review_items


def sandbox_review_items(settings: Settings) -> list[dict[str, str]]:
    sample_items = [
        {
            "app_name": "Demo Reader",
            "bundle_id": "com.demo.reader",
            "version": "2.3.1",
            "platform": "IOS",
            "state": "IN_REVIEW",
            "app_id": "sandbox-app-1",
        },
        {
            "app_name": "Demo Reader",
            "bundle_id": "com.demo.reader",
            "version": "2.3.0",
            "platform": "IOS",
            "state": "PENDING_DEVELOPER_RELEASE",
            "app_id": "sandbox-app-1",
        },
        {
            "app_name": "Focus Timer Pro",
            "bundle_id": "com.demo.timer",
            "version": "1.8.0",
            "platform": "IOS",
            "state": "REJECTED",
            "app_id": "sandbox-app-2",
        },
    ]
    watched_states = set(settings.asc_review_states)
    return [item for item in sample_items if item["state"] in watched_states]


def feishu_signature(secret: str) -> tuple[str, str]:
    timestamp = str(int(dt.datetime.now().timestamp()))
    string_to_sign = f"{timestamp}\n{secret}"
    sign = base64.b64encode(
        hmac.new(string_to_sign.encode("utf-8"), digestmod=hashlib.sha256).digest()
    ).decode("utf-8")
    return timestamp, sign


def build_report_title() -> str:
    now = dt.datetime.now().strftime("%Y-%m-%d %H:%M")
    return f"App 审核播报 {now}"


def build_report_lines(settings: Settings, review_items: list[dict[str, str]]) -> list[str]:
    lines: list[str] = []
    if settings.feishu_keyword:
        lines.append(settings.feishu_keyword)

    if not review_items:
        lines.append("当前没有命中审核关注状态的版本")
        return lines

    for item in review_items:
        lines.append(
            f"{item['app_name']} | {item['platform']} | {item['version']} | {item['state']}"
        )
    return lines


def build_feishu_payload(settings: Settings, review_items: list[dict[str, str]]) -> dict[str, Any]:
    lines = build_report_lines(settings, review_items)
    return {
        "msg_type": "post",
        "content": {
            "post": {
                "zh_cn": {
                    "title": build_report_title(),
                    "content": [[{"tag": "text", "text": line}] for line in lines],
                }
            }
        },
    }


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
        review_items = sandbox_review_items(settings) if settings.sandbox_mode else collect_review_items(settings)
        if not review_items and not settings.report_empty_result:
            print(json.dumps({"status": "ok", "message": "当前无命中状态，已跳过发送"}, ensure_ascii=False))
            return 0

        payload = build_feishu_payload(settings, review_items)
        result = send_to_feishu(settings, payload)
        print(
            json.dumps(
                {
                    "status": "ok",
                    "sandbox_mode": settings.sandbox_mode,
                    "matched_count": len(review_items),
                    "feishu": result,
                    "states": settings.asc_review_states,
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
