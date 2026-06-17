import sys
import tempfile
import types
import unittest
from unittest import mock

sys.modules.setdefault("jwt", types.SimpleNamespace(encode=lambda *args, **kwargs: "token"))
sys.modules.setdefault("requests", types.SimpleNamespace())
sys.modules.setdefault("google", types.ModuleType("google"))
sys.modules.setdefault("google.auth", types.ModuleType("google.auth"))
sys.modules.setdefault("google.auth.transport", types.ModuleType("google.auth.transport"))
sys.modules.setdefault(
    "google.auth.transport.requests",
    types.SimpleNamespace(Request=lambda *args, **kwargs: object()),
)
sys.modules.setdefault("google.oauth2", types.ModuleType("google.oauth2"))
sys.modules.setdefault(
    "google.oauth2.service_account",
    types.SimpleNamespace(Credentials=types.SimpleNamespace(from_service_account_file=lambda *args, **kwargs: object())),
)

import appstore_review_report as report


def make_app(app_id: str, name: str) -> dict:
    return {
        "id": app_id,
        "attributes": {
            "name": name,
            "bundleId": f"com.example.{app_id}",
        },
    }


def make_event(event_id: str, reference_name: str, state: str, related_app_id: str) -> dict:
    return {
        "id": event_id,
        "attributes": {
            "referenceName": reference_name,
            "eventState": state,
        },
        "relationships": {
            "app": {
                "data": {
                    "id": related_app_id,
                    "type": "apps",
                }
            }
        },
    }


class CollectReviewItemsTests(unittest.TestCase):
    def test_collect_review_items_filters_cross_app_events(self) -> None:
        settings = report.Settings(
            asc_issuer_id="issuer",
            asc_key_id="key",
            asc_private_key_path="unused.p8",
            feishu_webhook_url="https://example.com",
            feishu_secret="",
            feishu_keyword="",
            asc_api_base_url="https://api.example.com",
            asc_app_ids=(),
            gplay_service_account_json_path="./google_play_service_account.json",
            gplay_package_names=(),
            state_file_path="./.state/test.json",
            sandbox_mode=False,
            send_google_play_snapshot=False,
        )
        app_a = make_app("app-a", "Chair Yoga & Tai Chi Walking")
        app_b = make_app("app-b", "Other App")

        def fake_fetch_app_events(_settings, _headers, app_id: str):
            if app_id == "app-a":
                return [
                    make_event("event-a", "Challenge11", "WAITING_FOR_REVIEW", "app-a"),
                    make_event("event-b", "Challenge12", "WAITING_FOR_REVIEW", "app-b"),
                ]
            if app_id == "app-b":
                return [make_event("event-b", "Challenge12", "WAITING_FOR_REVIEW", "app-b")]
            return []

        with mock.patch.object(report, "auth_headers", return_value={"Authorization": "Bearer token"}), mock.patch.object(
            report, "fetch_apps", return_value=[app_a, app_b]
        ), mock.patch.object(report, "fetch_app_versions", return_value=[]), mock.patch.object(
            report, "fetch_custom_product_pages", return_value=[]
        ), mock.patch.object(
            report, "fetch_custom_product_page_versions", return_value=[]
        ), mock.patch.object(
            report, "fetch_app_events", side_effect=fake_fetch_app_events
        ), mock.patch.object(
            report, "collect_google_play_items", return_value=[]
        ):
            items = report.collect_review_items(settings)

        app_a_events = [item for item in items if item["entity_type"] == "IAE" and item["app_id"] == "app-a"]
        app_b_events = [item for item in items if item["entity_type"] == "IAE" and item["app_id"] == "app-b"]

        self.assertEqual([item["name"] for item in app_a_events], ["Challenge11"])
        self.assertEqual([item["name"] for item in app_b_events], ["Challenge12"])

    def test_collect_google_play_items_reads_production_releases(self) -> None:
        with tempfile.NamedTemporaryFile() as service_account_file:
            settings = report.Settings(
                asc_issuer_id="issuer",
                asc_key_id="key",
                asc_private_key_path="unused.p8",
                feishu_webhook_url="https://example.com",
                feishu_secret="",
                feishu_keyword="",
                asc_api_base_url="https://api.example.com",
                asc_app_ids=(),
                gplay_service_account_json_path=service_account_file.name,
                gplay_package_names=("com.example.app",),
                state_file_path="./.state/test.json",
                sandbox_mode=False,
                send_google_play_snapshot=False,
            )

            tracks = [
                {
                    "track": "internal",
                    "releases": [{"name": "1.0.0", "status": "completed", "versionCodes": ["100"]}],
                },
                {
                    "track": "production",
                    "releases": [{"name": "1.2.3", "status": "inProgress", "versionCodes": ["123"], "userFraction": 0.5}],
                },
            ]
            with mock.patch.object(report, "build_google_play_headers", return_value={"Authorization": "Bearer token"}), mock.patch.object(
                report, "fetch_google_play_tracks", return_value=tracks
            ):
                items = report.collect_google_play_items(settings)

        self.assertEqual(len(items), 1)
        self.assertEqual(
            items[0],
            {
                "entity_type": "GOOGLE_PLAY_RELEASE",
                "entity_id": "com.example.app:production:123",
                "app_id": "com.example.app",
                "app_name": "com.example.app",
                "bundle_id": "com.example.app",
                "name": "1.2.3",
                "platform": "ANDROID",
                "state": "inProgress",
                "track": "production",
                "version": "123",
                "rollout": "50%",
            },
        )

    def test_google_play_release_uses_configured_display_name(self) -> None:
        item = report.normalize_google_play_release(
            "com.seniorchairyoga.eab",
            {"track": "production"},
            {"name": "102 (1.0.0)", "status": "completed", "versionCodes": ["102"]},
        )

        self.assertEqual(item["app_name"], "Chair Yoga")
        self.assertEqual(item["bundle_id"], "com.seniorchairyoga.eab")


class MessageGroupingTests(unittest.TestCase):
    def test_build_report_rows_groups_changes_by_app_within_platform(self) -> None:
        settings = report.Settings(
            asc_issuer_id="issuer",
            asc_key_id="key",
            asc_private_key_path="unused.p8",
            feishu_webhook_url="https://example.com",
            feishu_secret="",
            feishu_keyword="",
            asc_api_base_url="https://api.example.com",
            asc_app_ids=(),
            gplay_service_account_json_path="./google_play_service_account.json",
            gplay_package_names=(),
            state_file_path="./.state/test.json",
            sandbox_mode=False,
            send_google_play_snapshot=False,
        )
        changes = [
            {
                "previous": {"entity_type": "APP_VERSION", "app_name": "Chair Yoga & Tai Chi Walking", "platform": "IOS", "name": "1.0.0", "state": "PENDING_DEVELOPER_RELEASE"},
                "current": {"entity_type": "APP_VERSION", "app_name": "Chair Yoga & Tai Chi Walking", "platform": "IOS", "name": "1.0.0", "state": "READY_FOR_SALE / READY_FOR_DISTRIBUTION"},
            },
            {
                "previous": {"entity_type": "IAE", "app_name": "Other App", "platform": "IOS", "name": "Challenge12", "state": "APPROVED"},
                "current": {"entity_type": "IAE", "app_name": "Other App", "platform": "IOS", "name": "Challenge12", "state": "PUBLISHED"},
            },
        ]

        rows = report.build_report_rows(settings, changes)
        texts = [row[0]["text"] for row in rows]

        self.assertEqual(
            texts,
            [
                "Chair Yoga & Tai Chi Walking / Other App",
                "【IOS】",
                "Chair Yoga & Tai Chi Walking",
                "[Chair Yoga & Tai Chi Walking] 版本：1.0.0",
                "旧状态：待开发者发布",
                "新状态：可销售 / 可分发",
                "Other App",
                "[Other App] IAE：Challenge12",
                "旧状态：已通过",
                "新状态：已发布",
            ],
        )

    def test_build_google_play_snapshot_payload_renders_android_status(self) -> None:
        settings = report.Settings(
            asc_issuer_id="issuer",
            asc_key_id="key",
            asc_private_key_path="unused.p8",
            feishu_webhook_url="https://example.com",
            feishu_secret="",
            feishu_keyword="",
            asc_api_base_url="https://api.example.com",
            asc_app_ids=(),
            gplay_service_account_json_path="./google_play_service_account.json",
            gplay_package_names=("com.example.app",),
            state_file_path="./.state/test.json",
            sandbox_mode=False,
            send_google_play_snapshot=True,
        )
        payload = report.build_google_play_snapshot_payload(
            settings,
            [
                {
                    "entity_type": "GOOGLE_PLAY_RELEASE",
                    "entity_id": "com.example.app:production:123",
                    "app_id": "com.example.app",
                    "app_name": "Chair Yoga",
                    "bundle_id": "com.example.app",
                    "name": "1.2.3",
                    "platform": "ANDROID",
                    "state": "completed",
                    "track": "production",
                    "version": "123",
                    "rollout": "-",
                }
            ],
        )

        post = payload["content"]["post"]["zh_cn"]
        texts = [row[0]["text"] for row in post["content"]]

        self.assertTrue(post["title"].startswith("Google Play审核信息 "))
        self.assertEqual(
            texts,
            [
                "Chair Yoga",
                "【ANDROID】",
                "Chair Yoga",
                "[Chair Yoga] Google Play：1.2.3 | production | 123",
                "新状态：已发布",
            ],
        )


if __name__ == "__main__":
    unittest.main()
