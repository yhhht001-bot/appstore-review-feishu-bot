import sys
import types
import unittest
from unittest import mock

sys.modules.setdefault("jwt", types.SimpleNamespace(encode=lambda *args, **kwargs: "token"))
sys.modules.setdefault("requests", types.SimpleNamespace())

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
            state_file_path="./.state/test.json",
            sandbox_mode=False,
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
        ):
            items = report.collect_review_items(settings)

        app_a_events = [item for item in items if item["entity_type"] == "IAE" and item["app_id"] == "app-a"]
        app_b_events = [item for item in items if item["entity_type"] == "IAE" and item["app_id"] == "app-b"]

        self.assertEqual([item["name"] for item in app_a_events], ["Challenge11"])
        self.assertEqual([item["name"] for item in app_b_events], ["Challenge12"])


if __name__ == "__main__":
    unittest.main()
