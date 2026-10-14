from __future__ import annotations

from fastapi.testclient import TestClient

from secmind.api import create_app


def test_lifecycle_prompt_catalog_and_preview_are_read_only_and_routable(settings) -> None:
    settings.prepare_directories()
    with TestClient(create_app(settings), base_url="http://127.0.0.1") as client:
        response = client.get("/api/v1/prompts/lifecycle")
        assert response.status_code == 200
        payload = response.json()
        assert payload["count"] == 195
        assert payload["library_version"] == "2.0.0"
        assert payload["prompt_content_exposed"] is False
        assert all("template" not in item for item in payload["items"])

        role_payload = client.get(
            "/api/v1/prompts/lifecycle",
            params={"role": "plan_author"},
        ).json()
        assert role_payload["count"] == 15

        preview = client.post(
            "/api/v1/prompts/lifecycle/preview",
            json={"role": "plan_author", "signals": ["monorepo"], "top_k": 1},
        )
        assert preview.status_code == 200
        assert preview.json()["executes_model"] is False
        assert preview.json()["selected"][0]["prompt_id"] == "plan-author-monorepo"


def test_lifecycle_prompt_preview_rejects_unknown_roles(settings) -> None:
    settings.prepare_directories()
    with TestClient(create_app(settings), base_url="http://127.0.0.1") as client:
        response = client.post(
            "/api/v1/prompts/lifecycle/preview",
            json={"role": "untrusted_super_agent", "signals": [], "top_k": 1},
        )
        assert response.status_code == 422
