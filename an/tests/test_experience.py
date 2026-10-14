from __future__ import annotations

from fastapi.testclient import TestClient

from security_agent.api import create_app


def test_experience_api_supports_manual_create_list_and_delete(settings) -> None:
    settings.prepare_directories()
    app = create_app(settings)
    with TestClient(app) as client:
        empty = client.get("/api/v1/experiences")
        assert empty.status_code == 200
        assert empty.json()["statistics"]["total"] == 0

        created = client.post(
            "/api/v1/experiences",
            json={
                "title": "先确认源码覆盖率",
                "summary": "压缩包审计前先安全展开，并确认至少存在一个受支持源码文件。",
                "module_route": "code_audit",
                "experience_kind": "operator_note",
                "vulnerability_type": "execution_coverage",
                "tags": ["archive", "coverage"],
            },
        )
        assert created.status_code == 201
        experience = created.json()["experience"]
        assert experience["source_type"] == "manual"
        assert experience["source_title"] == "人工填入"
        assert experience["verified"] is False

        listed = client.get("/api/v1/experiences?source_type=manual")
        assert listed.status_code == 200
        assert listed.json()["statistics"]["manual"] == 1
        assert listed.json()["experiences"][0]["tags"] == ["archive", "coverage"]

        deleted = client.delete(f"/api/v1/experiences/{experience['experience_id']}")
        assert deleted.status_code == 204
        assert client.get("/api/v1/experiences").json()["experiences"] == []


def test_experience_delete_returns_not_found(settings) -> None:
    app = create_app(settings)
    with TestClient(app) as client:
        response = client.delete("/api/v1/experiences/does-not-exist")
        assert response.status_code == 404


def test_experience_list_pages_cover_all_filtered_records(settings) -> None:
    app = create_app(settings)
    with TestClient(app) as client:
        ids = set()
        for number in range(3):
            response = client.post('/api/v1/experiences', json={
                'title': f'经验 {number}', 'summary': f'第 {number} 条完整经验',
                'module_route': 'code_audit', 'experience_kind': 'operator_note',
            })
            assert response.status_code == 201
            ids.add(response.json()['experience']['experience_id'])
        pages = [client.get('/api/v1/experiences', params={'limit': 1, 'offset': offset}).json()
                 for offset in range(3)]
        assert {page['experiences'][0]['experience_id'] for page in pages} == ids
        assert all(page['statistics']['total'] == 3 for page in pages)
        assert [page['has_more'] for page in pages] == [True, True, False]
        assert client.get('/api/v1/experiences', params={'offset': -1}).status_code == 422
