# Copyright 2026 Alibaba Group Holding Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from fastapi.testclient import TestClient

from opensandbox_server.api import devops


def test_diagnostics_logs_with_scope_returns_stable_inline_descriptor(
    client: TestClient,
    auth_headers: dict,
    monkeypatch,
) -> None:
    class StubService:
        @staticmethod
        def get_sandbox_logs(
            sandbox_id: str,
            tail: int,
            since: str | None = None,
            container: str | None = None,
        ) -> str:
            assert sandbox_id == "sbx-001"
            assert tail == 100
            assert since is None
            assert container is None
            return "sandbox log line"

    monkeypatch.setattr(devops, "sandbox_service", StubService())

    response = client.get(
        "/v1/sandboxes/sbx-001/diagnostics/logs?scope=container",
        headers=auth_headers,
    )

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    assert response.json() == {
        "sandboxId": "sbx-001",
        "kind": "logs",
        "scope": "container",
        "delivery": "inline",
        "contentType": "text/plain; charset=utf-8",
        "content": "sandbox log line",
        "contentLength": 16,
        "truncated": False,
    }


def test_diagnostics_logs_rejects_unsupported_scope(
    client: TestClient,
    auth_headers: dict,
    monkeypatch,
) -> None:
    class StubService:
        @staticmethod
        def get_sandbox_logs(*args, **kwargs) -> str:
            raise AssertionError("unsupported scope must not query the backend")

    monkeypatch.setattr(devops, "sandbox_service", StubService())

    response = client.get(
        "/v1/sandboxes/sbx-001/diagnostics/logs?scope=TEXT",
        headers=auth_headers,
    )

    assert response.status_code == 400
    assert response.json()["code"] == "DIAGNOSTICS_SCOPE_UNSUPPORTED"


def test_diagnostics_logs_all_scope_discloses_backend_limit(
    client: TestClient,
    auth_headers: dict,
    monkeypatch,
) -> None:
    class StubService:
        @staticmethod
        def get_sandbox_logs(*args, **kwargs) -> str:
            return "container logs only"

    monkeypatch.setattr(devops, "sandbox_service", StubService())

    response = client.get(
        "/v1/sandboxes/sbx-001/diagnostics/logs?scope=all",
        headers=auth_headers,
    )

    assert response.status_code == 200
    assert response.json()["warnings"] == [
        "This backend currently contributes sandbox container logs only."
    ]


def test_diagnostics_logs_without_scope_preserves_deprecated_plain_text(
    client: TestClient,
    auth_headers: dict,
    monkeypatch,
) -> None:
    class StubService:
        @staticmethod
        def get_sandbox_logs(
            sandbox_id: str,
            tail: int,
            since: str | None = None,
            container: str | None = None,
        ) -> str:
            assert sandbox_id == "sbx-001"
            assert tail == 25
            assert since == "5m"
            assert container is None
            return "legacy logs"

    monkeypatch.setattr(devops, "sandbox_service", StubService())

    response = client.get(
        "/v1/sandboxes/sbx-001/diagnostics/logs?tail=25&since=5m",
        headers=auth_headers,
    )

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    assert response.headers["deprecation"] == "true"
    assert response.text == "legacy logs"


def test_diagnostics_logs_forwards_container_query_to_service(
    client: TestClient,
    auth_headers: dict,
    monkeypatch,
) -> None:
    captured: dict = {}

    class StubService:
        @staticmethod
        def get_sandbox_logs(
            sandbox_id: str,
            tail: int,
            since: str | None = None,
            container: str | None = None,
        ) -> str:
            captured["container"] = container
            return "sidecar logs"

    monkeypatch.setattr(devops, "sandbox_service", StubService())

    response = client.get(
        "/v1/sandboxes/sbx-001/diagnostics/logs?container=egress",
        headers=auth_headers,
    )

    assert response.status_code == 200
    assert response.text == "sidecar logs"
    assert captured == {"container": "egress"}


def test_diagnostics_events_with_scope_returns_stable_inline_descriptor(
    client: TestClient,
    auth_headers: dict,
    monkeypatch,
) -> None:
    class StubService:
        @staticmethod
        def get_sandbox_events(sandbox_id: str, limit: int) -> str:
            assert sandbox_id == "sbx-001"
            assert limit == 50
            return "runtime event"

    monkeypatch.setattr(devops, "sandbox_service", StubService())

    response = client.get(
        "/v1/sandboxes/sbx-001/diagnostics/events?scope=RUNTIME",
        headers=auth_headers,
    )

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    assert response.json() == {
        "sandboxId": "sbx-001",
        "kind": "events",
        "scope": "runtime",
        "delivery": "inline",
        "contentType": "text/plain; charset=utf-8",
        "content": "runtime event",
        "contentLength": 13,
        "truncated": False,
    }


def test_diagnostics_events_lifecycle_scope_discloses_runtime_mapping(
    client: TestClient,
    auth_headers: dict,
    monkeypatch,
) -> None:
    class StubService:
        @staticmethod
        def get_sandbox_events(*args, **kwargs) -> str:
            return "runtime event"

    monkeypatch.setattr(devops, "sandbox_service", StubService())

    response = client.get(
        "/v1/sandboxes/sbx-001/diagnostics/events?scope=lifecycle",
        headers=auth_headers,
    )

    assert response.status_code == 200
    assert response.json()["warnings"] == [
        "This backend currently represents lifecycle/all scopes with runtime events."
    ]


def test_diagnostics_summary_redacts_unexpected_exception_details(
    client: TestClient,
    auth_headers: dict,
    monkeypatch,
) -> None:
    class StubService:
        @staticmethod
        def get_sandbox_inspect(sandbox_id: str) -> str:
            raise RuntimeError("backend secret token")

        @staticmethod
        def get_sandbox_events(sandbox_id: str, limit: int) -> str:
            return "events ok"

        @staticmethod
        def get_sandbox_logs(
            sandbox_id: str,
            tail: int,
            since: str | None = None,
            container: str | None = None,
        ) -> str:
            return "logs ok"

    monkeypatch.setattr(devops, "sandbox_service", StubService())

    response = client.get(
        "/v1/sandboxes/sbx-001/diagnostics/summary",
        headers=auth_headers,
    )

    assert response.status_code == 200
    assert "[error] Failed to collect inspect diagnostics." in response.text
    assert "backend secret token" not in response.text
    assert "events ok" in response.text
    assert "logs ok" in response.text
