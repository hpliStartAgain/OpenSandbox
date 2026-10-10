# Copyright 2026 The OpenSandbox Authors
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

from contextlib import nullcontext
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from docker.errors import DockerException
from fastapi import HTTPException
import pytest

from opensandbox_server.api.schema import (
    CreateSandboxRequest, CredentialProxyConfig, ImageSpec, NetworkPolicy, PVC, ResourceLimits, Volume,
)
from opensandbox_server.config import AppConfig, EgressConfig, IngressConfig, RuntimeConfig
from opensandbox_server.services.constants import SANDBOX_MANAGED_VOLUMES_LABEL
from opensandbox_server.services.docker import DockerSandboxService
from opensandbox_server.services.docker.snapshot_runtime import DockerSnapshotRuntime
from opensandbox_server.services.egress_quarantine import (
    EXPERIMENTAL_REVISION_RUNTIME_ENV,
    QUARANTINE_DIRECTORY,
    QUARANTINE_ID_ENV,
    QUARANTINE_LABEL,
    QUARANTINE_OWNER_LABEL,
    QUARANTINE_VOLUME_PREFIX,
)
from opensandbox_server.services.factory import create_sandbox_service
from opensandbox_server.services.helpers import split_egress_env


@pytest.fixture
def service(monkeypatch):
    monkeypatch.setenv(EXPERIMENTAL_REVISION_RUNTIME_ENV, "true")
    service = object.__new__(DockerSandboxService)
    service.app_config = AppConfig(
        runtime=RuntimeConfig(type="docker", execd_image="execd:test"),
        egress=EgressConfig(image="egress:test", mode="dns+nft"),
    )
    service.docker_client = MagicMock()
    service.docker_client.containers.list.return_value = []
    service.docker_client.api.create_host_config.side_effect = lambda **kwargs: kwargs
    service.docker_client.api.create_container.return_value = {"Id": "sidecar-id"}
    service.docker_client.containers.create.return_value.wait.return_value = {"StatusCode": 0}
    service._ensure_image_available = MagicMock()
    service._wait_for_egress_sidecar_ready = MagicMock()
    service._cleanup_managed_volumes = MagicMock()
    service._docker_operation = lambda *args, **kwargs: nullcontext()
    return service


def _start(service, **changes):
    kwargs = dict(
        sandbox_id="sandbox-id",
        network_policy=NetworkPolicy(defaultAction="deny", egress=[]),
        egress_token="token",
        host_execd_port=44772,
        host_http_port=8080,
        egress_api_host_port=18080,
        credential_proxy_enabled=True,
        runtime_volume_name="shared-runtime",
    )
    kwargs.update(changes)
    return service._start_egress_sidecar(**kwargs)


def test_helper_provisions_before_sidecar_with_private_mount(service):
    client = service.docker_client
    helper = client.containers.create.return_value
    order = MagicMock()
    order.attach_mock(helper.remove, "remove_helper")
    order.attach_mock(client.api.create_container, "create_sidecar")
    order.attach_mock(client.containers.get.return_value.start, "start_sidecar")
    order.attach_mock(service._wait_for_egress_sidecar_ready, "ready")

    _start(service)

    volume = client.volumes.create.call_args.kwargs
    assert volume["name"].startswith(QUARANTINE_VOLUME_PREFIX)
    assert volume["labels"] == {
        SANDBOX_MANAGED_VOLUMES_LABEL: "server", QUARANTINE_OWNER_LABEL: "sandbox-id",
    }
    helper_config = client.containers.create.call_args.kwargs
    assert helper_config["entrypoint"] == ["/opt/opensandbox-egress/egress"]
    assert helper_config["command"] == ["--provision-quarantine"]
    assert helper_config["network_mode"] == "none"
    assert helper_config["cap_drop"] == ["ALL"]
    assert helper_config["read_only"] is True
    assert helper_config["restart_policy"] == {"Name": "no"}
    assert helper_config["volumes"] == {
        volume["name"]: {"bind": QUARANTINE_DIRECTORY, "mode": "rw"},
    }
    incarnation = helper_config["environment"][QUARANTINE_ID_ENV]
    assert len(incarnation) == 32
    sidecar = client.api.create_container.call_args.kwargs
    assert f"{EXPERIMENTAL_REVISION_RUNTIME_ENV}=true" in sidecar["environment"]
    assert f"{QUARANTINE_ID_ENV}={incarnation}" in sidecar["environment"]
    assert sidecar["labels"][QUARANTINE_LABEL] == "true"
    assert f"{volume['name']}:{QUARANTINE_DIRECTORY}:rw" in sidecar["host_config"]["binds"]
    assert "command" not in sidecar
    assert [call[0] for call in order.mock_calls] == [
        "remove_helper", "create_sidecar", "start_sidecar", "ready",
    ]


@pytest.mark.parametrize("failure", ["nonzero", "wait", "remove", "create"])
def test_provision_failure_never_starts_sidecar(service, failure):
    helper = service.docker_client.containers.create.return_value
    if failure == "nonzero":
        helper.wait.return_value = {"StatusCode": 1}
    elif failure == "create":
        service.docker_client.containers.create.side_effect = DockerException("unavailable")
    else:
        getattr(helper, failure).side_effect = DockerException("unavailable")
    with pytest.raises(HTTPException):
        _start(service)
    service.docker_client.api.create_container.assert_not_called()
    if failure in {"remove", "create"}:
        service._cleanup_managed_volumes.assert_not_called()
    else:
        service._cleanup_managed_volumes.assert_called_once()


def test_readiness_failure_removes_sidecar_and_volume(service):
    service._wait_for_egress_sidecar_ready.side_effect = RuntimeError("not ready")
    with pytest.raises(HTTPException):
        _start(service)
    service.docker_client.containers.get.return_value.remove.assert_called_once_with(force=True)
    service._cleanup_managed_volumes.assert_called_once()


def test_failed_sidecar_removal_preserves_journal_volume(service):
    service._wait_for_egress_sidecar_ready.side_effect = RuntimeError("not ready")
    service.docker_client.containers.get.return_value.remove.side_effect = DockerException("busy")
    with pytest.raises(HTTPException):
        _start(service)
    service._cleanup_managed_volumes.assert_not_called()


def test_uncertain_sidecar_creation_preserves_journal_volume(service):
    service.docker_client.api.create_container.side_effect = DockerException("connection lost")
    with pytest.raises(HTTPException):
        _start(service)
    service._cleanup_managed_volumes.assert_not_called()


@pytest.mark.parametrize("survivor", ["workload", "sidecar"])
def test_cleanup_retains_journal_while_namespace_participant_exists(service, survivor):
    service.docker_client.containers.list.side_effect = (
        [[MagicMock()]] if survivor == "workload" else [[], [MagicMock()]]
    )
    service._cleanup_egress_quarantine_volumes("sandbox-id")
    service.docker_client.volumes.list.assert_not_called()
    service._cleanup_managed_volumes.assert_not_called()


def test_cleanup_removes_journal_only_after_both_participants_gone(service):
    volume = SimpleNamespace(name="private-volume")
    service.docker_client.volumes.list.return_value = [volume]
    service._cleanup_egress_quarantine_volumes("sandbox-id")
    assert service.docker_client.containers.list.call_count == 2
    service._cleanup_managed_volumes.assert_called_once_with("sandbox-id", ["private-volume"])


@pytest.mark.parametrize("changes", [
    {"credential_proxy_enabled": False},
    {"egress_api_host_port": None},
    {"extra_env": {QUARANTINE_ID_ENV: "user-id"}},
    {"extra_env": {EXPERIMENTAL_REVISION_RUNTIME_ENV: "false"}},
])
def test_unsafe_sidecar_configuration_rejected_before_resources(service, changes):
    with pytest.raises(ValueError):
        _start(service, **changes)
    service.docker_client.volumes.create.assert_not_called()
    service.docker_client.api.create_container.assert_not_called()


def test_dns_only_rejected_and_no_policy_inactive(service):
    service.app_config.egress.mode = "dns"
    with pytest.raises(ValueError, match="dns.nft"):
        _start(service)
    assert not service._validate_egress_quarantine(
        has_network_policy=False, credential_proxy_enabled=False, extra_env=None,
    )


def test_default_gate_off_preserves_sidecar(service, monkeypatch):
    monkeypatch.delenv(EXPERIMENTAL_REVISION_RUNTIME_ENV)
    _start(service, credential_proxy_enabled=False)
    service.docker_client.containers.create.assert_not_called()
    service.docker_client.volumes.create.assert_not_called()
    sidecar = service.docker_client.api.create_container.call_args.kwargs
    assert QUARANTINE_LABEL not in sidecar["labels"]
    assert not any(QUARANTINE_ID_ENV in env for env in sidecar["environment"])


@pytest.mark.parametrize("key", [EXPERIMENTAL_REVISION_RUNTIME_ENV, QUARANTINE_ID_ENV])
def test_quarantine_identity_and_gate_not_user_settable(key):
    with pytest.raises(ValueError, match="not allowed"):
        split_egress_env({key: "true"})


def test_workload_cannot_request_private_quarantine_volume(service):
    volume = Volume(
        name="escape", mountPath="/quarantine",
        pvc=PVC(claimName=f"{QUARANTINE_VOLUME_PREFIX}other-sandbox"),
    )
    with pytest.raises(HTTPException) as exc:
        service._validate_pvc_volume(volume)
    assert exc.value.status_code == 400
    service.docker_client.api.inspect_volume.assert_not_called()


@pytest.mark.parametrize("operation", ["pause_sandbox", "resume_sandbox"])
def test_persisted_label_blocks_lifecycle_after_server_gate_off(service, monkeypatch, operation):
    monkeypatch.delenv(EXPERIMENTAL_REVISION_RUNTIME_ENV)
    container = MagicMock(attrs={"Config": {"Labels": {QUARANTINE_LABEL: "true"}}})
    service._get_container_by_sandbox_id = MagicMock(return_value=container)
    with pytest.raises(HTTPException) as exc:
        getattr(service, operation)("sandbox-id")
    assert exc.value.status_code == 409
    container.pause.assert_not_called()
    container.unpause.assert_not_called()


def test_snapshot_preflight_and_commit_reject_persisted_label():
    container = MagicMock(attrs={"Config": {"Labels": {QUARANTINE_LABEL: "true"}}})
    runtime = DockerSnapshotRuntime(SimpleNamespace(
        containers=SimpleNamespace(list=lambda **kwargs: [container]),
    ))
    with pytest.raises(HTTPException) as exc:
        runtime.preflight_create_snapshot("sandbox-id")
    assert exc.value.status_code == 409
    result = runtime.create_snapshot("snapshot-id", "sandbox-id")
    assert result.state.value == "Failed"
    container.commit.assert_not_called()


def test_non_docker_runtime_rejected_before_initialization(service):
    with patch("opensandbox_server.services.factory.KubernetesSandboxService") as factory:
        with pytest.raises(ValueError, match="Kubernetes and Fast Sandbox"):
            create_sandbox_service(service_type="kubernetes", config=service.app_config)
    factory.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("ready", [True, False])
async def test_workload_only_starts_after_ready_and_never_receives_private_mount(monkeypatch, ready):
    monkeypatch.setenv(EXPERIMENTAL_REVISION_RUNTIME_ENV, "true")
    client = MagicMock()
    client.containers.list.return_value = []
    client.api.create_host_config.side_effect = lambda **kwargs: kwargs
    client.api.create_container.side_effect = [{"Id": "sidecar-id"}, {"Id": "workload-id"}]
    sidecar = MagicMock(id="sidecar-id")
    workload = MagicMock(id="workload-id")
    client.containers.get.side_effect = [sidecar, workload]
    client.containers.create.return_value.wait.return_value = {"StatusCode": 0}
    config = AppConfig(
        runtime=RuntimeConfig(type="docker", execd_image="execd:test"),
        egress=EgressConfig(image="egress:test", mode="dns+nft"),
        ingress=IngressConfig(mode="direct"),
    )
    config.docker.network_mode = "bridge"
    with patch("opensandbox_server.services.docker.docker_service.docker") as docker:
        docker.from_env.return_value = client
        service = DockerSandboxService(config=config)
    request = CreateSandboxRequest(
        image=ImageSpec(uri="workload:test"), timeout=120,
        resourceLimits=ResourceLimits(root={}), entrypoint=["python"],
        networkPolicy=NetworkPolicy(defaultAction="deny", egress=[]),
        credentialProxy=CredentialProxyConfig(enabled=True),
    )
    order = MagicMock()
    with (
        patch.object(service, "_ensure_image_available"),
        patch.object(service, "_prepare_sandbox_runtime"),
        patch.object(service, "_prepare_creation_context", return_value=(
            "sandbox-id", datetime.now(timezone.utc), None,
        )),
        patch.object(service, "_wait_for_egress_sidecar_ready") as health,
        patch("opensandbox_server.services.docker.docker_service.allocate_port_bindings", return_value={
            "44772": ("0.0.0.0", 44772), "8080": ("0.0.0.0", 8080),
            "18080": ("0.0.0.0", 18080),
        }),
    ):
        order.attach_mock(health, "health")
        order.attach_mock(workload.start, "workload_start")
        if ready:
            await service.create_sandbox(request)
        else:
            health.side_effect = RuntimeError("quarantine not ready")
            with pytest.raises(HTTPException):
                await service.create_sandbox(request)
    if not ready:
        assert client.api.create_container.call_count == 1
        workload.start.assert_not_called()
        return
    assert [call[0] for call in order.mock_calls] == ["health", "workload_start"]
    workload_config = client.api.create_container.call_args_list[1].kwargs
    assert workload_config["labels"][QUARANTINE_LABEL] == "true"
    assert all(QUARANTINE_VOLUME_PREFIX not in bind
               for bind in workload_config["host_config"].get("binds", []))
    assert all(QUARANTINE_DIRECTORY not in bind
               for bind in workload_config["host_config"].get("binds", []))
    assert all(not entry.startswith((f"{QUARANTINE_ID_ENV}=", f"{EXPERIMENTAL_REVISION_RUNTIME_ENV}="))
               for entry in workload_config["environment"])
