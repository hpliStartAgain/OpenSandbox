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

from copy import deepcopy
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from pydantic import ValidationError

from opensandbox_server.api.schema import CreateSandboxRequest, ImageSpec, NetworkPolicy
from opensandbox_server.config import AppConfig, EgressUpstreamProxyConfig
from opensandbox_server.services.helpers import split_egress_env
from opensandbox_server.services.k8s.agent_sandbox_provider import AgentSandboxProvider
from opensandbox_server.services.k8s.batchsandbox_provider import BatchSandboxProvider
from opensandbox_server.services.k8s.create_helpers import _build_create_workload_context
from opensandbox_server.services.k8s.egress_helper import (
    apply_egress_to_spec,
    validate_upstream_proxy_pod,
)
from opensandbox_server.services.k8s.workload_provider import (
    EgressWorkloadSettings,
    UpstreamProxySettings,
)

UPSTREAM_EGRESS_IMAGE = "egress:test@sha256:" + "0123456789abcdef" * 4


def _config(provider="batchsandbox", enabled=True):
    return AppConfig.model_validate(
        {
            "runtime": {"type": "kubernetes", "execd_image": "execd:test"},
            "kubernetes": {"workload_provider": provider},
            "egress": {
                "image": UPSTREAM_EGRESS_IMAGE,
                "mode": "dns+nft",
                "upstream_proxy": {
                    "enabled": enabled,
                    "url": "https://gateway.example",
                    "ca_bundle": {"secret_name": "gateway-ca"},
                    "dns_servers": ["10.0.0.53"],
                },
            },
        }
    )


def _settings():
    return EgressWorkloadSettings(
        network_policy=NetworkPolicy(defaultAction="deny"),
        image=UPSTREAM_EGRESS_IMAGE,
        mode="dns+nft",
        auth_token="local-api-token",
        credential_proxy_enabled=False,
        env={},
        disable_ipv6=True,
        resource_requests=None,
        resource_limits=None,
        upstream_proxy=UpstreamProxySettings(
            url="https://gateway.example:443",
            ca_secret_name="gateway-ca",
            ca_key="ca.crt",
            identity_secret_name="egress-identity-test-id",
            identity_key="identity.jwt",
        ),
        public_policy='{"version":1,"dns_servers":["10.0.0.53"],"internal_targets":[]}',
    )


def _pod():
    pod = {"containers": [{"name": "sandbox", "env": [], "volumeMounts": []}], "volumes": []}
    apply_egress_to_spec(pod["containers"], _settings(), "test-id", pod_spec=pod)
    return pod


@pytest.mark.parametrize(
    "url",
    [
        "http://gateway.example",
        "https://127.0.0.1",
        "https://127.1",
        "https://[::1]",
        "https://user:password@gateway.example",
        "https://gateway.example/path",
        "https://gateway.example?",
        "https://gateway.example#",
        "https://gateway.example:0",
        "https://gateway.example:65536",
        "https://gateway.example:",
        "https://gateway..example",
        "https://gateway.example\n",
        "https://-gateway.example",
        "https://gateway_example",
    ],
)
def test_rejects_unsafe_gateway(url):
    with pytest.raises(ValidationError):
        EgressUpstreamProxyConfig(url=url)


def test_disabled_config_is_backward_compatible_and_enabled_requires_references():
    assert EgressUpstreamProxyConfig().enabled is False
    with pytest.raises(ValidationError, match="requires url and ca_bundle"):
        EgressUpstreamProxyConfig(enabled=True)
    assert _config().egress.upstream_proxy.url == "https://gateway.example:443"


@pytest.mark.parametrize("name", ["ca..secret", "ca.-secret", "ca-.secret", "CA", "ca/secret"])
def test_rejects_invalid_kubernetes_ca_secret_name(name):
    with pytest.raises(ValidationError):
        EgressUpstreamProxyConfig(ca_bundle={"secret_name": name})


@pytest.mark.parametrize(
    "change",
    [
        {"runtime": {"type": "docker", "execd_image": "execd:test"}, "kubernetes": None},
        {"secure_runtime": {"type": "gvisor", "k8s_runtime_class": "runsc"}},
        {"secure_runtime": {"type": "kata", "k8s_runtime_class": "kata"}},
        {"kubernetes": {"workload_provider": "fast-sandbox"}},
    ],
)
def test_unsupported_config_fails_on_startup(change):
    raw = _config().model_dump()
    raw.update(change)
    with pytest.raises(ValidationError, match="upstream_proxy"):
        AppConfig.model_validate(raw)


@pytest.mark.parametrize("key,value", [("mode", "dns"), ("disable_ipv6", False), ("image", None)])
def test_enabled_requires_network_enforcement(key, value):
    raw = _config().model_dump()
    raw["egress"][key] = value
    with pytest.raises(ValidationError, match="upstream_proxy"):
        AppConfig.model_validate(raw)


@pytest.mark.parametrize(
    "name",
    [
        "OPENSANDBOX_EGRESS_UPSTREAM_PROXY",
        "OPENSANDBOX_EGRESS_UPSTREAM_PROXY_AUTH",
        "OPENSANDBOX_EGRESS_UPSTREAM_PROXY_IDENTITY_FILE",
        "OPENSANDBOX_EGRESS_UPSTREAM_PROXY_CA_FILE",
        "OPENSANDBOX_EGRESS_MITMPROXY_SCRIPT",
        "OPENSANDBOX_EGRESS_MITMPROXY_UPSTREAM_TRUST_DIR",
    ],
)
def test_request_cannot_set_admin_environment(name):
    with pytest.raises(ValueError, match="not allowed"):
        split_egress_env({name: "attacker-controlled"})


def _context(config, **request_fields):
    request = CreateSandboxRequest.model_validate(
        {
            "image": {"uri": "python:test"},
            "entrypoint": ["sleep", "600"],
            "timeout": 600,
            "resourceLimits": {"cpu": "1", "memory": "1Gi"},
            **request_fields,
        }
    )
    return _build_create_workload_context(
        config,
        request,
        "test-id",
        datetime.now(timezone.utc),
        lambda: "api-token",
        lambda: "secure-token",
    )


def test_context_resolves_identity_from_server_sandbox_id():
    context = _context(_config(), networkPolicy={"defaultAction": "deny"}, env={"APP": "value"})
    assert context.egress_settings.upstream_proxy.identity_secret_name == "egress-identity-test-id"
    assert context.sandbox_env == {"APP": "value"}
    assert "gateway.example" not in str(context.sandbox_env)


def test_omitting_policy_cannot_bypass_admin_proxy():
    with pytest.raises(ValueError, match="networkPolicy is required"):
        _context(_config())
    assert _context(_config(enabled=False)).egress_settings is None


@pytest.mark.parametrize(
    "name",
    [
        "OPENSANDBOX_EGRESS_MITMPROXY_SSL_INSECURE",
        "OPENSANDBOX_EGRESS_MITMPROXY_TRANSPARENT",
        "OPENSANDBOX_EGRESS_POLICY_FILE",
        "OPENSANDBOX_EGRESS_MITMPROXY_EXTRA_PORTS",
    ],
)
def test_request_cannot_override_transport_options(name):
    with pytest.raises(ValueError, match="cannot override"):
        _context(_config(), networkPolicy={"defaultAction": "deny"}, env={name: "false"})


def test_private_mounts_support_rotation_without_blocking_unissued_identity():
    pod = _pod()
    validate_upstream_proxy_pod(pod, _settings())
    main = pod["containers"][0]
    egress = pod["initContainers"][0]
    assert main["volumeMounts"] == []
    private = {v["name"]: v for v in pod["volumes"]}
    assert private["egress-identity"]["secret"]["optional"] is True
    assert not private["egress-gateway-ca"]["secret"].get("optional", False)
    assert all(
        m["readOnly"] and "subPath" not in m for m in egress["volumeMounts"] if m["name"] in private
    )
    env = {e["name"]: e["value"] for e in egress["env"]}
    assert env["OPENSANDBOX_EGRESS_MITMPROXY_TRANSPARENT"] == "true"
    assert "OPENSANDBOX_EGRESS_UPSTREAM_PROXY_AUTH" not in env
    assert env["OPENSANDBOX_EGRESS_SANDBOX_ID"] == "test-id"


@pytest.mark.parametrize("container_key", ["containers", "initContainers", "ephemeralContainers"])
@pytest.mark.parametrize(
    "source", ["direct", "alias", "projected", "csi", "flexVolume", "azureFile", "env", "envFrom"]
)
def test_final_manifest_rejects_identity_exposure(container_key, source):
    pod = _pod()
    consumer = {
        "name": "untrusted",
        "volumeMounts": [{"name": "egress-identity", "mountPath": "/leak"}],
    }
    if source in ("alias", "projected", "csi", "flexVolume", "azureFile"):
        volume = {"name": "alias"}
        if source == "alias":
            volume["secret"] = {"secretName": "egress-identity-test-id"}
        elif source == "projected":
            volume["projected"] = {"sources": [{"secret": {"name": "egress-identity-test-id"}}]}
        elif source == "csi":
            volume["csi"] = {
                "driver": "fixture.example",
                "nodePublishSecretRef": {"name": "egress-identity-test-id"},
            }
        elif source == "flexVolume":
            volume["flexVolume"] = {
                "driver": "fixture/example",
                "secretRef": {"name": "egress-identity-test-id"},
            }
        else:
            volume["azureFile"] = {"secretName": "egress-identity-test-id", "shareName": "fixture"}
        pod["volumes"].append(volume)
        consumer["volumeMounts"][0]["name"] = "alias"
    if source in ("env", "envFrom"):
        consumer["volumeMounts"] = []
        if source == "env":
            consumer["env"] = [
                {
                    "name": "LEAK",
                    "valueFrom": {
                        "secretKeyRef": {"name": "egress-identity-test-id", "key": "identity.jwt"}
                    },
                }
            ]
        else:
            consumer["envFrom"] = [{"secretRef": {"name": "egress-identity-test-id"}}]
    pod.setdefault(container_key, []).append(consumer)
    with pytest.raises(
        ValueError,
            match="only be mounted|cannot be exposed|exactly one sandbox|initContainers|generated init|ephemeral",
    ):
        validate_upstream_proxy_pod(pod, _settings())


@pytest.mark.parametrize("runtime", ["runsc", "kata", "unknown-runtime"])
def test_final_runtime_class_is_checked_after_merge(runtime):
    pod = _pod()
    pod["runtimeClassName"] = runtime
    with pytest.raises(ValueError, match="default Linux runc"):
        validate_upstream_proxy_pod(pod, _settings())


def test_final_manifest_rejects_replaced_secret_and_duplicate_env():
    pod = _pod()
    pod["volumes"][0]["secret"]["secretName"] = "wrong-ca"
    with pytest.raises(ValueError, match="private volumes were changed"):
        validate_upstream_proxy_pod(pod, _settings())
    pod = _pod()
    pod["initContainers"][0]["env"].append(
        {"name": "OPENSANDBOX_EGRESS_UPSTREAM_PROXY", "value": "https://evil.example"}
    )
    with pytest.raises(ValueError, match="environment was changed"):
        validate_upstream_proxy_pod(pod, _settings())


@pytest.mark.parametrize(
    "provider_cls,provider_name,pod_key",
    [
        (BatchSandboxProvider, "batchsandbox", "template"),
        (AgentSandboxProvider, "agent-sandbox", "podTemplate"),
    ],
)
def test_both_provider_create_entrypoints_render_private_mounts(
    provider_cls, provider_name, pod_key
):
    client = MagicMock()
    client.create_custom_object.return_value = {"metadata": {"name": "test-id", "uid": "uid"}}
    provider = provider_cls(client, _config(provider_name))
    provider.create_workload(
        sandbox_id="test-id",
        namespace="test-ns",
        image_spec=ImageSpec(uri="python:test"),
        entrypoint=["sleep", "600"],
        env={"APP": "value"},
        resource_limits={"cpu": "1", "memory": "1Gi"},
        labels={},
        expires_at=None,
        execd_image="execd:test",
        egress_settings=_settings(),
    )
    pod = client.create_custom_object.call_args.kwargs["body"]["spec"][pod_key]["spec"]
    validate_upstream_proxy_pod(
        pod,
        _settings(),
        expected_execd_init=next(
            container
            for container in pod["initContainers"]
            if container["name"] == "execd-installer"
        ),
    )
    assert {m["name"] for m in pod["containers"][0]["volumeMounts"]}.isdisjoint(
        {"egress-identity", "egress-gateway-ca"}
    )
    assert len(pod["volumes"]) == 3


def test_legacy_container_only_call_unchanged_and_proxy_requires_pod():
    settings = _settings()
    with pytest.raises(ValueError, match="owning pod_spec"):
        apply_egress_to_spec([], settings)
    from dataclasses import replace

    legacy = replace(settings, upstream_proxy=None)
    containers = [{"name": "sandbox"}]
    original = deepcopy(containers)
    apply_egress_to_spec(containers, legacy)
    assert containers[0] == original[0]
    assert len(containers[1]["volumeMounts"]) == 1
