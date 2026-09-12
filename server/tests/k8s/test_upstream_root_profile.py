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

from dataclasses import replace
from unittest.mock import MagicMock

import pytest
from pydantic import ValidationError

from opensandbox_server.api.schema import ImageSpec, NetworkPolicy
from opensandbox_server.config import AppConfig, EgressUpstreamProxyConfig
from opensandbox_server.services.constants import (
    OPENSANDBOX_EGRESS_DNS_UPSTREAM,
    OPENSANDBOX_EGRESS_PUBLIC_POLICY,
)
from opensandbox_server.services.helpers import split_egress_env
from opensandbox_server.services.k8s.agent_sandbox_provider import AgentSandboxProvider
from opensandbox_server.services.k8s.batchsandbox_provider import BatchSandboxProvider
from opensandbox_server.services.k8s.egress_helper import (
    apply_egress_to_spec,
    build_root_compatible_security_context,
    validate_upstream_proxy_pod,
)
from opensandbox_server.services.k8s.workload_provider import (
    EgressWorkloadSettings,
    UpstreamProxySettings,
)

UPSTREAM_EGRESS_IMAGE = "egress:test@sha256:" + "0123456789abcdef" * 4


def _config(provider: str = "batchsandbox", *, enabled: bool = True) -> AppConfig:
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
                    "dns_servers": ["192.0.2.53"],
                    "internal_targets": [
                        {
                            "host": "Registry.EXAMPLE.COM.",
                            "ips": ["192.0.2.10"],
                            "ports": [8443],
                        }
                    ],
                },
            },
        }
    )


def _settings(config: AppConfig) -> EgressWorkloadSettings:
    proxy = config.egress.upstream_proxy
    assert proxy.enabled and proxy.url and proxy.ca_bundle
    return EgressWorkloadSettings(
        network_policy=NetworkPolicy(defaultAction="deny"),
        image=config.egress.image or "",
        mode=config.egress.mode,
        auth_token="local-api-token",
        credential_proxy_enabled=False,
        env={},
        disable_ipv6=config.egress.disable_ipv6,
        resource_requests=None,
        resource_limits=None,
        upstream_proxy=UpstreamProxySettings(
            url=proxy.url,
            ca_secret_name=proxy.ca_bundle.secret_name,
            ca_key=proxy.ca_bundle.key,
            identity_secret_name="egress-identity-test-id",
            identity_key=proxy.identity.key,
        ),
        public_policy=proxy.public_policy_json(),
    )


def _raw_pod(settings: EgressWorkloadSettings) -> dict:
    pod = {
        "containers": [{"name": "sandbox", "env": [], "volumeMounts": []}],
        "volumes": [],
    }
    apply_egress_to_spec(
        pod["containers"], settings, sandbox_id="test-id", pod_spec=pod
    )
    return pod


def _rendered_pod(provider_cls, provider_name: str, pod_key: str) -> dict:
    config = _config(provider_name)
    settings = _settings(config)
    client = MagicMock()
    client.create_custom_object.return_value = {
        "metadata": {"name": "test-id", "uid": "uid"}
    }
    provider = provider_cls(client, config)
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
        egress_settings=settings,
    )
    pod = client.create_custom_object.call_args.kwargs["body"]["spec"][pod_key][
        "spec"
    ]
    validate_upstream_proxy_pod(
        pod,
        settings,
        expected_execd_init=next(
            container
            for container in pod["initContainers"]
            if container["name"] == "execd-installer"
        ),
    )
    return pod


@pytest.mark.parametrize(
    "provider_cls,provider_name,pod_key",
    [
        (BatchSandboxProvider, "batchsandbox", "template"),
        (AgentSandboxProvider, "agent-sandbox", "podTemplate"),
    ],
)
def test_both_providers_render_root_compatible_profile_and_native_sidecar(
    provider_cls, provider_name, pod_key
):
    config = _config(provider_name)
    settings = _settings(config)
    pod = _rendered_pod(provider_cls, provider_name, pod_key)

    assert pod["automountServiceAccountToken"] is False
    assert pod["securityContext"]["sysctls"] == [
        {"name": "net.ipv4.ip_unprivileged_port_start", "value": "1024"}
    ]
    assert len(pod["containers"]) == 1
    app_security_context = pod["containers"][0]["securityContext"]
    assert app_security_context == build_root_compatible_security_context()
    assert "NET_BIND_SERVICE" not in app_security_context["capabilities"]["add"]
    assert "readOnlyRootFilesystem" not in pod["containers"][0]["securityContext"]

    assert [container["name"] for container in pod["initContainers"]] == [
        "egress",
        "execd-installer",
    ]
    sidecar = pod["initContainers"][0]
    assert sidecar["restartPolicy"] == "Always"
    assert sidecar["readinessProbe"]["httpGet"]["path"] == "/healthz"
    assert sidecar["startupProbe"] == {
        "exec": {
            "command": [
                "python3",
                "/opt/opensandbox-egress/public_egress_manifest.py",
                "--check-ready",
            ]
        },
        "timeoutSeconds": 10,
        "periodSeconds": 2,
        "failureThreshold": 30,
    }
    assert sidecar["securityContext"] == {
        "capabilities": {"add": ["NET_ADMIN", "NET_BIND_SERVICE"]}
    }

    env = {entry["name"]: entry["value"] for entry in sidecar["env"]}
    assert env[OPENSANDBOX_EGRESS_PUBLIC_POLICY] == settings.public_policy
    assert env[OPENSANDBOX_EGRESS_DNS_UPSTREAM] == "192.0.2.53"
    assert '"host":"registry.example.com"' in env[OPENSANDBOX_EGRESS_PUBLIC_POLICY]

    # The strict guard blocks IPv6 before this file installer can start.
    # Nothing touching the business-writable runtime volume is privileged.
    installer = pod["initContainers"][1]
    assert installer["securityContext"] == build_root_compatible_security_context()
    assert "disable_ipv6" not in str(installer.get("command", []))
    assert "disable_ipv6" not in str(installer.get("args", []))


def test_default_off_keeps_regular_egress_container_and_no_root_profile():
    settings = EgressWorkloadSettings(
        network_policy=NetworkPolicy(defaultAction="deny"),
        image="egress:test",
        mode="dns",
        auth_token=None,
        credential_proxy_enabled=False,
        env={},
        disable_ipv6=True,
        resource_requests=None,
        resource_limits=None,
    )
    pod = {"containers": [{"name": "sandbox"}], "volumes": []}
    apply_egress_to_spec(pod["containers"], settings, pod_spec=pod)

    assert [container["name"] for container in pod["containers"]] == [
        "sandbox",
        "egress",
    ]
    assert "initContainers" not in pod
    assert pod["containers"][0].get("securityContext") is None
    assert "runAsUser" not in pod["containers"][0].get("securityContext", {})
    assert OPENSANDBOX_EGRESS_PUBLIC_POLICY not in {
        entry["name"] for entry in pod["containers"][1]["env"]
    }


@pytest.mark.parametrize(
    "image",
    [
        "egress:test",
        "egress:test@sha256:" + "a" * 63,
        "egress:test@sha256:" + "a" * 65,
        "egress:test@sha256:" + "A" * 64,
        "egress:test@sha512:" + "a" * 64,
    ],
)
def test_enabled_upstream_requires_lowercase_sha256_image_digest(image):
    raw = _config().model_dump()
    raw["egress"]["image"] = image

    with pytest.raises(ValidationError, match="digest"):
        AppConfig.model_validate(raw)


def test_enabled_upstream_accepts_tagged_sha256_image_digest():
    assert _config().egress.image == UPSTREAM_EGRESS_IMAGE


def test_disabled_upstream_keeps_mutable_image_tag_compatibility():
    raw = _config(enabled=False).model_dump()
    raw["egress"]["image"] = "egress:test"

    config = AppConfig.model_validate(raw)
    assert config.egress.image == "egress:test"


def test_helper_rejects_unpinned_upstream_image_even_with_manual_settings():
    settings = replace(_settings(_config()), image="egress:test")
    pod = {"containers": [{"name": "sandbox"}], "volumes": []}

    with pytest.raises(ValueError, match="digest"):
        apply_egress_to_spec(pod["containers"], settings, pod_spec=pod)


@pytest.mark.parametrize(
    "field,value",
    [
        ("runAsUser", 1000),
        ("runAsNonRoot", True),
        ("allowPrivilegeEscalation", True),
        ("privileged", True),
        ("seccompProfile", {"type": "Unconfined"}),
        ("capabilities", {"drop": ["ALL"], "add": ["NET_RAW"]}),
    ],
)
def test_final_manifest_rejects_root_profile_mutation(field, value):
    settings = _settings(_config())
    pod = _raw_pod(settings)
    pod["containers"][0]["securityContext"][field] = value

    with pytest.raises(ValueError, match="sandbox securityContext"):
        validate_upstream_proxy_pod(pod, settings)


def test_final_manifest_rejects_sidecar_probe_security_and_init_mutations():
    settings = _settings(_config())

    pod = _raw_pod(settings)
    pod["initContainers"][0]["securityContext"]["capabilities"]["add"].append(
        "NET_RAW"
    )
    with pytest.raises(ValueError, match="sidecar securityContext"):
        validate_upstream_proxy_pod(pod, settings)

    pod = _raw_pod(settings)
    pod["initContainers"][0]["startupProbe"]["exec"]["command"][-1] = "--not-ready"
    with pytest.raises(ValueError, match="sidecar"):
        validate_upstream_proxy_pod(pod, settings)

    pod = _raw_pod(settings)
    pod["initContainers"][0]["restartPolicy"] = "Never"
    with pytest.raises(ValueError, match="sidecar"):
        validate_upstream_proxy_pod(pod, settings)

    pod = _raw_pod(settings)
    pod["initContainers"][0]["env"] = [
        entry
        if entry["name"] != "OPENSANDBOX_EGRESS_SANDBOX_ID"
        else {"name": entry["name"], "value": "other-id"}
        for entry in pod["initContainers"][0]["env"]
    ]
    # This raw fixture has no OPENSANDBOX_ID in the app env, so pass the
    # expected value explicitly as providers do after rendering.
    with pytest.raises(ValueError, match="sandbox identity|sidecar environment"):
        validate_upstream_proxy_pod(pod, settings, expected_sandbox_id="test-id")

    pod = _raw_pod(settings)
    identity_volume = next(
        volume for volume in pod["volumes"] if volume["name"] == "egress-identity"
    )
    identity_volume["secret"]["optional"] = False
    with pytest.raises(ValueError, match="private volumes"):
        validate_upstream_proxy_pod(pod, settings)

    pod = _raw_pod(settings)
    pod["initContainers"].append({"name": "untrusted-init", "image": "evil:test"})
    with pytest.raises(ValueError, match="initContainers"):
        validate_upstream_proxy_pod(pod, settings)


@pytest.mark.parametrize(
    "mutation,pattern",
    [
        (lambda pod: pod.update({"automountServiceAccountToken": True}), "automount"),
        (
            lambda pod: pod.update({"hostNetwork": True}),
            "isolated Pod network",
        ),
        (lambda pod: pod.update({"hostPID": True}), "isolated Pod network"),
        (lambda pod: pod.update({"hostIPC": True}), "isolated Pod network"),
        (
            lambda pod: pod.update({"shareProcessNamespace": True}),
            "isolated Pod network",
        ),
        (
            lambda pod: pod["securityContext"].update(
                {
                    "sysctls": [
                        {"name": "net.ipv4.ip_unprivileged_port_start", "value": "1025"}
                    ]
                }
            ),
            "Pod sysctls",
        ),
        (
            lambda pod: pod["securityContext"].update(
                {
                    "sysctls": [
                        {"name": "net.ipv4.ip_unprivileged_port_start", "value": "1024"},
                        {"name": "net.ipv4.ip_local_port_range", "value": "32768 60999"},
                    ]
                }
            ),
            "Pod sysctls",
        ),
        (
            lambda pod: pod["volumes"].append(
                {"name": "host", "hostPath": {"path": "/"}}
            ),
            "hostPath",
        ),
        (
            lambda pod: pod["volumes"].append(
                {
                    "name": "token",
                    "projected": {"sources": [{"serviceAccountToken": {}}]},
                }
            ),
            "serviceAccountToken",
        ),
        (
            lambda pod: pod["containers"][0]["volumeMounts"].append(
                {"name": "tmp", "mountPath": "/sys/fs/cgroup"}
            ),
            "writable /proc, /sys",
        ),
        (
            lambda pod: pod["containers"][0].update({"securityContext": {"procMount": "Unmasked"}}),
            "unmasked proc",
        ),
        (
            lambda pod: pod["securityContext"].update(
                {"appArmorProfile": {"type": "Unconfined"}}
            ),
            "RuntimeDefault AppArmor",
        ),
    ],
)
def test_final_manifest_rejects_pod_escape_hatches(mutation, pattern):
    settings = _settings(_config())
    pod = _raw_pod(settings)
    mutation(pod)

    with pytest.raises(ValueError, match=pattern):
        validate_upstream_proxy_pod(pod, settings)


@pytest.mark.parametrize(
    "mount_path",
    ["//proc", "//proc/self", "//sys", "//sys/fs/cgroup", "///sys/fs/cgroup",
     "/tmp/..//proc", "//tmp/../sys/fs/cgroup"],
)
def test_final_manifest_rejects_normalized_dangerous_mounts(mount_path):
    settings = _settings(_config())
    pod = _raw_pod(settings)
    pod["volumes"].append({"name": "unsafe", "emptyDir": {}})
    pod["containers"][0]["volumeMounts"].append(
        {"name": "unsafe", "mountPath": mount_path}
    )
    with pytest.raises(ValueError, match="writable /proc, /sys"):
        validate_upstream_proxy_pod(pod, settings)


@pytest.mark.parametrize("token", [None, "", " "])
def test_strict_profile_requires_generated_control_token(token):
    settings = replace(_settings(_config()), auth_token=token)
    with pytest.raises(ValueError, match="control API token"):
        _raw_pod(settings)


def test_strict_profile_keeps_other_pod_security_context_fields_compatible():
    settings = _settings(_config())
    pod = _raw_pod(settings)
    pod["securityContext"]["fsGroup"] = 0

    validate_upstream_proxy_pod(pod, settings)


@pytest.mark.parametrize(
    "raw",
    [
        {"enabled": True, "url": "https://gateway.example", "ca_bundle": {"secret_name": "ca"}},
        {
            "enabled": True,
            "url": "https://gateway.example",
            "ca_bundle": {"secret_name": "ca"},
            "dns_servers": ["127.0.0.1"],
        },
        {
            "enabled": True,
            "url": "https://gateway.example",
            "ca_bundle": {"secret_name": "ca"},
            "dns_servers": ["169.254.169.254"],
        },
        {
            "enabled": True,
            "url": "https://gateway.example",
            "ca_bundle": {"secret_name": "ca"},
            "dns_servers": ["100.100.100.200"],
        },
        {
            "enabled": True,
            "url": "https://gateway.example",
            "ca_bundle": {"secret_name": "ca"},
            "dns_servers": ["168.63.129.16"],
        },
        {
            "enabled": True,
            "url": "https://gateway.example",
            "ca_bundle": {"secret_name": "ca"},
            "dns_servers": ["10.0.0.53/32"],
        },
        {
            "enabled": True,
            "url": "https://gateway.example",
            "ca_bundle": {"secret_name": "ca"},
            "dns_servers": ["10.0.0.53", "10.0.0.53"],
        },
        {
            "enabled": True,
            "url": "https://gateway.example",
            "ca_bundle": {"secret_name": "ca"},
            "dns_servers": ["10.0.0.53"],
            "internal_targets": [
                {"host": "*.example.com", "ips": ["10.0.0.10"], "ports": [8443]}
            ],
        },
        {
            "enabled": True,
            "url": "https://gateway.example",
            "ca_bundle": {"secret_name": "ca"},
            "dns_servers": ["10.0.0.53"],
            "internal_targets": [
                {"host": "10.0.0.10", "ips": ["10.0.0.10"], "ports": [8443]}
            ],
        },
        {
            "enabled": True,
            "url": "https://gateway.example",
            "ca_bundle": {"secret_name": "ca"},
            "dns_servers": ["10.0.0.53"],
            "internal_targets": [
                {"host": "registry.example.com", "ips": ["169.254.169.254"], "ports": [8443]}
            ],
        },
        {
            "enabled": True,
            "url": "https://gateway.example",
            "ca_bundle": {"secret_name": "ca"},
            "dns_servers": ["10.0.0.53"],
            "internal_targets": [
                {"host": "registry.example.com", "ips": ["127.0.0.1"], "ports": [8443]}
            ],
        },
        {
            "enabled": True,
            "url": "https://gateway.example",
            "ca_bundle": {"secret_name": "ca"},
            "dns_servers": ["10.0.0.53"],
            "internal_targets": [
                {"host": "registry.example.com", "ips": ["169.254.1.1"], "ports": [8443]}
            ],
        },
        {
            "enabled": True,
            "url": "https://gateway.example",
            "ca_bundle": {"secret_name": "ca"},
            "dns_servers": ["10.0.0.53"],
            "internal_targets": [
                {"host": "registry.example.com", "ips": ["10.0.0.10"], "ports": [53]}
            ],
        },
        {
            "enabled": True,
            "url": "https://gateway.example",
            "ca_bundle": {"secret_name": "ca"},
            "dns_servers": ["10.0.0.53"],
            "internal_targets": [
                {"host": "registry.example.com", "ips": ["10.0.0.10"], "ports": ["8443"]}
            ],
        },
        {
            "enabled": True,
            "url": "https://gateway.example:53",
            "ca_bundle": {"secret_name": "ca"},
            "dns_servers": ["10.0.0.53"],
        },
        {
            "enabled": True,
            "url": "https://gateway.example:353",
            "ca_bundle": {"secret_name": "ca"},
            "dns_servers": ["10.0.0.53"],
        },
        {
            "enabled": True,
            "url": "https://gateway.example:380",
            "ca_bundle": {"secret_name": "ca"},
            "dns_servers": ["10.0.0.53"],
        },
        {
            "enabled": True,
            "url": "https://gateway.example:381",
            "ca_bundle": {"secret_name": "ca"},
            "dns_servers": ["10.0.0.53"],
        },
        {
            "enabled": True,
            "url": "https://gateway.example:15353",
            "ca_bundle": {"secret_name": "ca"},
            "dns_servers": ["10.0.0.53"],
        },
        {
            "enabled": True,
            "url": "https://gateway.example:18080",
            "ca_bundle": {"secret_name": "ca"},
            "dns_servers": ["10.0.0.53"],
        },
        {
            "enabled": True,
            "url": "https://gateway.example:18081",
            "ca_bundle": {"secret_name": "ca"},
            "dns_servers": ["10.0.0.53"],
        },
        {
            "enabled": True,
            "url": "https://Gateway.Example",
            "ca_bundle": {"secret_name": "ca"},
            "dns_servers": ["10.0.0.53"],
            "internal_targets": [
                {"host": "gateway.example", "ips": ["10.0.0.10"], "ports": [8443]}
            ],
        },
    ],
)
def test_invalid_admin_public_policy_is_rejected(raw):
    with pytest.raises(ValidationError):
        EgressUpstreamProxyConfig.model_validate(raw)


def test_disabled_legacy_gateway_url_keeps_reserved_port_compatibility():
    proxy = EgressUpstreamProxyConfig.model_validate(
        {"enabled": False, "url": "https://gateway.example:18080"}
    )
    assert proxy.url == "https://gateway.example:18080"


def test_admin_policy_is_canonical_and_normalizes_hosts():
    config = _config()
    proxy = config.egress.upstream_proxy
    assert proxy.dns_servers == ["192.0.2.53"]
    assert proxy.internal_targets[0].host == "registry.example.com"
    assert proxy.public_policy_json() == (
        '{"version":1,"dns_servers":["192.0.2.53"],'
        '"internal_targets":[{"host":"registry.example.com",'
        '"ips":["192.0.2.10"],"ports":[8443]}]}'
    )


def test_admin_policy_bounds_match_addon_contract():
    base = {
        "enabled": True,
        "url": "https://gateway.example",
        "ca_bundle": {"secret_name": "ca"},
        "dns_servers": ["10.0.0.53"],
    }

    too_many_dns = {**base, "dns_servers": [f"10.0.0.{index}" for index in range(1, 10)]}
    with pytest.raises(ValidationError):
        EgressUpstreamProxyConfig.model_validate(too_many_dns)

    too_many_targets = {
        **base,
        "internal_targets": [
            {"host": f"target-{index}.example.com", "ips": ["10.0.0.10"], "ports": [8443]}
            for index in range(129)
        ],
    }
    with pytest.raises(ValidationError):
        EgressUpstreamProxyConfig.model_validate(too_many_targets)

    too_many_ips = {
        **base,
        "internal_targets": [
            {
                "host": "registry.example.com",
                "ips": [f"10.0.1.{index}" for index in range(1, 34)],
                "ports": [8443],
            }
        ],
    }
    with pytest.raises(ValidationError):
        EgressUpstreamProxyConfig.model_validate(too_many_ips)

    too_many_ports = {
        **base,
        "internal_targets": [
            {
                "host": "registry.example.com",
                "ips": ["10.0.0.10"],
                "ports": list(range(1, 34)),
            }
        ],
    }
    with pytest.raises(ValidationError):
        EgressUpstreamProxyConfig.model_validate(too_many_ports)

    oversized = {
        **base,
        "internal_targets": [
            {
                "host": f"target-{index}.example.com",
                "ips": [f"10.1.0.{ip_index}" for ip_index in range(1, 33)],
                "ports": list(range(1, 33)),
            }
            for index in range(128)
        ],
    }
    with pytest.raises(ValidationError, match="32 KiB"):
        EgressUpstreamProxyConfig.model_validate(oversized)


@pytest.mark.parametrize("reserved_port", [53, 353, 380, 381, 15353, 18080, 18081])
def test_internal_target_cannot_collide_with_egress_control_ports(reserved_port):
    with pytest.raises(ValidationError, match="reserved egress control ports"):
        EgressUpstreamProxyConfig.model_validate(
            {
                "enabled": True,
                "url": "https://gateway.example",
                "ca_bundle": {"secret_name": "ca"},
                "dns_servers": ["10.0.0.53"],
                "internal_targets": [
                    {
                        "host": "registry.example.com",
                        "ips": ["10.0.0.10"],
                        "ports": [reserved_port],
                    }
                ],
            }
        )


@pytest.mark.parametrize("reserved_port", [53, 353, 380, 381, 15353, 18080, 18081])
def test_helper_policy_rejects_all_reserved_internal_ports(reserved_port):
    settings = replace(
        _settings(_config()),
        public_policy=(
            '{"version":1,"dns_servers":["10.0.0.53"],'
            '"internal_targets":[{"host":"registry.example.com",'
            '"ips":["10.0.0.10"],"ports":['
            + str(reserved_port)
            + ']}]}'
        ),
    )
    pod = {"containers": [{"name": "sandbox"}], "volumes": []}

    with pytest.raises(ValueError, match="internal target"):
        apply_egress_to_spec(pod["containers"], settings, pod_spec=pod)


@pytest.mark.parametrize("name", [OPENSANDBOX_EGRESS_DNS_UPSTREAM, OPENSANDBOX_EGRESS_PUBLIC_POLICY])
def test_request_cannot_set_server_owned_public_policy_environment(name):
    with pytest.raises(ValueError, match="not allowed"):
        split_egress_env({name: "attacker-controlled"})
