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

"""
Egress sidecar helpers for Kubernetes pod specs.

Public entry points: ``prep_execd_init_for_egress``, ``build_security_context_for_sandbox_container``,
``apply_egress_to_spec``. SecurityContext dict ↔ V1 conversion lives in ``security_context``.
"""

import json
import ipaddress
import posixpath
import re
import shlex
from typing import Any, Dict, List, Optional

from opensandbox_server.services.constants import (
    EGRESS_MODE_ENV,
    EGRESS_RULES_ENV,
    OTEL_EXPORTER_OTLP_ENDPOINT,
    OPEN_SANDBOX_EGRESS_AUTH_HEADER,
    OPENSANDBOX_EGRESS_DNS_UPSTREAM,
    OPENSANDBOX_EGRESS_MITMPROXY_TRANSPARENT,
    OPENSANDBOX_EGRESS_PUBLIC_POLICY,
    OPENSANDBOX_EGRESS_SANDBOX_ID,
    OPENSANDBOX_EGRESS_TOKEN,
    OPENSANDBOX_RUNTIME_MOUNT_PATH,
    OPENSANDBOX_RUNTIME_VOLUME_NAME,
)
from opensandbox_server.services.k8s.workload_provider import EgressWorkloadSettings

_IPV6_DISABLE_PATH = "/proc/sys/net/ipv6/conf/all/disable_ipv6"

# The administrator-managed upstream proxy profile deliberately keeps the
# business image's historical UID-0 contract.  Privilege is bounded by the
# container capability set and by the private Pod namespaces instead of by a
# process UID (the egress addon itself runs as a different UID).
_ROOT_COMPATIBLE_ALLOWED_CAPABILITIES = (
    "CHOWN",
    "DAC_OVERRIDE",
    "FOWNER",
    "FSETID",
    "KILL",
    "SETUID",
    "SETGID",
    "SYS_CHROOT",
)
_EGRESS_SIDECAR_SECURITY_CONTEXT = {
    "capabilities": {"add": ["NET_ADMIN"]},
}
_DANGEROUS_MOUNT_ROOTS = ("/proc", "/sys")
_EGRESS_IMAGE_DIGEST_RE = re.compile(r"^.+@sha256:[0-9a-f]{64}$")
_PUBLIC_POLICY_KEYS = {"version", "dns_servers", "internal_targets"}
_PUBLIC_EGRESS_RESERVED_PORTS = {53, 353, 380, 381, 15353, 18080, 18081}
_ROOT_PROFILE_SYSCTLS = (
    {"name": "net.ipv4.ip_unprivileged_port_start", "value": "1024"},
)
_PUBLIC_EGRESS_METADATA_IPS = {
    "100.100.100.200",
    "100.100.100.201",
    "168.63.129.16",
    "169.254.169.254",
    "169.254.170.2",
    "169.254.170.23",
}
_PUBLIC_FQDN_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?")


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _valid_public_ipv4(value: Any) -> bool:
    if not isinstance(value, str) or not value or value != value.strip():
        return False
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return bool(
        address.version == 4
        and not address.is_unspecified
        and not address.is_loopback
        and not address.is_link_local
        and not address.is_multicast
        and address.packed[0] != 0
        and address.packed[0] < 224
        and value not in _PUBLIC_EGRESS_METADATA_IPS
    )


def _valid_public_fqdn(value: Any) -> bool:
    if not isinstance(value, str) or not value or value != value.strip():
        return False
    if len(value) > 253 or value.endswith(".") or value != value.lower():
        return False
    labels = value.split(".")
    return len(labels) >= 2 and all(
        len(label) <= 63 and _PUBLIC_FQDN_LABEL.fullmatch(label) is not None
        for label in labels
    )


def _parse_public_policy(raw: str) -> tuple[str, str]:
    """Validate the server-owned JSON policy and return (canonical, DNS list)."""
    if not isinstance(raw, str) or not raw or len(raw) > 32768:
        raise ValueError("upstream_proxy requires a non-empty public egress policy")
    try:
        policy = json.loads(raw, object_pairs_hook=_reject_duplicate_json_keys)
    except (TypeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError("upstream_proxy public egress policy is invalid JSON") from exc
    if not isinstance(policy, dict) or set(policy) != _PUBLIC_POLICY_KEYS:
        raise ValueError("upstream_proxy public egress policy has an invalid schema")
    if type(policy.get("version")) is not int or policy["version"] != 1:
        raise ValueError("upstream_proxy public egress policy requires version 1")
    dns_servers = policy.get("dns_servers")
    if (
        not isinstance(dns_servers, list)
        or not 1 <= len(dns_servers) <= 8
        or not all(_valid_public_ipv4(server) for server in dns_servers)
        or len(set(dns_servers)) != len(dns_servers)
    ):
        raise ValueError("upstream_proxy public egress policy requires DNS servers")
    internal_targets = policy.get("internal_targets")
    if not isinstance(internal_targets, list) or len(internal_targets) > 128:
        raise ValueError("upstream_proxy public egress policy internal_targets is invalid")
    seen_hosts: set[str] = set()
    for target in internal_targets:
        if not isinstance(target, dict) or set(target) != {"host", "ips", "ports"}:
            raise ValueError("upstream_proxy public egress policy internal target is invalid")
        if (
            not _valid_public_fqdn(target["host"])
            or target["host"] in seen_hosts
            or not isinstance(target["ips"], list)
            or not 1 <= len(target["ips"]) <= 32
            or not all(_valid_public_ipv4(ip) for ip in target["ips"])
            or len(set(target["ips"])) != len(target["ips"])
            or not isinstance(target["ports"], list)
            or not 1 <= len(target["ports"]) <= 32
            or not all(
                type(port) is int
                and 1 <= port <= 65535
                and port not in _PUBLIC_EGRESS_RESERVED_PORTS
                for port in target["ports"]
            )
            or len(set(target["ports"])) != len(target["ports"])
        ):
            raise ValueError("upstream_proxy public egress policy internal target is invalid")
        seen_hosts.add(target["host"])
    canonical = json.dumps(policy, separators=(",", ":"))
    if canonical != raw:
        raise ValueError("upstream_proxy public egress policy must use canonical JSON")
    return canonical, ",".join(dns_servers)


def build_root_compatible_security_context() -> Dict[str, Any]:
    """Return the fixed security context for the upstream-proxy app container.

    This function returns a fresh structure because provider/template merges
    operate on mutable dictionaries.  Keep the list intentionally explicit:
    adding a capability here changes the security boundary and needs a design
    review.
    """
    return {
        "runAsUser": 0,
        "runAsNonRoot": False,
        "allowPrivilegeEscalation": False,
        "privileged": False,
        "seccompProfile": {"type": "RuntimeDefault"},
        "capabilities": {
            "drop": ["ALL"],
            "add": list(_ROOT_COMPATIBLE_ALLOWED_CAPABILITIES),
        },
    }


def _build_egress_sidecar_security_context(*, strict: bool = False) -> Dict[str, Any]:
    """Return the fixed sidecar context while retaining NET_ADMIN for nftables."""
    capabilities = list(_EGRESS_SIDECAR_SECURITY_CONTEXT["capabilities"]["add"])
    if strict:
        # Required by protected listeners and the MITM child's ambient cap;
        # do not rely on a runtime's implicit default capability set.
        capabilities.append("NET_BIND_SERVICE")
    return {
        "capabilities": {
            "add": capabilities,
        },
    }


def _validate_upstream_egress_image(image: Any) -> None:
    """Require a content-addressed addon image for the strict profile."""
    if (
        not isinstance(image, str)
        or any(char.isspace() or ord(char) < 32 for char in image)
        or not _EGRESS_IMAGE_DIGEST_RE.fullmatch(image)
    ):
        raise ValueError(
            "upstream_proxy requires egress.image pinned by "
            "@sha256:<64 lowercase hex digest>"
        )


def _build_root_profile_sysctls() -> List[Dict[str, str]]:
    """Return the sole Pod sysctl allowed by the strict root profile."""
    return [dict(sysctl) for sysctl in _ROOT_PROFILE_SYSCTLS]


def _apply_root_compatible_profile(containers: List[Dict[str, Any]]) -> None:
    sandbox_containers = [container for container in containers if container.get("name") == "sandbox"]
    if len(sandbox_containers) != 1:
        raise ValueError("upstream_proxy requires exactly one sandbox container")
    sandbox_containers[0]["securityContext"] = build_root_compatible_security_context()


def prep_execd_init_for_egress(exec_install_script: str) -> tuple[str, Dict[str, Any]]:
    """
    Prepare execd init when ``egress.disable_ipv6`` is true: disable IPv6 in the Pod netns, then install.

    Writes ``/proc/sys/.../disable_ipv6`` when that path exists (no ``sysctl`` binary
    required). A missing path is valid for an IPv4-only Pod netns, while a write failure
    remains fatal. The returned security context dict must be applied to the execd init
    container (typically via ``build_security_context_from_dict`` in ``security_context``).

    Returns:
        ``(prefixed_shell_script, {"privileged": True})``
    """
    ipv6_disable_path = shlex.quote(_IPV6_DISABLE_PATH)
    script = (
        f"set -e; if [ -e {ipv6_disable_path} ]; then "
        f"echo 1 > {ipv6_disable_path}; fi; {exec_install_script}"
    )
    return script, {"privileged": True}


def build_security_context_for_sandbox_container(
    has_network_policy: bool,
) -> Dict[str, Any]:
    """
    Security context dict for the main sandbox container.

    When network policy is enabled, drops ``NET_ADMIN`` so only the egress sidecar can
    mutate network stack state.
    """
    if not has_network_policy:
        return {}

    return {
        "capabilities": {
            "drop": ["NET_ADMIN"],
        },
    }


def apply_egress_to_spec(
    containers: List[Dict[str, Any]],
    egress_settings: Optional[EgressWorkloadSettings] = None,
    sandbox_id: Optional[str] = None,
    *,
    pod_spec: Optional[Dict[str, Any]] = None,
) -> None:
    """
    Append the egress sidecar to ``containers``. For the administrator-managed
    upstream profile, render it as a native Kubernetes sidecar init container
    before the generated execd initializer so the network guard is installed
    before the business container can start. When ``egress.disable_ipv6`` is
    enabled, IPv6 is handled by the strict egress guard before the
    root-compatible execd installer runs. The strict profile emits one fixed
    Pod sysctl for low-port compatibility.

    ``sandbox_id`` is injected as ``OPENSANDBOX_EGRESS_SANDBOX_ID`` when provided.
    ``egress.otlp_endpoint`` is injected as ``OTEL_EXPORTER_OTLP_ENDPOINT`` when configured.
    """
    if egress_settings is None:
        return
    upstream = egress_settings.upstream_proxy
    if upstream is not None and (pod_spec is None or pod_spec.get("containers") is not containers):
        raise ValueError("upstream_proxy requires the owning pod_spec for private volume rendering")
    if upstream is not None:
        # This is intentionally applied while the runtime manifest is being
        # generated, before the administrator template is merged.  The final
        # validator below repeats the check after merging.
        _validate_upstream_egress_image(egress_settings.image)
        if not egress_settings.auth_token or not egress_settings.auth_token.strip():
            raise ValueError("upstream_proxy requires the generated control API token")
        _apply_root_compatible_profile(containers)
        assert pod_spec is not None
        pod_spec["automountServiceAccountToken"] = False
        pod_security_context = pod_spec.get("securityContext")
        if pod_security_context is None:
            pod_security_context = {}
        elif not isinstance(pod_security_context, dict):
            raise ValueError("upstream_proxy Pod securityContext is invalid")
        else:
            pod_security_context = dict(pod_security_context)
        pod_security_context["sysctls"] = _build_root_profile_sysctls()
        pod_spec["securityContext"] = pod_security_context
        public_policy, dns_upstream = _parse_public_policy(egress_settings.public_policy)
    else:
        public_policy = dns_upstream = None

    policy_payload = json.dumps(
        egress_settings.network_policy.model_dump(by_alias=True, exclude_none=True)
    )

    env: List[Dict[str, str]] = [
        {"name": EGRESS_RULES_ENV, "value": policy_payload},
        {"name": EGRESS_MODE_ENV, "value": egress_settings.mode},
    ]
    if egress_settings.otlp_endpoint:
        env.append(
            {"name": OTEL_EXPORTER_OTLP_ENDPOINT, "value": egress_settings.otlp_endpoint}
        )
    if sandbox_id:
        env.append({"name": OPENSANDBOX_EGRESS_SANDBOX_ID, "value": sandbox_id})
    if egress_settings.credential_proxy_enabled or upstream is not None:
        env.append({"name": OPENSANDBOX_EGRESS_MITMPROXY_TRANSPARENT, "value": "true"})
    if egress_settings.auth_token:
        env.append({"name": OPENSANDBOX_EGRESS_TOKEN, "value": egress_settings.auth_token})
    if egress_settings.env:
        for name, value in egress_settings.env.items():
            if upstream is not None and (name.startswith("OPENSANDBOX_EGRESS_UPSTREAM_PROXY") or name in {
                "OPENSANDBOX_EGRESS_MITMPROXY_TRANSPARENT",
                "OPENSANDBOX_EGRESS_MITMPROXY_SSL_INSECURE",
                "OPENSANDBOX_EGRESS_MITMPROXY_EXTRA_PORTS",
                "OPENSANDBOX_EGRESS_POLICY_FILE",
                "OPENSANDBOX_EGRESS_MITMPROXY_SCRIPT",
                "OPENSANDBOX_EGRESS_MITMPROXY_UPSTREAM_TRUST_DIR",
                OPENSANDBOX_EGRESS_PUBLIC_POLICY,
                OPENSANDBOX_EGRESS_DNS_UPSTREAM,
            }):
                raise ValueError("request env cannot override administrator upstream_proxy transport settings")
            if (
                egress_settings.credential_proxy_enabled
                and name == OPENSANDBOX_EGRESS_MITMPROXY_TRANSPARENT
            ):
                continue
            env.append({"name": name, "value": value or ""})
    if upstream is not None:
        # _parse_public_policy returns canonical strings after validating the
        # server-owned schema; keep these assignments explicit so request env
        # values can never replace either administrator input.
        assert public_policy is not None and dns_upstream is not None
        env.extend([
            {"name": OPENSANDBOX_EGRESS_PUBLIC_POLICY, "value": public_policy},
            {"name": OPENSANDBOX_EGRESS_DNS_UPSTREAM, "value": dns_upstream},
            {"name": "OPENSANDBOX_EGRESS_UPSTREAM_PROXY", "value": upstream.url},
            {"name": "OPENSANDBOX_EGRESS_UPSTREAM_PROXY_IDENTITY_FILE", "value": "/run/opensandbox/egress-identity/identity.jwt"},
            {"name": "OPENSANDBOX_EGRESS_UPSTREAM_PROXY_CA_FILE", "value": "/run/opensandbox/egress-gateway-ca/ca.crt"},
        ])

    sidecar: Dict[str, Any] = {
        "name": "egress",
        "image": egress_settings.image,
        "env": env,
        "securityContext": _build_egress_sidecar_security_context(strict=upstream is not None),
        "ports": [{"name": "egress-api", "containerPort": 18080}],
        "readinessProbe": {
            "httpGet": {
                "path": "/healthz",
                "port": 18080,
            },
            "periodSeconds": 1,
            "failureThreshold": 30,
        },
    }
    sidecar["volumeMounts"] = [
        {
            "name": OPENSANDBOX_RUNTIME_VOLUME_NAME,
            "mountPath": OPENSANDBOX_RUNTIME_MOUNT_PATH,
        }
    ]
    resources = {}
    if egress_settings.resource_requests:
        resources["requests"] = egress_settings.resource_requests
    if egress_settings.resource_limits:
        resources["limits"] = egress_settings.resource_limits
    if resources:
        sidecar["resources"] = resources
    if egress_settings.auth_token:
        sidecar["readinessProbe"]["httpGet"]["httpHeaders"] = [
            {
                "name": OPEN_SANDBOX_EGRESS_AUTH_HEADER,
                "value": egress_settings.auth_token,
            }
        ]
    if upstream is not None:
        assert pod_spec is not None
        private_volumes = [
            {"name": "egress-gateway-ca", "secret": {
                "secretName": upstream.ca_secret_name, "defaultMode": 0o444,
                "items": [{"key": upstream.ca_key, "path": "ca.crt"}],
            }},
            {"name": "egress-identity", "secret": {
                "secretName": upstream.identity_secret_name, "optional": True, "defaultMode": 0o444,
                "items": [{"key": upstream.identity_key, "path": "identity.jwt"}],
            }},
        ]
        # Directory mounts follow kubelet's atomic Secret projection updates.
        # 0444 permits the unprivileged mitmproxy child to read these files;
        # isolation comes from the mount namespace, not Pod-wide fsGroup.
        existing = pod_spec.get("volumes", [])
        if any(v.get("name") in {"egress-gateway-ca", "egress-identity"} for v in existing):
            raise ValueError("upstream_proxy private volume name conflicts with an existing volume")
        pod_spec["volumes"] = [*existing, *private_volumes]
        sidecar["volumeMounts"] = [*sidecar["volumeMounts"],
            {"name": "egress-gateway-ca", "mountPath": "/run/opensandbox/egress-gateway-ca", "readOnly": True},
            {"name": "egress-identity", "mountPath": "/run/opensandbox/egress-identity", "readOnly": True},
        ]
    if upstream is not None:
        # Native sidecars are ordered with init containers.  The readiness
        # probe remains the authenticated HTTP health endpoint while the
        # startup probe checks the server-owned readiness contract locally:
        # the kubelet must not advance through the init sequence until egress
        # has installed its policy and completed addon initialization.
        assert pod_spec is not None
        sidecar["restartPolicy"] = "Always"
        sidecar["startupProbe"] = {
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
        init_containers = pod_spec.setdefault("initContainers", [])
        if not isinstance(init_containers, list):
            raise ValueError("upstream_proxy requires a list of init containers")
        pod_spec["initContainers"] = [sidecar, *init_containers]
    else:
        containers.append(sidecar)


def _is_dangerous_mount_path(mount_path: Any) -> bool:
    if not isinstance(mount_path, str):
        return False
    # Kubernetes requires an absolute mountPath.  Normalize only for the
    # comparison so a harmless-looking duplicate slash cannot evade the
    # protected /proc and /sys prefixes.
    normalized = posixpath.normpath(mount_path)
    # POSIX permits special semantics for exactly two leading slashes, so
    # normpath preserves them. Linux mount destinations do not: compare their
    # single-root spelling as well as resolving dot components above.
    if normalized.startswith("/"):
        normalized = "/" + normalized.lstrip("/")
    return any(
        normalized == root or normalized.startswith(f"{root}/")
        for root in _DANGEROUS_MOUNT_ROOTS
    )


def _volume_secret_refs(volume: Dict[str, Any]) -> set[str]:
    """Collect Secret names used by direct, projected, CSI and legacy volumes."""
    refs: set[str] = set()
    for source in volume.values():
        if not isinstance(source, dict):
            continue
        secret_name = source.get("secretName")
        if isinstance(secret_name, str):
            refs.add(secret_name)
        for key in ("secretRef", "nodePublishSecretRef"):
            ref = source.get(key)
            if isinstance(ref, dict) and isinstance(ref.get("name"), str):
                refs.add(ref["name"])
    projected = volume.get("projected")
    if isinstance(projected, dict):
        sources = projected.get("sources", [])
        if isinstance(sources, list):
            for source in sources:
                if isinstance(source, dict):
                    secret = source.get("secret")
                    if isinstance(secret, dict) and isinstance(secret.get("name"), str):
                        refs.add(secret["name"])
    return refs


def _validate_upstream_proxy_pod_safety(pod_spec: Dict[str, Any]) -> None:
    """Reject Pod-level escape hatches that templates could otherwise add."""
    if pod_spec.get("automountServiceAccountToken") is not False:
        raise ValueError("upstream_proxy requires automountServiceAccountToken=false")

    if any(
        pod_spec.get(key)
        for key in ("hostNetwork", "hostPID", "hostIPC", "shareProcessNamespace")
    ):
        raise ValueError("upstream_proxy requires isolated Pod network and process namespaces")
    if pod_spec.get("dnsPolicy") == "ClusterFirstWithHostNet":
        raise ValueError("upstream_proxy forbids host-network DNS policy")

    pod_security_context = pod_spec.get("securityContext")
    if not isinstance(pod_security_context, dict):
        raise ValueError("upstream_proxy requires the generated Pod securityContext")
    if pod_security_context.get("sysctls") != _build_root_profile_sysctls():
        raise ValueError("upstream_proxy Pod sysctls must match the generated low-port setting")
    if isinstance(pod_security_context, dict):
        if "procMount" in pod_security_context:
            raise ValueError("upstream_proxy does not permit an unmasked proc mount")
        pod_seccomp = pod_security_context.get("seccompProfile")
        if pod_seccomp is not None and pod_seccomp != {"type": "RuntimeDefault"}:
            raise ValueError("upstream_proxy requires RuntimeDefault seccomp")
        pod_apparmor = pod_security_context.get("appArmorProfile")
        if pod_apparmor is not None and pod_apparmor != {"type": "RuntimeDefault"}:
            raise ValueError("upstream_proxy requires RuntimeDefault AppArmor")
        if "runAsUser" in pod_security_context and pod_security_context["runAsUser"] != 0:
            raise ValueError("upstream_proxy requires UID 0 for the sandbox container")
        if pod_security_context.get("runAsNonRoot") is True:
            raise ValueError("upstream_proxy requires runAsNonRoot=false")
        if "runAsGroup" in pod_security_context and pod_security_context["runAsGroup"] != 0:
            raise ValueError("upstream_proxy requires the Pod runAsGroup to remain root")

    volumes = pod_spec.get("volumes", [])
    if not isinstance(volumes, list):
        raise ValueError("upstream_proxy Pod volumes are invalid")
    for volume in volumes:
        if not isinstance(volume, dict):
            raise ValueError("upstream_proxy Pod volumes are invalid")
        if not isinstance(volume.get("name"), str) or not volume["name"]:
            raise ValueError("upstream_proxy Pod volumes are invalid")
        if "hostPath" in volume:
            raise ValueError("upstream_proxy forbids hostPath volumes")
        projected = volume.get("projected")
        if isinstance(projected, dict):
            sources = projected.get("sources", [])
            if isinstance(sources, list) and any(
                isinstance(source, dict) and "serviceAccountToken" in source
                for source in sources
            ):
                raise ValueError(
                    "upstream_proxy forbids projected serviceAccountToken volumes"
                )

    containers = pod_spec.get("containers", [])
    if not isinstance(containers, list):
        raise ValueError("upstream_proxy Pod containers are invalid")
    init_containers = pod_spec.get("initContainers", [])
    ephemeral_containers = pod_spec.get("ephemeralContainers", [])
    if not isinstance(init_containers, list) or not isinstance(ephemeral_containers, list):
        raise ValueError("upstream_proxy Pod auxiliary containers are invalid")
    if ephemeral_containers:
        raise ValueError("upstream_proxy does not permit ephemeral containers")

    for container in [*containers, *init_containers, *ephemeral_containers]:
        if not isinstance(container, dict):
            raise ValueError("upstream_proxy Pod containers are invalid")
        if container.get("volumeDevices"):
            raise ValueError("upstream_proxy does not permit volume devices")
        mounts = container.get("volumeMounts", [])
        if not isinstance(mounts, list):
            raise ValueError("upstream_proxy container volumeMounts are invalid")
        for mount in mounts:
            if not isinstance(mount, dict):
                raise ValueError("upstream_proxy container volumeMounts are invalid")
            if _is_dangerous_mount_path(mount.get("mountPath")):
                raise ValueError(
                    "upstream_proxy forbids writable /proc, /sys and cgroup mounts"
                )
        for env_key in ("env", "envFrom"):
            env_entries = container.get(env_key)
            if env_entries is not None and (
                not isinstance(env_entries, list)
                or any(not isinstance(entry, dict) for entry in env_entries)
            ):
                raise ValueError(f"upstream_proxy container {env_key} is invalid")
        security_context = container.get("securityContext")
        if isinstance(security_context, dict) and security_context.get("procMount") == "Unmasked":
            raise ValueError("upstream_proxy forbids an unmasked proc mount")


def validate_upstream_proxy_pod(
    pod_spec: Dict[str, Any],
    settings: Optional[EgressWorkloadSettings],
    *,
    expected_execd_init: Optional[Dict[str, Any]] = None,
    expected_sandbox_id: Optional[str] = None,
) -> None:
    """Validate the final merged manifest, including aliases from trusted templates.

    ``expected_execd_init`` is captured from the server-generated init
    container before the template merge.  When supplied, the final list must
    match it exactly. The strict guard already blocks IPv6 before the init
    runs, so this file installer needs no privileged sysctl setup.
    """
    if settings is None or settings.upstream_proxy is None:
        return
    upstream = settings.upstream_proxy
    _validate_upstream_proxy_pod_safety(pod_spec)

    containers = pod_spec.get("containers", [])
    if len(containers) != 1:
        raise ValueError("upstream_proxy requires exactly one sandbox container")
    sandbox_containers = [c for c in containers if c.get("name") == "sandbox"]
    if len(sandbox_containers) != 1:
        raise ValueError("upstream_proxy requires exactly one sandbox container")
    if any(c.get("name") != "sandbox" for c in containers):
        raise ValueError("upstream_proxy does not permit untrusted sidecar containers")
    if sandbox_containers[0].get("securityContext") != build_root_compatible_security_context():
        raise ValueError("upstream_proxy sandbox securityContext was changed by the Pod template")
    main_env = sandbox_containers[0].get("env", [])
    if main_env is None:
        main_env = []
    if not isinstance(main_env, list):
        raise ValueError("upstream_proxy sandbox environment was changed by the Pod template")
    main_id_entries = [
        entry
        for entry in main_env
        if isinstance(entry, dict) and entry.get("name") == "OPENSANDBOX_ID"
    ]
    if expected_sandbox_id is None and len(main_id_entries) == 1:
        inferred_id = main_id_entries[0].get("value")
        if isinstance(inferred_id, str):
            expected_sandbox_id = inferred_id
    if expected_sandbox_id is not None:
        if main_id_entries != [{"name": "OPENSANDBOX_ID", "value": expected_sandbox_id}]:
            raise ValueError("upstream_proxy sandbox identity was changed by the Pod template")

    # Build a fresh server-owned sidecar and private volume set.  The
    # placeholder sandbox is needed because the upstream profile is applied by
    # apply_egress_to_spec before it appends the sidecar.
    expected_spec: Dict[str, Any] = {
        "automountServiceAccountToken": False,
        "containers": [{"name": "sandbox"}],
        "initContainers": [],
        "volumes": [],
    }
    apply_egress_to_spec(expected_spec["containers"], settings, pod_spec=expected_spec)
    expected_sidecar = next(
        c for c in expected_spec["initContainers"] if c.get("name") == "egress"
    )

    init_containers = pod_spec.get("initContainers", [])
    # The sidecar carries the per-workload sandbox ID, which is intentionally
    # injected after the expected sidecar is built above.  Compare its
    # server-owned fields below instead of comparing the whole dictionary here.
    # The generated execd init, however, is captured before template merging and
    # must remain identical, with the same bounded root profile as the app.
    if not isinstance(init_containers, list) or not init_containers:
        raise ValueError("upstream_proxy initContainers must be server generated")
    if init_containers[0].get("name") != "egress":
        raise ValueError("upstream_proxy initContainers must start with the generated egress sidecar")
    if expected_execd_init is None:
        if len(init_containers) != 1:
            raise ValueError("upstream_proxy initContainers must be server generated")
    else:
        if len(init_containers) != 2 or init_containers[1] != expected_execd_init:
            raise ValueError("upstream_proxy generated init containers were changed by the Pod template")
        if init_containers[1].get("securityContext") != build_root_compatible_security_context():
            raise ValueError("upstream_proxy execd installer requires the bounded root profile")

    expected_volumes = {v["name"]: v for v in expected_spec["volumes"]}
    actual_volumes = pod_spec.get("volumes", [])
    for name, expected in expected_volumes.items():
        if [v for v in actual_volumes if v.get("name") == name] != [expected]:
            raise ValueError("upstream_proxy private volumes were changed by the Pod template")

    actual_sidecar = init_containers[0]
    if set(actual_sidecar) != set(expected_sidecar):
        raise ValueError("upstream_proxy sidecar was changed by the Pod template")
    if actual_sidecar.get("securityContext") != expected_sidecar.get("securityContext"):
        raise ValueError("upstream_proxy sidecar securityContext was changed by the Pod template")
    for key in (
        "image",
        "volumeMounts",
        "command",
        "args",
        "ports",
        "readinessProbe",
        "startupProbe",
        "restartPolicy",
        "resources",
    ):
        if actual_sidecar.get(key) != expected_sidecar.get(key):
            raise ValueError("upstream_proxy sidecar was changed by the Pod template")
    # The sandbox ID is injected separately by the provider.  Every other
    # sidecar environment entry is server-owned, so reject additions,
    # deletions and duplicate names rather than trusting template ordering.
    expected_env = {entry["name"]: entry for entry in expected_sidecar["env"]}
    actual_env = actual_sidecar.get("env", [])
    if not isinstance(actual_env, list):
        raise ValueError("upstream_proxy sidecar environment was changed by the Pod template")
    allowed_extra_names = {OPENSANDBOX_EGRESS_SANDBOX_ID}
    actual_by_name: Dict[str, List[Dict[str, Any]]] = {}
    for entry in actual_env:
        if not isinstance(entry, dict) or not isinstance(entry.get("name"), str):
            raise ValueError("upstream_proxy sidecar environment was changed by the Pod template")
        actual_by_name.setdefault(entry["name"], []).append(entry)
    if set(actual_by_name) - set(expected_env) - allowed_extra_names:
        raise ValueError("upstream_proxy sidecar environment was changed by the Pod template")
    for name, entry in expected_env.items():
        if actual_by_name.get(name) != [entry]:
            raise ValueError("upstream_proxy sidecar environment was changed by the Pod template")
    sandbox_id_entries = actual_by_name.get(OPENSANDBOX_EGRESS_SANDBOX_ID, [])
    if len(sandbox_id_entries) > 1 or (
        expected_sandbox_id is not None
        and sandbox_id_entries
        != [{"name": OPENSANDBOX_EGRESS_SANDBOX_ID, "value": expected_sandbox_id}]
    ):
        raise ValueError("upstream_proxy sidecar environment was changed by the Pod template")

    pod_os = pod_spec.get("os", {})
    if pod_spec.get("runtimeClassName") or (
        isinstance(pod_os, dict) and pod_os.get("name", "linux") != "linux"
    ):
        raise ValueError("upstream_proxy currently supports only the default Linux runc runtime")

    secret_names = {upstream.ca_secret_name, upstream.identity_secret_name}
    private_names = {"egress-gateway-ca", "egress-identity"}
    for volume in actual_volumes:
        refs = _volume_secret_refs(volume)
        if secret_names.intersection(refs):
            private_names.add(volume["name"])

    for container in [*containers, *init_containers, *pod_spec.get("ephemeralContainers", [])]:
        mounts = container.get("volumeMounts", []) or []
        if container.get("name") != "egress" and any(
            mount.get("name") in private_names for mount in mounts
        ):
            raise ValueError(
                "upstream_proxy CA and identity volumes may only be mounted into egress"
            )
        refs = []
        for entry in container.get("envFrom", []) or []:
            secret_ref = entry.get("secretRef")
            if isinstance(secret_ref, dict) and isinstance(secret_ref.get("name"), str):
                refs.append(secret_ref["name"])
        for entry in container.get("env", []) or []:
            value_from = entry.get("valueFrom")
            if not isinstance(value_from, dict):
                continue
            secret_ref = value_from.get("secretKeyRef")
            if isinstance(secret_ref, dict) and isinstance(secret_ref.get("name"), str):
                refs.append(secret_ref["name"])
        if secret_names.intersection(refs):
            raise ValueError(
                "upstream_proxy private Secrets cannot be exposed through container environment"
            )
