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

"""Internal Docker-only OSEP-0023 provisioning contract; not request configuration."""

import os

from fastapi import HTTPException, status

from opensandbox_server.services.constants import SandboxErrorCodes


EXPERIMENTAL_REVISION_RUNTIME_ENV = "OPENSANDBOX_EGRESS_EXPERIMENTAL_REVISION_RUNTIME"
QUARANTINE_ID_ENV = "OPENSANDBOX_EGRESS_QUARANTINE_ID"
QUARANTINE_DIRECTORY = "/var/lib/opensandbox-egress/quarantine"
QUARANTINE_VOLUME_PREFIX = "opensandbox-egress-quarantine-"
QUARANTINE_LABEL = "opensandbox.io/egress-quarantine"
QUARANTINE_OWNER_LABEL = "opensandbox.io/egress-quarantine-for"


def experimental_revision_runtime_enabled() -> bool:
    # Only the lifecycle server's administrator can enable this experiment.
    # Both environment names remain absent from ALLOWED_EGRESS_ENV_VARS.
    return os.getenv(EXPERIMENTAL_REVISION_RUNTIME_ENV, "").strip().lower() in {
        "1", "true", "yes", "y", "on",
    }


def reject_quarantine_lifecycle(container, operation: str) -> None:
    """A persisted label keeps unsupported operations disabled after server restart."""
    labels = (getattr(container, "attrs", {}) or {}).get("Config", {}).get("Labels") or {}
    if labels.get(QUARANTINE_LABEL) == "true":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "code": SandboxErrorCodes.INVALID_PARAMETER,
                "message": f"{operation} is unsupported for experimental egress quarantine sandboxes.",
            },
        )
