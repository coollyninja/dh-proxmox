from __future__ import annotations

import re
import ssl
from collections.abc import Mapping
from enum import StrEnum
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlparse

import httpx
from deckhand.adapters import (
    AdapterCancellation,
    AdapterError,
    AdapterErrorKind,
    AdapterExecution,
    AdapterHealth,
    AdapterHealthState,
    AdapterObservation,
    AdapterPlan,
    AdapterVerification,
    CancellationDisposition,
)
from deckhand.models import (
    ActionDefinition,
    ActionRequest,
    ConfirmationMode,
    RetryDisposition,
    RiskClass,
    StatusValue,
    StrictModel,
)
from deckhand.plugin_api import (
    DeckhandPlugin,
    PluginContext,
    PluginContribution,
    PluginManifest,
    PluginPermissions,
)
from pydantic import Field, field_validator, model_validator


class ProxmoxTargetKind(StrEnum):
    CLUSTER = "cluster"
    NODE = "node"
    QEMU = "qemu"
    LXC = "lxc"


class ProxmoxTarget(StrictModel):
    kind: ProxmoxTargetKind
    node: str | None = Field(default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
    vmid: int | None = Field(default=None, ge=1, le=999_999_999)
    stale_after_seconds: int = Field(default=30, ge=1, le=3600)

    @model_validator(mode="after")
    def validate_shape(self) -> ProxmoxTarget:
        needs_node = self.kind in {
            ProxmoxTargetKind.NODE,
            ProxmoxTargetKind.QEMU,
            ProxmoxTargetKind.LXC,
        }
        needs_vmid = self.kind in {ProxmoxTargetKind.QEMU, ProxmoxTargetKind.LXC}
        if needs_node != (self.node is not None):
            raise ValueError(f"{self.kind.value} target has invalid node binding")
        if needs_vmid != (self.vmid is not None):
            raise ValueError(f"{self.kind.value} target has invalid vmid binding")
        return self

    def api_path(self) -> str:
        if self.kind == ProxmoxTargetKind.CLUSTER:
            return "/api2/json/cluster/status"
        node = quote(self.node or "", safe="")
        if self.kind == ProxmoxTargetKind.NODE:
            return f"/api2/json/nodes/{node}/status"
        return f"/api2/json/nodes/{node}/{self.kind.value}/{self.vmid}/status/current"


class ProxmoxConfig(StrictModel):
    endpoint: str
    token_id_file: Path
    token_secret_file: Path
    verify_tls: bool = True
    ca_file: Path | None = None
    timeout_seconds: float = Field(default=5.0, gt=0, le=30)
    targets: dict[str, ProxmoxTarget] = Field(min_length=1)

    @field_validator("endpoint")
    @classmethod
    def validate_endpoint(cls, value: str) -> str:
        parsed = urlparse(value)
        if parsed.scheme != "https" or not parsed.hostname:
            raise ValueError("endpoint must be an absolute HTTPS origin")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("endpoint must not contain credentials, query, or fragment")
        if parsed.path not in {"", "/"}:
            raise ValueError("endpoint must not contain a path")
        return value.rstrip("/")

    @field_validator("token_id_file", "token_secret_file", "ca_file")
    @classmethod
    def validate_file_path(cls, value: Path | None) -> Path | None:
        if value is not None and not value.is_absolute():
            raise ValueError("credential and CA file paths must be absolute")
        return value

    @field_validator("targets")
    @classmethod
    def validate_target_aliases(cls, value: dict[str, ProxmoxTarget]) -> dict[str, ProxmoxTarget]:
        invalid = [alias for alias in value if re.fullmatch(r"[a-z][a-z0-9_]{0,63}", alias) is None]
        if invalid:
            raise ValueError("target aliases must be lowercase logical identifiers")
        return value


class ProxmoxClient:
    def __init__(
        self,
        config: ProxmoxConfig,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.config = config
        self.transport = transport

    @staticmethod
    def _credential(path: Path) -> str:
        try:
            if path.stat().st_size > 4096:
                raise AdapterError(
                    "credential file exceeds size limit",
                    kind=AdapterErrorKind.CONFIGURATION,
                )
            value = path.read_text(encoding="utf-8").strip()
        except OSError as error:
            raise AdapterError(
                "credential file is unavailable",
                kind=AdapterErrorKind.CONFIGURATION,
            ) from error
        if not value:
            raise AdapterError("credential file is empty", kind=AdapterErrorKind.CONFIGURATION)
        return value

    def _verify(self) -> bool | ssl.SSLContext:
        if not self.config.verify_tls:
            return False
        if self.config.ca_file is None:
            return True
        try:
            return ssl.create_default_context(cafile=str(self.config.ca_file))
        except (OSError, ssl.SSLError) as error:
            raise AdapterError(
                "TLS CA file is unavailable or invalid",
                kind=AdapterErrorKind.CONFIGURATION,
            ) from error

    async def get(self, path: str) -> Any:
        token_id = self._credential(self.config.token_id_file)
        token_secret = self._credential(self.config.token_secret_file)
        try:
            async with httpx.AsyncClient(
                base_url=self.config.endpoint,
                timeout=self.config.timeout_seconds,
                verify=self._verify(),
                follow_redirects=False,
                trust_env=False,
                transport=self.transport,
            ) as client:
                response = await client.get(
                    path, headers={"Authorization": f"PVEAPIToken={token_id}={token_secret}"}
                )
        except httpx.TimeoutException as error:
            raise AdapterError(
                "Proxmox request timed out",
                kind=AdapterErrorKind.TIMEOUT,
                retry=RetryDisposition.SAFE,
            ) from error
        except httpx.HTTPError as error:
            raise AdapterError(
                "Proxmox is unavailable",
                kind=AdapterErrorKind.UNAVAILABLE,
                retry=RetryDisposition.SAFE,
            ) from error
        if response.is_redirect:
            raise AdapterError("Proxmox redirect refused", kind=AdapterErrorKind.PROTOCOL)
        if response.status_code == 401:
            raise AdapterError(
                "Proxmox authentication failed", kind=AdapterErrorKind.AUTHENTICATION
            )
        if response.status_code == 403:
            raise AdapterError("Proxmox authorization failed", kind=AdapterErrorKind.AUTHORIZATION)
        if response.status_code == 404:
            raise AdapterError(
                "configured Proxmox target was not found",
                kind=AdapterErrorKind.NOT_FOUND,
            )
        if response.status_code == 429:
            raise AdapterError(
                "Proxmox rate limit reached",
                kind=AdapterErrorKind.RATE_LIMITED,
                retry=RetryDisposition.SAFE,
            )
        if response.status_code >= 500:
            raise AdapterError(
                "Proxmox returned a server error",
                kind=AdapterErrorKind.UNAVAILABLE,
                retry=RetryDisposition.SAFE,
            )
        if response.status_code >= 400:
            raise AdapterError("Proxmox request failed", kind=AdapterErrorKind.PROTOCOL)
        try:
            document = response.json()
        except ValueError as error:
            raise AdapterError(
                "Proxmox returned invalid JSON", kind=AdapterErrorKind.PROTOCOL
            ) from error
        if not isinstance(document, dict) or "data" not in document:
            raise AdapterError(
                "Proxmox response envelope is invalid", kind=AdapterErrorKind.PROTOCOL
            )
        return document["data"]

    async def health(self) -> AdapterHealth:
        data = await self.get("/api2/json/version")
        details = {"api": "reachable"}
        if isinstance(data, dict) and isinstance(data.get("version"), str):
            details["version"] = data["version"]
        return AdapterHealth(state=AdapterHealthState.HEALTHY, details=details)

    async def observe(self, target: ProxmoxTarget) -> AdapterObservation:
        data = await self.get(target.api_path())
        if target.kind == ProxmoxTargetKind.CLUSTER:
            if not isinstance(data, list):
                raise AdapterError(
                    "Proxmox cluster status has invalid shape", kind=AdapterErrorKind.PROTOCOL
                )
            nodes = [
                entry for entry in data if isinstance(entry, dict) and entry.get("type") == "node"
            ]
            online = sum(entry.get("online") == 1 for entry in nodes)
            state = "healthy" if nodes and online == len(nodes) else "degraded"
            return AdapterObservation(
                state=state,
                details={"node_count": len(nodes), "online_node_count": online},
            )
        if not isinstance(data, dict):
            raise AdapterError(
                "Proxmox target status has invalid shape", kind=AdapterErrorKind.PROTOCOL
            )
        source_state = data.get("status") or data.get("qmpstatus")
        state = source_state if isinstance(source_state, str) and source_state else "unknown"
        return AdapterObservation(state=state, details={"kind": target.kind.value})


class ProxmoxReadAdapter:
    def __init__(self, client: ProxmoxClient, targets: Mapping[str, ProxmoxTarget]) -> None:
        self.client = client
        self.targets = dict(targets)

    def _target(self, request: ActionRequest) -> ProxmoxTarget:
        try:
            return self.targets[request.target.id]
        except KeyError as error:
            raise AdapterError(
                "Proxmox target alias is not configured", kind=AdapterErrorKind.NOT_FOUND
            ) from error

    async def health(self) -> AdapterHealth:
        return await self.client.health()

    async def plan(self, action: ActionDefinition, request: ActionRequest) -> AdapterPlan:
        self._target(request)
        return AdapterPlan(
            steps=["resolve configured target alias", "observe Proxmox API", "verify observation"]
        )

    async def execute(self, action: ActionDefinition, request: ActionRequest) -> AdapterExecution:
        self._target(request)
        return AdapterExecution(reference=f"observe:{request.target.id}")

    async def observe(self, action: ActionDefinition, request: ActionRequest) -> AdapterObservation:
        return await self.client.observe(self._target(request))

    async def verify(
        self,
        action: ActionDefinition,
        request: ActionRequest,
        execution: AdapterExecution,
        observation: AdapterObservation,
    ) -> AdapterVerification:
        return AdapterVerification(
            satisfied=observation.state != "unknown",
            details={"execution_reference": execution.reference},
        )

    async def cancel(
        self,
        action: ActionDefinition,
        request: ActionRequest,
        execution: AdapterExecution | None,
    ) -> AdapterCancellation:
        return AdapterCancellation(disposition=CancellationDisposition.ALREADY_TERMINAL)


class ProxmoxStatusProvider:
    def __init__(self, client: ProxmoxClient, target: ProxmoxTarget) -> None:
        self.client = client
        self.target = target

    async def observe(self) -> StatusValue:
        observation = await self.client.observe(self.target)
        return StatusValue(
            state=observation.state,
            observed_at=observation.observed_at,
            stale_after_seconds=self.target.stale_after_seconds,
            details=observation.details,
        )


OBSERVE_ACTION = ActionDefinition(
    id="proxmox.target.observe",
    version=1,
    title="Observe Proxmox target",
    description="Read current state for a configured logical Proxmox target alias.",
    risk_class=RiskClass.READ,
    plugin="dh-proxmox",
    adapter="dh-proxmox.read",
    target_types=["proxmox_target"],
    parameter_schema={
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "additionalProperties": False,
        "properties": {},
    },
    policy_action="proxmox.target.observe",
    confirmation=ConfirmationMode.NONE,
    timeout_seconds=30,
    idempotency="read-only",
    mutation=False,
)


CONFIG_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "additionalProperties": False,
    "required": ["endpoint", "token_id_file", "token_secret_file", "targets"],
    "properties": {
        "endpoint": {"type": "string", "format": "uri", "pattern": "^https://"},
        "token_id_file": {"type": "string", "pattern": "^/"},
        "token_secret_file": {"type": "string", "pattern": "^/"},
        "verify_tls": {"type": "boolean", "default": True},
        "ca_file": {"type": "string", "pattern": "^/"},
        "timeout_seconds": {"type": "number", "exclusiveMinimum": 0, "maximum": 30},
        "targets": {
            "type": "object",
            "minProperties": 1,
            "propertyNames": {"pattern": "^[a-z][a-z0-9_]{0,63}$"},
            "additionalProperties": {
                "type": "object",
                "additionalProperties": False,
                "required": ["kind"],
                "properties": {
                    "kind": {"enum": ["cluster", "node", "qemu", "lxc"]},
                    "node": {"type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"},
                    "vmid": {"type": "integer", "minimum": 1, "maximum": 999999999},
                    "stale_after_seconds": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 3600,
                    },
                },
                "allOf": [
                    {
                        "if": {"properties": {"kind": {"const": "cluster"}}},
                        "then": {
                            "not": {"anyOf": [{"required": ["node"]}, {"required": ["vmid"]}]}
                        },
                    },
                    {
                        "if": {"properties": {"kind": {"const": "node"}}},
                        "then": {
                            "required": ["node"],
                            "not": {"required": ["vmid"]},
                        },
                    },
                    {
                        "if": {"properties": {"kind": {"enum": ["qemu", "lxc"]}}},
                        "then": {"required": ["node", "vmid"]},
                    },
                ],
            },
        },
    },
}


class ProxmoxPlugin:
    @property
    def manifest(self) -> PluginManifest:
        return PluginManifest(
            id="dh-proxmox",
            name="Proxmox VE",
            version="0.1.0",
            description="Read-only status and typed observation for configured Proxmox targets.",
            adapters=["dh-proxmox.read"],
            status_provider_types=["proxmox-resource"],
            actions=[OBSERVE_ACTION.id],
            permissions=PluginPermissions(
                mutation=False,
                credential_slots=[
                    "proxmox.token_id",
                    "proxmox.token_secret",
                    "proxmox.tls_ca",
                ],
                egress_bindings=["endpoint"],
            ),
            config_schema=CONFIG_SCHEMA,
        )

    def build(self, context: PluginContext) -> PluginContribution:
        config = ProxmoxConfig.model_validate(dict(context.config))
        client = ProxmoxClient(config)
        return PluginContribution(
            adapters={"dh-proxmox.read": ProxmoxReadAdapter(client, config.targets)},
            status_providers={
                alias: ProxmoxStatusProvider(client, target)
                for alias, target in config.targets.items()
            },
            actions=(OBSERVE_ACTION,),
        )


def create_plugin() -> DeckhandPlugin:
    return ProxmoxPlugin()
