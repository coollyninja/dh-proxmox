from pathlib import Path
from uuid import UUID

import httpx
import pytest
import yaml
from deckhand.adapters import AdapterError, AdapterErrorKind, CancellationDisposition
from deckhand.models import ActionRequest, RequestContext, Target
from deckhand.plugins import (
    PluginActivation,
    PluginConfiguration,
    PluginLock,
    PluginLockEntry,
    PluginManager,
)

from dh_proxmox.plugin import (
    OBSERVE_ACTION,
    ProxmoxClient,
    ProxmoxConfig,
    ProxmoxReadAdapter,
    ProxmoxTarget,
    create_plugin,
)


def write_credential(path: Path, value: str) -> Path:
    path.write_text(value, encoding="utf-8")
    return path


def config(tmp_path: Path, *, targets: dict[str, dict[str, object]]) -> ProxmoxConfig:
    return ProxmoxConfig.model_validate(
        {
            "endpoint": "https://proxmox.example.invalid:8006",
            "token_id_file": write_credential(tmp_path / "token-id", "operator@pve!deckhand"),
            "token_secret_file": write_credential(tmp_path / "token-secret", "test-secret"),
            "targets": targets,
        }
    )


def request(alias: str) -> ActionRequest:
    return ActionRequest(
        action_id=OBSERVE_ACTION.id,
        action_version=1,
        target=Target(type="proxmox_target", id=alias),
        parameters={},
        context=RequestContext(client="test"),
        idempotency_key=UUID("00000000-0000-4000-8000-000000000001"),
    )


def test_manifest_is_read_only_and_matches_repository() -> None:
    manifest = create_plugin().manifest
    assert manifest.id == "dh-proxmox"
    assert manifest.api_version == 1
    assert manifest.permissions.mutation is False
    assert OBSERVE_ACTION.mutation is False
    with open("deckhand-plugin.yaml", encoding="utf-8") as manifest_file:
        assert yaml.safe_load(manifest_file) == manifest.model_dump(mode="json")


@pytest.mark.parametrize(
    ("target", "path"),
    [
        ({"kind": "cluster"}, "/api2/json/cluster/status"),
        ({"kind": "node", "node": "example-node"}, "/api2/json/nodes/example-node/status"),
        (
            {"kind": "qemu", "node": "example-node", "vmid": 101},
            "/api2/json/nodes/example-node/qemu/101/status/current",
        ),
        (
            {"kind": "lxc", "node": "example-node", "vmid": 202},
            "/api2/json/nodes/example-node/lxc/202/status/current",
        ),
    ],
)
def test_target_maps_to_fixed_api_path(target: dict[str, object], path: str) -> None:
    assert ProxmoxTarget.model_validate(target).api_path() == path


@pytest.mark.parametrize(
    "target",
    [
        {"kind": "cluster", "node": "unexpected"},
        {"kind": "node"},
        {"kind": "node", "node": "example", "vmid": 101},
        {"kind": "qemu", "node": "example"},
    ],
)
def test_target_rejects_invalid_bindings(target: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        ProxmoxTarget.model_validate(target)


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://proxmox.example.invalid:8006",
        "https://user:password@proxmox.example.invalid:8006",
        "https://proxmox.example.invalid:8006/api2/json",
        "https://proxmox.example.invalid:8006?token=secret",
    ],
)
def test_config_rejects_unsafe_endpoints(tmp_path: Path, endpoint: str) -> None:
    with pytest.raises(ValueError):
        ProxmoxConfig(
            endpoint=endpoint,
            token_id_file=write_credential(tmp_path / "id", "id"),
            token_secret_file=write_credential(tmp_path / "secret", "secret"),
            targets={"cluster": ProxmoxTarget(kind="cluster")},
        )


def test_config_rejects_noncanonical_alias(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        config(tmp_path, targets={"Real-Cluster": {"kind": "cluster"}})


@pytest.mark.asyncio
async def test_client_sends_api_token_and_normalizes_health(tmp_path: Path) -> None:
    def handler(http_request: httpx.Request) -> httpx.Response:
        assert http_request.url.path == "/api2/json/version"
        assert http_request.headers["Authorization"] == (
            "PVEAPIToken=operator@pve!deckhand=test-secret"
        )
        return httpx.Response(200, json={"data": {"version": "8.4"}})

    client = ProxmoxClient(
        config(tmp_path, targets={"cluster": {"kind": "cluster"}}),
        transport=httpx.MockTransport(handler),
    )
    health = await client.health()
    assert health.state == "healthy"
    assert health.details == {"api": "reachable", "version": "8.4"}


@pytest.mark.asyncio
async def test_client_refuses_redirect(tmp_path: Path) -> None:
    client = ProxmoxClient(
        config(tmp_path, targets={"cluster": {"kind": "cluster"}}),
        transport=httpx.MockTransport(
            lambda _: httpx.Response(302, headers={"location": "https://other.example.invalid"})
        ),
    )
    with pytest.raises(AdapterError) as captured:
        await client.health()
    assert captured.value.kind == AdapterErrorKind.PROTOCOL


@pytest.mark.asyncio
async def test_upstream_error_does_not_leak_response_or_secret(tmp_path: Path) -> None:
    client = ProxmoxClient(
        config(tmp_path, targets={"cluster": {"kind": "cluster"}}),
        transport=httpx.MockTransport(
            lambda _: httpx.Response(401, text="upstream diagnostic with test-secret")
        ),
    )
    with pytest.raises(AdapterError) as captured:
        await client.health()
    assert captured.value.kind == AdapterErrorKind.AUTHENTICATION
    assert "test-secret" not in str(captured.value)
    assert "upstream diagnostic" not in str(captured.value)


@pytest.mark.asyncio
async def test_cluster_observation_is_minimized(tmp_path: Path) -> None:
    client = ProxmoxClient(
        config(tmp_path, targets={"cluster": {"kind": "cluster"}}),
        transport=httpx.MockTransport(
            lambda _: httpx.Response(
                200,
                json={
                    "data": [
                        {"type": "cluster", "name": "example"},
                        {"type": "node", "name": "node-a", "online": 1},
                        {"type": "node", "name": "node-b", "online": 0},
                    ]
                },
            )
        ),
    )
    observation = await client.observe(ProxmoxTarget(kind="cluster"))
    assert observation.state == "degraded"
    assert observation.details == {"node_count": 2, "online_node_count": 1}
    assert "node-a" not in str(observation.details)


@pytest.mark.asyncio
async def test_adapter_implements_full_read_only_lifecycle(tmp_path: Path) -> None:
    client = ProxmoxClient(
        config(tmp_path, targets={"runner": {"kind": "qemu", "node": "example", "vmid": 101}}),
        transport=httpx.MockTransport(
            lambda _: httpx.Response(200, json={"data": {"status": "running"}})
        ),
    )
    adapter = ProxmoxReadAdapter(client, client.config.targets)
    action_request = request("runner")
    plan = await adapter.plan(OBSERVE_ACTION, action_request)
    execution = await adapter.execute(OBSERVE_ACTION, action_request)
    observation = await adapter.observe(OBSERVE_ACTION, action_request)
    verification = await adapter.verify(OBSERVE_ACTION, action_request, execution, observation)
    cancellation = await adapter.cancel(OBSERVE_ACTION, action_request, execution)

    assert len(plan.steps) == 3
    assert execution.reference == "observe:runner"
    assert observation.state == "running"
    assert verification.satisfied is True
    assert cancellation.disposition == CancellationDisposition.ALREADY_TERMINAL


def test_core_discovers_and_loads_installed_plugin(tmp_path: Path) -> None:
    loaded = PluginManager().load(
        PluginConfiguration(
            plugins={
                "dh-core": PluginActivation(),
                "dh-proxmox": PluginActivation(
                    config=config(
                        tmp_path,
                        targets={"virtualization_cluster": {"kind": "cluster"}},
                    ).model_dump(mode="json", exclude_none=True)
                ),
            }
        ),
        PluginLock(
            plugins=[
                PluginLockEntry(id="dh-core", version="0.4.0", source="builtin"),
                PluginLockEntry(id="dh-proxmox", version="0.1.0", source="python"),
            ]
        ),
        allow_external=True,
    )
    assert [manifest.id for manifest in loaded.manifests] == ["dh-core", "dh-proxmox"]
    assert loaded.adapters.get("dh-proxmox.read")
    assert set(loaded.status.providers) == {"virtualization_cluster"}
