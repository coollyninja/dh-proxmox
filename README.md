# dh-proxmox

`dh-proxmox` is the read-only Proxmox VE integration for
[Deckhand](https://github.com/coollyninja/deckhand). It contributes one typed observation
action and status providers for explicitly configured logical targets. It cannot start, stop,
restart, migrate, delete, or otherwise mutate Proxmox resources.

## What it provides

- cluster health summarized from `/cluster/status`
- node state from `/nodes/{node}/status`
- QEMU guest state from `/nodes/{node}/qemu/{vmid}/status/current`
- LXC guest state from `/nodes/{node}/lxc/{vmid}/status/current`
- the read-only `proxmox.target.observe` action
- the complete Deckhand adapter lifecycle: health, plan, execute, observe, verify, and cancel

The public plugin contains no endpoint, node name, VM ID, token, or lab-specific policy.
Deployments bind logical aliases such as `virtualization_cluster` in their private
`deckhand-site-<site>` repository.

## Proxmox preparation

Create a dedicated API token with a minimal read-only role. Proxmox's built-in `PVEAuditor`
role is a reasonable starting point; scope it to only the resources this Deckhand deployment
must observe. Store the token ID and secret in separate files readable only by the Deckhand
process.

## Configuration

```yaml
schema_version: 1
plugins:
  dh-proxmox:
    enabled: true
    config:
      endpoint: https://proxmox.example.invalid:8006
      token_id_file: /run/secrets/deckhand/proxmox-token-id
      token_secret_file: /run/secrets/deckhand/proxmox-token-secret
      verify_tls: true
      ca_file: /run/secrets/deckhand/proxmox-ca.pem
      timeout_seconds: 5
      targets:
        virtualization_cluster:
          kind: cluster
        compute_node:
          kind: node
          node: example-node
        build_runner:
          kind: qemu
          node: example-node
          vmid: 101
```

The endpoint must be an HTTPS origin without credentials, a path, query, or fragment. Credential
and CA paths must be absolute. Target aliases are public control-plane identifiers; the concrete
node names and VM IDs remain deployment configuration.

## Development

```bash
uv sync --all-groups
uv run ruff check .
uv run ruff format --check .
uv run mypy src
uv run pytest
uv run python scripts/check_public_surface.py
```

The plugin is MIT licensed. Its initial core dependency is pinned to the exact Deckhand lifecycle
contract commit; this changes to a released compatibility range after the first stable core
plugin-API release.
