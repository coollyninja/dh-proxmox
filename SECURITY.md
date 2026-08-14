# Security policy

Please report suspected vulnerabilities privately through GitHub's security-advisory feature for
this repository. Do not open a public issue containing secrets, internal topology, or exploit
details.

## Deployment expectations

- Use a dedicated, minimally scoped, read-only Proxmox API token.
- Keep token values outside repository configuration and provide them through root-readable files.
- Keep TLS verification enabled. Use `ca_file` for a private certificate authority.
- Restrict network egress to the configured Proxmox origin.
- Put real endpoints, node names, VM IDs, and policy in a private `deckhand-site-<site>` overlay.

The plugin refuses redirects and does not include upstream response bodies or credential values in
its errors. Version 0.1.x intentionally implements no mutation actions.
