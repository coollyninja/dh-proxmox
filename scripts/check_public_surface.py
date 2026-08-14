from __future__ import annotations

import ipaddress
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IPV4 = re.compile(r"(?<![A-Za-z0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![A-Za-z0-9.])")
PRIVATE_DNS = re.compile(
    r"(?i)\b[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9-]+)*\.(?:internal|lan|local)\b"
)
PRIVATE_IPV6 = re.compile(r"(?i)(?<![0-9a-f:])f[cd][0-9a-f]{2}:[0-9a-f:]+")
SKIP_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2"}


def tracked_files() -> list[Path]:
    result = subprocess.run(
        ["/usr/bin/git", "ls-files", "-z"], cwd=ROOT, check=True, capture_output=True
    )
    return [ROOT / item.decode() for item in result.stdout.split(b"\0") if item]


def findings(path: Path) -> list[str]:
    if not path.is_file() or path.suffix.lower() in SKIP_SUFFIXES:
        return []
    try:
        contents = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return []
    problems = [f"private DNS name {match.group(0)!r}" for match in PRIVATE_DNS.finditer(contents)]
    problems.extend(
        f"private IPv6 address {match.group(0)!r}" for match in PRIVATE_IPV6.finditer(contents)
    )
    for match in IPV4.finditer(contents):
        try:
            address = ipaddress.ip_address(match.group(0))
        except ValueError:
            continue
        if address.is_private and not address.is_loopback and not address.is_unspecified:
            problems.append(f"private IPv4 address {address}")
    return problems


def main() -> None:
    failures = [
        f"{path.relative_to(ROOT)}: {problem}"
        for path in tracked_files()
        for problem in findings(path)
    ]
    if failures:
        raise SystemExit("public-surface validation failed:\n" + "\n".join(failures))
    print("public-surface validation passed")


if __name__ == "__main__":
    main()
