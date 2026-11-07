#!/usr/bin/env python3
"""One-time backfill of version-specific GitHub Release descriptions.

The original CHANGELOG existed at the pinned, immutable version-3.3.22
release commit. After migration it is removed from the current repo so
the README remains an evergreen product guide and release histories live
under their corresponding GitHub Releases.

This uses the CI job's explicitly scoped GITHUB_TOKEN (contents:write).
It never modifies tags, binary assets, commits or existing historic
prerelease/stable classifications; only v3.3.22 is promoted to stable.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections import defaultdict

REPO = "MSMSofts/MSM-Pingtunnel"
STABLE_TAG = "v3.3.22"
ARCHIVE_COMMIT = "a64a22039b1a22d01635a411ed02978d4c5c60eb"
SECTION_RE = re.compile(r"^##\s+(.+)$", re.MULTILINE)
VERSION_RE = re.compile(r"^(?:\[)?(3\.\d+\.\d+)")
HEADER_RE = re.compile(r"^##\s+.*?(?:\[)?(3\.\d+\.\d+)")
API_VERSION = "2022-11-28"


def parse_changelog(source: str) -> dict[str, str]:
    """Preserve historical notes and keep both original 3.3.5 entries."""
    markers = list(SECTION_RE.finditer(source))
    sections: dict[str, list[str]] = defaultdict(list)
    for n, marker in enumerate(markers):
        heading = marker.group(1)
        match = VERSION_RE.match(heading)
        if not match:
            continue  # Exclude Unreleased, 3.0, 3.1 and policy notes.
        tag = "v" + match.group(1)
        description = heading.split(" — ", 1)
        title = description[1].strip() if len(description) > 1 else ""
        body = source[marker.end():markers[n + 1].start() if n + 1 < len(markers) else len(source)].strip()
        if not body:
            raise ValueError("Historical notes are empty for " + tag)
        if tag == STABLE_TAG:
            title = "Three routing policies and queue-latency optimizations"
        title = re.sub(r"\s*\(preview\)\s*", "", title, flags=re.I)
        if not title:
            title = "Version " + tag
        sections[tag].append(f"### {title}\n\n{body}")
    return {
        tag: (
            f"# MSM-Pingtunnel {tag}\n\n"
            + ("**Stable GitHub release.** CI tests and build checks passed for Linux AMD64 and ARM64. "
               "Real-world gaming latency and network stability depend on the VPS path; this is not a guarantee of zero lag.\n\n"
               if tag == STABLE_TAG else
               "**Archived release notes.** The notes below describe changes as originally released. "
               "For current installation instructions use the latest stable release.\n\n")
            + "\n\n".join(parts)
            + (f"\n\n---\n\n**Install on both VPSs (upgrade together):**\n\n"
               f"```bash\ncurl -fsSL https://raw.githubusercontent.com/{REPO}/{STABLE_TAG}/Source/install.sh -o /tmp/pingtunnel-install.sh\n"
               f"sudo bash /tmp/pingtunnel-install.sh\n```\n\n"
               f"**Routes:** `sudo pingtunnel` → **15) Route Policy**; choose the same mode on both peers.\n"
               f"**Wire:** v4 · **Config schema:** 3 · **Platform:** Linux AMD64 / ARM64.\n"
               if tag == STABLE_TAG else "")
        )
        for tag, parts in sections.items()
    }


def request_json(url: str, token: str, method: str = "GET", payload: dict | None = None):
    data = None if payload is None else json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, method=method,
        headers={
            "Authorization": "Bearer " + token,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": API_VERSION,
            "User-Agent": "MSM-Pingtunnel-release-notes-migration",
            "Content-Type": "application/json",
        },
    )
    for attempt in range(4):
        try:
            with urllib.request.urlopen(req, timeout=35) as response:
                return json.load(response)
        except urllib.error.HTTPError as exc:
            if exc.code not in (429, 500, 502, 503, 504) or attempt == 3:
                # Do not output token, request headers or response data.
                raise RuntimeError(f"GitHub API {method} failed: status {exc.code} at {url}") from exc
            time.sleep(1 + attempt * 2)


def backfill(dry_run: bool) -> None:
    if os.getenv("GITHUB_REPOSITORY") != REPO:
        raise SystemExit("Refusing release migration for unexpected repository")
    source = subprocess.check_output(
        ["git", "show", f"{ARCHIVE_COMMIT}:CHANGELOG.md"], text=True
    )
    notes = parse_changelog(source)
    token = os.environ.get("GITHUB_TOKEN", "")
    if not token and not dry_run:
        raise SystemExit("Missing GITHUB_TOKEN")
    releases = request_json(
        f"https://api.github.com/repos/{REPO}/releases?per_page=100", token
    ) if token else []
    by_tag = {release["tag_name"]: release for release in releases}
    numbered = {tag for tag in by_tag if re.fullmatch(r"v\d+\.\d+\.\d+", tag)}
    if releases:
        missing = numbered - set(notes)
        if missing:
            raise SystemExit("No archived section for versions: " + ", ".join(sorted(missing)))
        if len(numbered) != 30:
            raise SystemExit(f"Expected 30 numbered releases, found {len(numbered)}: aborting")
        latest = by_tag.get(STABLE_TAG)
        if latest is None or latest.get("draft") or len(latest.get("assets", [])) < 9:
            raise SystemExit("Stable release or its built binary/sha256 assets are unavailable")

    for tag in sorted(numbered - {STABLE_TAG}, key=lambda s: tuple(map(int, s[1:].split(".")))):
        release = by_tag[tag]
        if dry_run:
            print(f"DRY-RUN: update notes for {tag}, {len(notes[tag])} characters")
            continue
        request_json(
            f"https://api.github.com/repos/{REPO}/releases/{release['id']}",
            token, "PATCH", {"body": notes[tag]},
        )
        print(f"Updated archived release {tag}")

    if "rust-latest" in by_tag:
        rolling = by_tag["rust-latest"]
        text = (
            "# Rolling build — rust-latest\n\n"
            "This is a moving, unpinned CI build of the Rust manager and Go ICMP core. "
            "For reproducible production deployments use the numbered **latest stable** "
            f"release [{STABLE_TAG}](https://github.com/{REPO}/releases/tag/{STABLE_TAG}).\n\n"
            "The rolling build is not an independent numbered version. Historical "
            "changes are described under each versioned Release."
        )
        if not dry_run:
            request_json(
                f"https://api.github.com/repos/{REPO}/releases/{rolling['id']}",
                token, "PATCH", {"body": text},
            )
        print("Updated rolling release description")

    if STABLE_TAG in by_tag:
        release = by_tag[STABLE_TAG]
        if dry_run:
            print(f"DRY-RUN: promote {STABLE_TAG} to stable and latest")
        else:
            promoted = request_json(
                f"https://api.github.com/repos/{REPO}/releases/{release['id']}",
                token, "PATCH",
                {"body": notes[STABLE_TAG],
                 "name": "MSM-Pingtunnel v3.3.22 — Stable",
                 "prerelease": False,
                 "draft": False,
                 "make_latest": "true"},
            )
            if promoted.get("prerelease") is not False or promoted.get("draft") is not False:
                raise RuntimeError("GitHub did not confirm v3.3.22 as stable")
            print("Promoted v3.3.22 to stable and latest release")
    print("Release notes migration complete:", len(numbered), "numbered releases")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--dry-run", action="store_true")
    opt = p.parse_args()
    try:
        backfill(opt.dry_run)
    except (ValueError, OSError, RuntimeError, subprocess.CalledProcessError) as exc:
        print("Release history migration failed:", exc, file=sys.stderr)
        sys.exit(1)
