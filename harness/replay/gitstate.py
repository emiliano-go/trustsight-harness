"""Reconstruct a package's AUR repository state at the recorded commits.

The document records the PKGBUILD's SHA-256 before and after the change.  AUR
keeps full history, so those hashes identify the two commits exactly - no
position guessing and no dependence on how far HEAD has moved since the alert.

The clone and every read go through TrustSight's sandboxed git client, the
same one its own pipeline uses: the harness neither spawns git nor opens the
network itself.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

__all__ = ["Artifacts", "ReplayGitError", "extract", "project_for", "resolve"]

#: Commits walked when locating a recorded blob.  The AUR clone is shallow, so
#: this is a bound on the walk, not a promise of history depth.
WALK_LIMIT = 2000


class ReplayGitError(RuntimeError):
    """A repository could not be cloned or read."""


def project_for(package: str, cache_dir, upstream_mtime: int | None = None):
    """Clone or open the package through TrustSight's git client."""
    from trustsight import fetcher

    fetcher.CACHE_DIR = cache_dir
    try:
        return fetcher.clone_or_fetch(package, upstream_mtime)
    except Exception as exc:
        raise ReplayGitError(
            f"{package}: clone unavailable: {type(exc).__name__}: {exc}"[:300]) from exc


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _row(commit) -> dict:
    return {
        "sha": commit.id,
        "ts": int(commit.commit_time),
        "who": f"{commit.author_name} <{commit.author_email}>".strip(),
        "parents": list(commit.parents),
    }


def _walk(project, head: str, limit: int = WALK_LIMIT) -> list[dict]:
    try:
        return [_row(commit) for commit in project.walk(head, limit=limit)]
    except Exception as exc:
        raise ReplayGitError(f"walk failed at {head[:12]}: {exc}"[:300]) from exc


def resolve(project, head: str, sha256: str, limit: int = WALK_LIMIT) -> dict | None:
    """The commit whose PKGBUILD hashes to *sha256*, walking back from *head*."""
    if not sha256:
        return None
    for row in _walk(project, head, limit):
        try:
            text = project.file_at(row["sha"], "PKGBUILD")
        except Exception:  # noqa: BLE001, S112 - a commit without the file is no match
            continue
        if _digest(text) == sha256:
            return row
    return None


@dataclass
class Artifacts:
    """The repository inputs the per-package analysis consumes."""

    package: str
    head_sha: str
    previous_sha: str
    old_pkgbuild: str
    new_pkgbuild: str
    srcinfo: str | None
    tree: list[tuple[str, bytes]]
    installs: list[tuple[str, str, str | None]]
    previous_tree: list[tuple[str, bytes]]
    commits: list[dict]
    head_ts: int
    previous_ts: int | None
    first_ts: int
    maintainer: str
    files: list[str] = field(default_factory=list)
    tree_complete: bool = True


_CHECKSUM_FIELDS = ("sha256sums", "sha512sums", "sha1sums", "md5sums", "b2sums")


def _checksum_only(old: str, new: str) -> bool:
    """Whether *old* and *new* differ only in their checksum arrays."""
    def body(text: str) -> list[str]:
        return [line for line in text.splitlines()
                if not line.lstrip().startswith(_CHECKSUM_FIELDS)]

    return bool(old) and old != new and body(old) == body(new)


def extract(project, package: str, case, walk_limit: int = WALK_LIMIT) -> Artifacts:
    """Read the two recorded revisions and everything committed beside them."""
    try:
        head = project.head_commit()
    except Exception as exc:
        raise ReplayGitError(f"{package}: head unreadable: {exc}"[:300]) from exc
    rows = _walk(project, head, walk_limit)
    head_row = resolve(project, head, case.pkgbuild_sha256, walk_limit)
    if head_row is None:
        raise ReplayGitError(
            f"{package}: recorded PKGBUILD {case.pkgbuild_sha256[:12]} not in history")
    previous_row = resolve(project, head, case.previous_pkgbuild_sha256, walk_limit)
    if previous_row is None and head_row["parents"]:
        parent = head_row["parents"][0]
        previous_row = next((row for row in rows if row["sha"] == parent), None)
    # A PKGBUILD can be unchanged across several commits.  The recorded digest
    # then matches more than one revision, and the newest match may predate a
    # file the older snapshot already carried (a .install added in between),
    # which would turn a checksum-only diff into a broader one.  Prefer the
    # newest ancestor with the same PKGBUILD digest whose tree already holds
    # every install file the head carries.
    if previous_row is not None:
        head_installs = [name for name, _body in
                         (project.tree_files(head_row["sha"])[0] or [])
                         if str(name).endswith(".install")]
        if head_installs:
            def _has_all(sha: str) -> bool:
                try:
                    present = {str(name) for name, _body in project.tree_files(sha)[0] or []}
                except Exception:  # noqa: BLE001
                    return False
                return all(name in present for name in head_installs)

            if not _has_all(previous_row["sha"]):
                for row in rows:
                    if row["sha"] in (head_row["sha"], previous_row["sha"]):
                        continue
                    try:
                        text = project.file_at(row["sha"], "PKGBUILD")
                    except Exception:  # noqa: BLE001, S112 - unreadable commit is no candidate
                        continue
                    if _digest(text) == case.previous_pkgbuild_sha256 and _has_all(row["sha"]):
                        previous_row = row
                        break
    try:
        listed, complete = project.tree_files(head_row["sha"])
        files = list(listed)
    except Exception as exc:
        raise ReplayGitError(f"{package}: tree unreadable: {exc}"[:300]) from exc
    tree = [(str(name), body if isinstance(body, bytes) else str(body).encode())
            for name, body in files]
    artifact_texts = (
        project.file_at(previous_row["sha"], "PKGBUILD") if previous_row and previous_row["sha"] else "",
        project.file_at(head_row["sha"], "PKGBUILD"),
    )
    previous_tree: list[tuple[str, bytes]] = []
    if previous_row and previous_row["sha"]:
        try:
            listed_prev, _complete = project.tree_files(previous_row["sha"])
            previous_tree = [(str(name), body if isinstance(body, bytes) else str(body).encode())
                             for name, body in listed_prev or ()]
        except Exception:  # noqa: BLE001 - a missing previous tree is empty
            previous_tree = []
    installs = []
    for name, body in tree:
        if not name.endswith(".install"):
            continue
        old = None
        if previous_row and previous_row["sha"]:
            try:
                old = project.file_at(previous_row["sha"], name)
            except Exception:  # noqa: BLE001 - absent before is a fact
                old = None
        # The watcher's previous companion file comes from its database
        # snapshot, not from git.  When the recorded previous revision does
        # not carry the file at all, that snapshot is unrecoverable.  Only a
        # checksum-only recipe change is affected by the difference (a
        # surgical swap must not look broader); for any other change the
        # install file's absence is a real fact and its hook rules must fire.
        if not old and body and _checksum_only(artifact_texts[0], artifact_texts[1]):
            old = body.decode("utf-8", "replace")
        installs.append((name, body.decode("utf-8", "replace"), old))
    try:
        srcinfo = project.file_at(head_row["sha"], ".SRCINFO")
    except Exception:  # noqa: BLE001 - .SRCINFO is optional
        srcinfo = None
    commits = [
        {"id": row["sha"], "commit_time": row["ts"], "parents": row["parents"],
         "message": "", "author_name": row["who"].split(" <")[0],
         "author_email": row["who"].split("<")[-1].rstrip(">")}
        for row in rows
    ]
    old = ""
    if previous_row and previous_row["sha"]:
        try:
            old = project.file_at(previous_row["sha"], "PKGBUILD")
        except Exception:  # noqa: BLE001 - an absent previous file is empty
            old = ""
    return Artifacts(
        package=package, head_sha=head_row["sha"],
        previous_sha=previous_row["sha"] if previous_row else "",
        old_pkgbuild=old,
        new_pkgbuild=project.file_at(head_row["sha"], "PKGBUILD"),
        srcinfo=srcinfo or None, tree=tree, installs=installs,
        previous_tree=previous_tree, commits=commits,
        head_ts=head_row["ts"],
        previous_ts=previous_row["ts"] if previous_row else None,
        first_ts=min((row["ts"] for row in rows), default=head_row["ts"]),
        maintainer=head_row["who"].strip(), files=[name for name, _ in tree],
        tree_complete=bool(complete),
    )
