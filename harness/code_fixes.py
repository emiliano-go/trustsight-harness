"""Gate and materialize agent-proposed code fixes for FP verdicts.

An FP triage PR must ship the actual rule fix, not only the suppression
JSON.  The sandboxed agent cannot write files, so it proposes each fix as a
unified diff in its verdict; this module is the deterministic gate between
that untrusted text and the PR:

- *Path allowlist.*  Only watcher rule/analysis code under ``src/trustsight/``
  and its tests under ``tests/`` may change.  Packaging, workflow, data, and
  dotfile paths are rejected by construction, as is anything absolute, any
  path containing ``..``, and any path outside the repo root.
- *Format gate.*  Every added line (``+`` lines, excluding the ``+++``
  header) passes the same charset allowlist as the PR text itself: no dash
  lookalikes, no `` -- `` separator, markdown-safe ASCII only.
- *Size caps.*  At most :data:`MAX_FIX_FILES` files and :data:`MAX_ADDED_LINES`
  added lines per PR, and a per-diff character cap, so a runaway verdict
  cannot smuggle a rewrite of the repo into a PR.
- *Apply check.*  Each diff is applied in order inside a throwaway temp
  tree seeded from the trustsight checkout (``git apply`` semantics: if a
  patch does not apply cleanly, the whole fix is rejected with the git
  reason and the tree is rolled back; later fixes still get their chance).
  The applied tree's changed files become the PR's file contents, so the
  rendered PR carries full post-fix sources, ready for the GitHub contents
  API, and the PR backstop compares exactly what a reviewer would merge.
- *Multi-package dedup.*  When several FP packages contribute fixes, the
  first fix to touch a path wins; an identical diff for the same path is
  deduplicated silently, a *different* diff for the same path is rejected
  with a reason (merging two agents' edits to one file is never attempted).

Nothing here trusts the agent: malformed entries are rejected, never
raised, so one bad fix cannot sink the suppressions that must still land.
Rejected entries are returned with reasons for the PR body and the logs.
"""

from __future__ import annotations

import os
import re
import shutil
import signal
import tempfile
import threading
from pathlib import Path

from .bounded import MAX_REPO_FILE_BYTES, read_bytes_capped
from .sandbox import NamespaceUnavailableError

#: Paths an agent fix may touch, relative to the trustsight repo root.
ALLOWED_PREFIXES = ("src/trustsight/", "tests/")

#: Hard caps per rendered PR (all FP packages merged).
MAX_FIX_FILES = 10
MAX_ADDED_LINES = 400

#: Per-fix caps, mirroring the verdict string caps.
MAX_DIFF_CHARS = 32 * 1024
MAX_SUMMARY_CHARS = 512
MAX_FINDING_CHARS = 256

#: Timeout for one git apply invocation.
_APPLY_TIMEOUT = 60

#: Characters a fixed source line may contain: printable ASCII plus tab.
#: The dash rules from the PR text gate (no U+2010..U+2212 lookalikes, no
#: " -- ") apply verbatim; other punctuation (#, =, *, ...) is code and is
#: allowed, because the rendered files are real source committed to the repo.
_CODE_LINE_EXTRA = frozenset("\u2010\u2011\u2012\u2013\u2014\u2015\u2212")


def _enforce_code_line(line: str) -> str:
    bad_dash = sorted({ch for ch in line if ch in _CODE_LINE_EXTRA})
    if bad_dash:
        names = " ".join(f"U+{ord(ch):04X}" for ch in bad_dash)
        raise FixError(f"dash lookalike not allowed ({names}); use ASCII '-'")
    if " -- " in line:
        raise FixError("' -- ' separator is not allowed")
    bad = next((ch for ch in line if ch != "\t" and not 0x20 <= ord(ch) <= 0x7E),
               None)
    if bad is not None:
        raise FixError(f"character not allowed in code line: {bad!r}")
    return line

_PATCH_TARGET_RE = re.compile(r"^\+\+\+ (?:b/([^\t\n]+)|/dev/null)\s*$",
                              re.MULTILINE)

_REQUIRED_KEYS = ("path", "diff", "summary", "linked_finding")


class FixError(ValueError):
    """A code fix is malformed, unsafe, oversized, or does not apply."""


def resolve_repo_root(explicit: str | None = None) -> Path | None:
    """Locate the trustsight checkout used for apply checks.

    Resolution order: the explicit argument, ``$TRUSTSIGHT_REPO_ROOT``, then
    the editable-install location of the ``trustsight`` package (the job
    image builds the three sibling checkouts side by side, so this resolves
    both on the worker host and inside the job container).  Returns None
    when no checkout can be found; callers then reject fixes rather than
    skip the apply check.
    """

    if explicit:
        return Path(explicit).resolve()
    env = os.environ.get("TRUSTSIGHT_REPO_ROOT", "").strip()
    if env:
        return Path(env).resolve()
    try:
        import importlib.util

        spec = importlib.util.find_spec("trustsight")
    except (ImportError, ValueError):
        return None
    if spec is None or not spec.origin:
        return None
    origin = Path(spec.origin).resolve()
    # <root>/src/trustsight/__init__.py -> <root>
    if origin.parent.name == "trustsight" and origin.parent.parent.name == "src":
        return origin.parent.parent.parent
    return None


def check_fix_path(path: object) -> str:
    """Validate a fix path against the allowlist; raise FixError."""

    if not isinstance(path, str) or not path:
        raise FixError("fix path must be a non-empty string")
    if len(path) > 256:
        raise FixError("fix path too long")
    if "\\" in path or path.startswith("/"):
        raise FixError(f"fix path must be repo-relative: {path!r}")
    parts = path.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise FixError(f"fix path escapes the repo root: {path!r}")
    for denied in ("data/", ".github/", "packaging/"):
        if path.startswith(denied):
            raise FixError(f"fix path in denied area {denied!r}: {path!r}")
    if not any(path.startswith(prefix) for prefix in ALLOWED_PREFIXES):
        raise FixError(
            f"fix path outside {ALLOWED_PREFIXES}: {path!r}")
    return path


def validate_fix_shape(fix: object) -> dict:
    """Shape-check one fix entry; raise FixError on any problem."""

    if not isinstance(fix, dict):
        raise FixError("fix must be an object")
    missing = [key for key in _REQUIRED_KEYS if not isinstance(
        fix.get(key), str)]
    if missing:
        raise FixError(f"fix missing string keys: {missing}")
    path = check_fix_path(fix["path"])
    diff = fix["diff"]
    summary = fix["summary"]
    linked = fix["linked_finding"]
    if not diff.strip():
        raise FixError("fix diff is empty")
    if len(diff) > MAX_DIFF_CHARS:
        raise FixError(f"fix diff exceeds {MAX_DIFF_CHARS} chars")
    if len(summary) > MAX_SUMMARY_CHARS:
        raise FixError("fix summary too long")
    if len(linked) > MAX_FINDING_CHARS:
        raise FixError("fix linked_finding too long")
    # Summaries render into the PR body, so they obey the PR text gate.
    from .fp_agent_pr import _enforce_text_format  # late: avoid a cycle

    _enforce_text_format(summary)
    _enforce_text_format(linked)
    added = 0
    for line in diff.splitlines():
        if line.startswith("+") and not line.startswith("+++"):
            added += 1
            _enforce_code_line(line)
        elif line.startswith("-"):
            pass
    if added == 0:
        raise FixError("fix diff adds no lines")
    return {"path": path, "diff": diff, "summary": summary,
            "linked_finding": linked}


def _patch_targets(diff: str) -> list[str]:
    targets = []
    for match in _PATCH_TARGET_RE.finditer(diff):
        target = match.group(1)
        if target is not None:
            targets.append(target)
    return targets


def _sanitize_reason(text: str) -> str:
    """Compress arbitrary tool output into a one-line, allowlist-safe note."""

    allowed = set(
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        " \t;:,()-./'_\"|[]+"
    )
    cleaned = "".join(ch if ch in allowed else "?" for ch in text)
    return " ".join(cleaned.split())[:200] or "unknown"


def _seed_tree(root: Path, repo_root: Path, paths: list[str]) -> None:
    for rel in paths:
        src = repo_root / rel
        dst = root / rel
        if src.is_file() and not src.is_symlink():
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
        elif dst.exists():
            dst.unlink()


async def _write_all(child, fd, data: bytes) -> None:
    """Write *data* to *fd*, owned by *child*, in bounded chunks."""
    ptr = await child.task.ptr(data)
    while ptr.size() > 0:
        _, ptr = await fd.write(ptr)


async def _spawn_git_apply(cwd: str, diff: str, git: str, box: dict):
    """Clone the parser sandbox, exec ``git apply`` on a sealed memfd patch.

    The child chdirs into the throwaway temp tree before exec, so the
    patch's repo-relative paths resolve there and nowhere else.  argv is
    the fixed literal ``[git, apply, --whitespace=nowarn, /proc/self/fd/N]``:
    the patch text is generated input, so it travels as data on a sealed
    memfd, never as an argument, and the child's stderr (which would echo
    generated content) goes to /dev/null - only the exit status is read.
    """
    from rsyscall import Command
    from rsyscall.fcntl import F_SEAL, F, O
    from rsyscall.linux.memfd import MFD
    from rsyscall.path import Path as RPath

    from .sandbox import PARSER_FLAGS, Limits, clone_child

    child = await clone_child(PARSER_FLAGS, limits=Limits.parser())
    box["pid"] = child.pid.pid.near.id
    child.environ.data = {
        "PATH": "/usr/bin:/bin",
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "HOME": "/nonexistent",
    }
    null = await child.task.open(await child.ptr(RPath("/dev/null")), O.RDWR)
    for std in (child.stdout, child.stderr):
        await null.dup2(std)
    await null.close()
    memfd = await child.task.memfd_create("harness-fp-fix", MFD.ALLOW_SEALING)
    box["memfd"] = memfd
    await _write_all(child, memfd, diff.encode("utf-8"))
    await memfd.fcntl(F.SETFD, 0)
    await memfd.fcntl(F.ADD_SEALS, F_SEAL.WRITE | F_SEAL.SHRINK | F_SEAL.GROW)
    await child.task.chdir(await child.ptr(RPath(cwd)))
    patch_path = f"/proc/self/fd/{int(memfd)}"
    return await child.exec(
        Command(RPath(git), [git, "apply", "--whitespace=nowarn", patch_path],
                {}))


async def _git_apply_rc(cwd: str, diff: str, git: str, box: dict) -> int:
    from rsyscall.sys.wait import W

    execd = await _spawn_git_apply(cwd, diff, git, box)
    status = await execd.waitpid(W.EXITED)
    return status.exit_status if status.exit_status is not None else -1


def _apply_one(root: Path, diff: str) -> tuple[bool, str]:
    """Apply *diff* inside *root* via a sandboxed ``git apply``; never raises.

    ``git apply --check`` semantics, but performed on the throwaway tree so
    a valid patch is also the materialization step: success means the files
    under *root* now hold the post-fix content.
    """
    git = shutil.which("git")
    if git is None:
        return False, "git not available"
    box: dict = {}
    state = {"killed": False}

    def _fire() -> None:
        state["killed"] = True
        pid = box.get("pid")
        if pid is not None:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

    timer = threading.Timer(_APPLY_TIMEOUT, _fire)
    timer.start()
    try:
        from .portal import get_portal

        rc = get_portal().run(_git_apply_rc, str(root), diff, git, box)
    except NamespaceUnavailableError as exc:
        return False, f"sandbox unavailable: {exc}"
    except BaseException:
        if state["killed"]:
            return False, f"git apply exceeded {_APPLY_TIMEOUT}s"
        raise
    finally:
        timer.cancel()
    if rc != 0:
        return False, f"git apply exited {rc}"
    return True, ""


def validate_and_apply(
    fixes: list[dict],
    *,
    repo_root: Path | None,
    package: str = "",
) -> dict:
    """Gate every fix and apply the survivors in a temp tree.

    Args:
        fixes: Raw ``code_fixes`` entries from one FP verdict (or, for a
            multi-package render, already-concatenated entries from every
            package; pass the whole list at once so the caps and the
            per-path dedup apply to the PR as a whole).
        repo_root: Trustsight checkout for seeding the temp tree; None
            rejects every fix with a reason instead of skipping the check.
        package: Package name recorded on each accepted entry (body text).

    Returns:
        ``{"files": {path: content}, "fixes": [{path, summary,
        linked_finding, package}], "rejected": [{path, reason}]}``
        *files* maps each changed path to its full post-fix content, ready
        for the PR file map.
    """

    out = {"files": {}, "fixes": [], "rejected": []}
    seen: dict[str, str] = {}  # path -> diff (dedup/conflict detection)
    accepted: list[tuple[dict, str]] = []  # (validated fix, package label)
    total_added = 0

    for raw in fixes:
        path_label = raw.get("path", "?") if isinstance(raw, dict) else "?"
        try:
            fix = validate_fix_shape(raw)
        except (FixError, ValueError) as exc:
            out["rejected"].append({"path": str(path_label)[:256],
                                    "reason": str(exc)[:200]})
            continue
        targets = _patch_targets(fix["diff"])
        if not targets:
            out["rejected"].append({"path": fix["path"],
                                    "reason": "unparseable diff"})
            continue
        try:
            for target in targets:
                check_fix_path(target)
        except FixError as exc:
            out["rejected"].append({"path": fix["path"], "reason": str(exc)})
            continue
        added = sum(1 for line in fix["diff"].splitlines()
                    if line.startswith("+")
                    and not line.startswith("+++"))
        if len(seen) + len(set(targets) - set(seen)) > MAX_FIX_FILES:
            out["rejected"].append({"path": fix["path"],
                                    "reason": f"more than {MAX_FIX_FILES}"
                                              " files per PR"})
            continue
        if total_added + added > MAX_ADDED_LINES:
            out["rejected"].append({"path": fix["path"],
                                    "reason": f"more than {MAX_ADDED_LINES}"
                                              " added lines"})
            continue
        conflict = next((t for t in targets if t in seen), None)
        if conflict is not None:
            if seen[conflict] == fix["diff"]:
                continue  # identical diff for the same path: dedup
            out["rejected"].append({
                "path": fix["path"],
                "reason": f"conflicting diff for {conflict} from another"
                          " package"})
            continue
        label = raw.get("package") if isinstance(raw, dict) else None
        accepted.append((fix, label if isinstance(label, str) else package))
        for target in targets:
            seen[target] = fix["diff"]
        total_added += added

    if not accepted:
        return out

    if repo_root is None or not Path(repo_root).is_dir():
        for fix, _label in accepted:
            out["rejected"].append({"path": fix["path"],
                                    "reason": "trustsight repo root"
                                              " unavailable"})
        return out

    with tempfile.TemporaryDirectory(prefix="fp-code-fixes-") as tmp:
        root = Path(tmp)
        all_targets = []
        for fix, _label in accepted:
            for target in _patch_targets(fix["diff"]):
                if target not in all_targets:
                    all_targets.append(target)
        _seed_tree(root, Path(repo_root), all_targets)

        changed: set[str] = set()
        for fix, label in accepted:
            before = {t: (read_bytes_capped(root / t, MAX_REPO_FILE_BYTES,
                                            "apply target")
                          if (root / t).is_file() else None)
                      for t in all_targets}
            ok, reason = _apply_one(root, fix["diff"])
            if not ok:
                for target, data in before.items():
                    dst = root / target
                    if data is None:
                        if dst.exists():
                            dst.unlink()
                    elif read_bytes_capped(
                            dst, MAX_REPO_FILE_BYTES, "apply target") != data:
                        dst.parent.mkdir(parents=True, exist_ok=True)
                        dst.write_bytes(data)
                out["rejected"].append({"path": fix["path"],
                                        "reason": f"does not apply: {reason}"})
                continue
            for target in _patch_targets(fix["diff"]):
                if target not in changed:
                    changed.add(target)
            out["fixes"].append({"path": fix["path"],
                                 "summary": fix["summary"],
                                 "linked_finding": fix["linked_finding"],
                                 "package": label})
        for target in sorted(changed):
            data = read_bytes_capped(root / target, MAX_REPO_FILE_BYTES,
                                     "apply target")
            try:
                out["files"][target] = data.decode("utf-8", "strict")
            except UnicodeDecodeError:
                out["files"].pop(target, None)
                out["rejected"].append({"path": target,
                                        "reason": "post-fix content is not"
                                                  " valid UTF-8"})

    return out
