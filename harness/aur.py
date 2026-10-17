"""Reading a package's build files from the AUR, within the AUR's rules.

The AUR is a free service that asks clients to be reasonable: the RPC is
capped at 4000 requests a day per IP, a ``multiinfo`` call must fit about
200 names and a 4443-byte URI, and searches are rejected below two
characters.  Bulk consumers are pointed at the metadata archives instead.
This module obeys the rules it can:

* it uses the documented endpoints - the v5 RPC for metadata, and the
  snapshot tarball for the build files - rather than scraping the web UI;
* it splits ``info`` calls to fit, and validates every name before it
  becomes part of a URL;
* it spends a budget of half the published daily cap, with a minimum gap
  between calls, and carries that budget across processes in a ledger;
* it caches a snapshot by (base, version, LastModified), so re-reading an
  unchanged package costs nothing.

It never fetches a URL that appears *inside* a PKGBUILD; the only URLs it
builds are ``aur.archlinux.org`` ones for the names the caller gave.

**Nothing here is unbounded.**  A hostile or broken peer, a saturating rate
limiter, or a caller handing over a million names all end the same way, at a
named cap:

* at most ``MAX_INFO_NAMES`` names per call, so a call issues at most
  ``MAX_INFO_NAMES / _INFO_CHUNK`` requests;
* at most ``_INFO_MAX_BYTES`` per RPC response and ``_MAX_RESULTS`` parsed
  records, and every string field is truncated to ``_MAX_FIELD_BYTES``;
* a snapshot tarball is read in memory, bounded in compressed bytes, member
  count and decompressed total, and the text of every build file
  (``PKGBUILD``, ``.SRCINFO``, ``*.install``, hooks, patches, ...) is
  retained, each capped;
* a whole call runs under a wall-clock :class:`~harness.net.Deadline`, which
  caps the pacing pause, the retry sleep and the socket read together.

A namespace sandbox is deliberately *not* used here.  It would either keep
the host network - adding no isolation the byte, count and deadline caps do
not already provide against a hostile *response* - or clone ``NEWNET``,
which would sever the very peer the tool exists to read.  The guarantee that
matters for a network client is that its work is bounded, and that is
enforced in the caps below and tested in ``tests/test_aur.py``.
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import tarfile
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import quote

from .net import Deadline, Fetcher, NetworkError, SlidingWindowLimiter, cache_dir

__all__ = ["AUR_READ_PER_DAY", "MAX_INFO_NAMES", "AurClient", "AurError"]

AUR_RPC = "https://aur.archlinux.org/rpc/v5"
AUR_SNAPSHOT = "https://aur.archlinux.org/cgit/aur.git/snapshot"

#: The published cap is 4000/day; half leaves headroom for other clients
#: sharing the IP and for a restart that reloads the ledger.
AUR_READ_PER_DAY = 2000
AUR_MIN_INTERVAL = 1.0

#: A whole call may not outlast this, pacing and retries included.
AUR_INFO_DEADLINE = 60.0
AUR_SNAPSHOT_DEADLINE = 120.0

#: The most names one ``info`` call accepts.  Beyond the URI/count split this
#: is the hard ceiling that keeps a single call's request count bounded.
MAX_INFO_NAMES = 2000

#: A ``multiinfo`` call must fit the URI limit and about 200 names.
_INFO_CHUNK = 200
_URI_BUDGET = 4000

#: A single RPC response and the records it may carry; strings are truncated.
_INFO_MAX_BYTES = 4 * 1024 * 1024
_MAX_RESULTS = 20000
_MAX_FIELD_BYTES = 4096

#: A name is scp-like at most; a longer one is not a name the AUR holds.
_MAX_NAME_BYTES = 255

#: A snapshot carries build files, not sources; keep a hard ceiling anyway.
_SNAPSHOT_MAX_BYTES = 16 * 1024 * 1024
_MAX_MEMBERS = 512
_MAX_TOTAL_UNCOMPRESSED = 32 * 1024 * 1024
_MAX_PKGBUILD_BYTES = 512 * 1024
_MAX_FILE_BYTES = 512 * 1024

#: A cache entry is written by us, but read back defensively: a tampered or
#: truncated file must not allocate without limit.
_CACHE_READ_MAX_BYTES = 2 * 1024 * 1024

#: Arch package/base naming: alphanumerics and ``@ . _ + -``, never a
#: leading hyphen or dot, never a path separator.
_NAME = re.compile(r"^[A-Za-z0-9@_+][A-Za-z0-9@._+-]*$")


class AurError(NetworkError):
    """The AUR could not answer, or the request was not ours to make."""


@dataclass(frozen=True)
class PackageBuild:
    """One package's build files, as analysed from an AUR snapshot."""

    package: str
    version: str
    last_modified: int | None
    files: list[str]
    pkgbuild: str
    cached: bool
    files_text: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "package": self.package,
            "version": self.version,
            "last_modified": self.last_modified,
            "files": self.files,
            "pkgbuild": self.pkgbuild,
            "files_text": self.files_text,
            "cached": self.cached,
        }


def _validate(name: str) -> str:
    if (not isinstance(name, str) or name in (".", "..")
            or len(name.encode("utf-8", errors="replace")) > _MAX_NAME_BYTES
            or not _NAME.match(name)):
        raise AurError(f"not a valid AUR package name: {name!r}")
    return name


def _truncate(row: dict) -> dict:
    """A record with every string bounded, so no field can dominate a reply."""
    out: dict = {}
    for key, value in row.items():
        if isinstance(value, str):
            out[key] = value[:_MAX_FIELD_BYTES]
        elif isinstance(value, (list, tuple)):
            out[key] = [
                item[:_MAX_FIELD_BYTES] if isinstance(item, str) else item
                for item in list(value)[:_MAX_RESULTS]
            ]
        else:
            out[key] = value
    return out


def _chunks(names: list[str]) -> list[list[str]]:
    """Split names into ``info`` batches that fit the URI and count caps."""
    chunks: list[list[str]] = []
    current: list[str] = []
    length = 0
    for name in names:
        cost = len("arg[]=") + len(quote(name, safe="")) + 1
        if current and (len(current) >= _INFO_CHUNK or length + cost > _URI_BUDGET):
            chunks.append(current)
            current, length = [], 0
        current.append(name)
        length += cost
    if current:
        chunks.append(current)
    return chunks


def _reject_unsafe(path: str) -> None:
    parts = path.split("/")
    if path.startswith("/") or any(p in ("", ".", "..") for p in parts):
        raise AurError(f"snapshot member escapes the archive: {path!r}")


def _read_snapshot(data: bytes) -> tuple[list[str], str, dict[str, str]]:
    """Return (file names, PKGBUILD text, other build files' text).

    The tarball is read in memory; nothing is extracted to disk, and the
    decompressed total is bounded so a hostile archive cannot exhaust RAM.
    Every text member (``.SRCINFO``, ``*.install``, hooks, patches, ...) is
    retained, each capped; binary members are listed but not decoded.
    """
    files: list[str] = []
    pkgbuild = ""
    files_text: dict[str, str] = {}
    total = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
            for index, member in enumerate(tar):
                if index >= _MAX_MEMBERS:
                    raise AurError("snapshot has too many members")
                if not member.isfile():
                    continue
                total += member.size
                if total > _MAX_TOTAL_UNCOMPRESSED:
                    raise AurError("snapshot decompresses beyond the cap")
                raw = member.name
                if raw.startswith("/"):
                    raise AurError(f"snapshot member escapes the archive: {raw!r}")
                name = raw.split("/", 1)[1] if "/" in raw else raw
                _reject_unsafe(name)
                files.append(name)
                handle = tar.extractfile(member)
                if handle is None:
                    continue
                if name == "PKGBUILD":
                    pkgbuild = handle.read(_MAX_PKGBUILD_BYTES).decode(
                        "utf-8", errors="replace"
                    )
                    continue
                blob = handle.read(_MAX_FILE_BYTES)
                if b"\x00" in blob:  # binary; list it but do not decode
                    continue
                files_text[name] = blob.decode("utf-8", errors="replace")
    except tarfile.TarError as exc:
        raise AurError(f"snapshot is not a readable tarball: {exc}") from exc
    if "PKGBUILD" not in files:
        raise AurError("snapshot has no PKGBUILD")
    return sorted(files), pkgbuild, files_text


class AurClient:
    """A paced, cached, read-only client over the AUR RPC and snapshots."""

    def __init__(
        self,
        *,
        fetcher: Fetcher | None = None,
        cache_root: Path | None = None,
        read_per_day: int = AUR_READ_PER_DAY,
    ):
        root = cache_root if cache_root is not None else cache_dir()
        root.mkdir(parents=True, exist_ok=True)
        self._cache = root / "aur-snapshots"
        self._cache.mkdir(parents=True, exist_ok=True)
        self._fetcher = fetcher if fetcher is not None else Fetcher(
            limiter=SlidingWindowLimiter(
                read_per_day,
                86400.0,
                min_interval=AUR_MIN_INTERVAL,
                state_path=root / "aur-ledger.json",
            )
        )

    def close(self) -> None:
        self._fetcher.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # -- metadata -----------------------------------------------------

    def info(self, names: list[str]) -> dict[str, dict]:
        """The RPC ``multiinfo`` records for *names*, keyed by Name and Base.

        Bounded by ``MAX_INFO_NAMES`` names and a wall-clock deadline; each
        response is byte-capped and each field truncated.
        """
        if isinstance(names, str):
            names = [names]
        return self._info(names, Deadline(AUR_INFO_DEADLINE))

    def _info(self, names: list[str], deadline: Deadline) -> dict[str, dict]:
        if len(names) > MAX_INFO_NAMES:
            raise AurError(
                f"info accepts at most {MAX_INFO_NAMES} names per call, "
                f"got {len(names)}"
            )
        validated = [_validate(n) for n in names]
        out: dict[str, dict] = {}
        parsed = 0
        for chunk in _chunks(validated):
            deadline.check("RPC info")
            params = [("arg[]", n) for n in chunk]
            result = self._fetcher.get(
                f"{AUR_RPC}/info", params=params,
                max_bytes=_INFO_MAX_BYTES, deadline=deadline,
            )
            if result.status != 200:
                raise AurError(f"RPC info returned HTTP {result.status}")
            data = result.json()
            if not isinstance(data, dict):
                raise AurError("RPC info returned a non-object")
            if data.get("type") == "error":
                raise AurError(f"RPC info error: {data.get('error', 'unknown')}")
            for row in data.get("results", []):
                if not isinstance(row, dict):
                    continue
                parsed += 1
                if parsed > _MAX_RESULTS:
                    raise AurError(f"RPC info returned more than {_MAX_RESULTS} records")
                row = _truncate(row)
                name = row.get("Name")
                base = row.get("PackageBase")
                if isinstance(name, str):
                    out[name] = row
                if isinstance(base, str):
                    out.setdefault(base, row)
        return out

    # -- build files --------------------------------------------------

    def pkgbuild(self, base: str) -> PackageBuild:
        """The snapshot's build files for *base*, cached by version.

        The metadata call and the snapshot fetch share one deadline, so the
        whole operation - not just each request - is time-bounded.
        """
        base = _validate(base)
        deadline = Deadline(AUR_SNAPSHOT_DEADLINE)
        records = self._info([base], deadline)
        record = records.get(base)
        if record is None:
            raise AurError(f"{base}: not found in the AUR")

        version = str(record.get("Version", ""))[:256]
        last_modified = record.get("LastModified")
        if not isinstance(last_modified, int):
            last_modified = None
        key = hashlib.sha256(
            f"{base}\0{version}\0{last_modified}".encode()
        ).hexdigest()[:32]
        cached = self._cache / f"{key}.json"
        if cached.exists():
            data = self._read_cache(cached)
            if data is not None:
                return PackageBuild(
                    package=data["package"], version=data["version"],
                    last_modified=data.get("last_modified"),
                    files=list(data["files"]), pkgbuild=data["pkgbuild"],
                    files_text=dict(data.get("files_text", {})),
                    cached=True,
                )

        url = f"{AUR_SNAPSHOT}/{quote(base, safe='')}.tar.gz"
        result = self._fetcher.get(
            url, accept="application/gzip", max_bytes=_SNAPSHOT_MAX_BYTES,
            deadline=deadline,
        )
        if result.status == 404:
            raise AurError(f"{base}: no snapshot available")
        if result.status != 200:
            raise AurError(f"snapshot returned HTTP {result.status}")

        files, pkgbuild, files_text = _read_snapshot(result.content)
        build = PackageBuild(
            package=base, version=version, last_modified=last_modified,
            files=files, pkgbuild=pkgbuild, files_text=files_text, cached=False,
        )
        try:
            cached.write_text(json.dumps({**build.to_dict(), "cached": False}))
        except OSError:
            pass  # caching is an optimisation, never a requirement
        return build

    @staticmethod
    def _read_cache(path: Path) -> dict | None:
        """A cached entry, read only if it is small enough to be one.

        A cache file is written by us, but read back defensively: a tampered
        or truncated file must fall back to a refetch, never allocate.
        """
        try:
            if path.stat().st_size > _CACHE_READ_MAX_BYTES:
                return None
            data = json.loads(path.read_text())
        except (OSError, ValueError):
            return None
        if not isinstance(data, dict):
            return None
        if not all(k in data for k in
                   ("package", "version", "files", "pkgbuild", "files_text")):
            return None  # a pre-``files_text`` cache entry; refetch
        return data
