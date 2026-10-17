"""The AUR client: RPC parsing, snapshot reading, caching, and confinement."""

from __future__ import annotations

import io
import tarfile

import httpx
import pytest

from harness import net
from harness.aur import (
    _CACHE_READ_MAX_BYTES,
    _MAX_FIELD_BYTES,
    _MAX_MEMBERS,
    _MAX_RESULTS,
    MAX_INFO_NAMES,
    AurClient,
    AurError,
    _chunks,
    _validate,
)

RECORD = {
    "ID": 1, "Name": "some-pkg", "PackageBase": "some-pkg",
    "Version": "1.2-1", "Description": "a package", "URL": "https://up.test",
    "NumVotes": 3, "Popularity": 0.5, "OutOfDate": None, "Maintainer": "someone",
    "LastModified": 1700000000, "URLPath": "/cgit/aur.git/snapshot/some-pkg.tar.gz",
}


def _snapshot(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, text in files.items():
            data = text.encode()
            info = tarfile.TarInfo(name=f"some-pkg/{name}")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


class _AurServer:
    def __init__(self, *, record=RECORD, snapshot=None, info_status=200,
                 snapshot_status=200, info_body=None):
        self.record = record
        self.snapshot = snapshot if snapshot is not None else _snapshot(
            {"PKGBUILD": "pkgname=some-pkg\n", "some-pkg.install": "true\n"})
        self.info_status = info_status
        self.snapshot_status = snapshot_status
        self.info_body = info_body
        self.info_calls = 0
        self.snapshot_calls = 0
        self.urls: list[str] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.urls.append(str(request.url))
        if request.url.path == "/rpc/v5/info":
            self.info_calls += 1
            if self.info_body is not None:
                return httpx.Response(self.info_status, json=self.info_body)
            if self.record is None:
                return httpx.Response(self.info_status, json={"type": "multiinfo", "results": []})
            return httpx.Response(self.info_status,
                                  json={"type": "multiinfo", "results": [self.record]})
        if request.url.path.endswith(".tar.gz"):
            self.snapshot_calls += 1
            return httpx.Response(self.snapshot_status, content=self.snapshot)
        return httpx.Response(404)


def _client(server, tmp_path):
    fetcher = net.Fetcher(http=httpx.Client(transport=httpx.MockTransport(server)), max_retries=0)
    return AurClient(fetcher=fetcher, cache_root=tmp_path)


def test_validate_rejects_bad_names():
    for name in ("", ".", "..", "a/b", "a b", "-leading", "a;rm"):
        with pytest.raises(AurError):
            _validate(name)
    assert _validate("some-pkg") == "some-pkg"


def test_chunks_split_to_fit_the_caps():
    names = [f"pkg-{i:04d}" for i in range(450)]
    chunks = _chunks(names)
    assert all(len(c) <= 200 for c in chunks)
    assert sum(len(c) for c in chunks) == len(names)


def test_info_returns_records_keyed_by_name_and_base(tmp_path):
    server = _AurServer()
    records = _client(server, tmp_path).info(["some-pkg"])
    assert records["some-pkg"]["Version"] == "1.2-1"
    assert records["some-pkg"]["PackageBase"] == "some-pkg"


def test_info_rejects_a_bad_name_without_a_request(tmp_path):
    server = _AurServer()
    with pytest.raises(AurError):
        _client(server, tmp_path).info(["bad/name"])
    assert server.info_calls == 0


def test_info_surfaces_an_rpc_error(tmp_path):
    server = _AurServer(info_body={"type": "error", "error": "Incorrect by field"})
    with pytest.raises(AurError, match="Incorrect by field"):
        _client(server, tmp_path).info(["some-pkg"])


def test_pkgbuild_reads_the_snapshot(tmp_path):
    server = _AurServer()
    build = _client(server, tmp_path).pkgbuild("some-pkg")
    assert build.package == "some-pkg"
    assert build.version == "1.2-1"
    assert build.pkgbuild == "pkgname=some-pkg\n"
    assert build.files == ["PKGBUILD", "some-pkg.install"]
    assert build.files_text == {"some-pkg.install": "true\n"}
    assert build.cached is False
    assert all(u.startswith("https://aur.archlinux.org/") for u in server.urls)


def test_pkgbuild_keeps_the_other_build_files(tmp_path):
    server = _AurServer(snapshot=_snapshot({
        "PKGBUILD": "pkgname=x\n",
        ".SRCINFO": "pkgbase = x\n",
        "x.install": "post_install() { :; }\n",
        "blob.bin": "\x00\x01\x02",
    }))
    build = _client(server, tmp_path).pkgbuild("some-pkg")
    assert build.files_text[".SRCINFO"] == "pkgbase = x\n"
    assert build.files_text["x.install"] == "post_install() { :; }\n"
    assert "blob.bin" in build.files
    assert "blob.bin" not in build.files_text


def test_pkgbuild_is_cached_by_version(tmp_path):
    server = _AurServer()
    client = _client(server, tmp_path)
    client.pkgbuild("some-pkg")
    second = client.pkgbuild("some-pkg")
    assert second.cached is True
    assert server.snapshot_calls == 1  # the snapshot is fetched once


def test_pkgbuild_when_the_package_is_absent(tmp_path):
    server = _AurServer(record=None)
    with pytest.raises(AurError, match="not found"):
        _client(server, tmp_path).pkgbuild("some-pkg")


def test_pkgbuild_a_missing_snapshot_is_an_error(tmp_path):
    server = _AurServer(snapshot_status=404)
    with pytest.raises(AurError, match="no snapshot"):
        _client(server, tmp_path).pkgbuild("some-pkg")


def test_snapshot_member_escaping_is_refused(tmp_path):
    evil = _snapshot({"PKGBUILD": "x", "../etc/passwd": "root"})
    server = _AurServer(snapshot=evil)
    with pytest.raises(AurError, match="escapes"):
        _client(server, tmp_path).pkgbuild("some-pkg")


def test_snapshot_without_a_pkgbuild_is_refused(tmp_path):
    server = _AurServer(snapshot=_snapshot({"README": "hi"}))
    with pytest.raises(AurError, match="no PKGBUILD"):
        _client(server, tmp_path).pkgbuild("some-pkg")


def test_snapshot_not_a_tarball_is_refused(tmp_path):
    server = _AurServer(snapshot=b"not a tarball")
    with pytest.raises(AurError, match="tarball"):
        _client(server, tmp_path).pkgbuild("some-pkg")


# ---------------------------------------------------------------------------
# Hardening: the AUR client is never unbounded
# ---------------------------------------------------------------------------


def test_info_refuses_more_than_the_name_cap(tmp_path):
    server = _AurServer()
    too_many = [f"pkg-{i}" for i in range(MAX_INFO_NAMES + 1)]
    with pytest.raises(AurError, match="at most"):
        _client(server, tmp_path).info(too_many)
    assert server.info_calls == 0


def test_info_caps_the_parsed_result_count(tmp_path):
    rows = [{"Name": f"pkg-{i}", "PackageBase": f"pkg-{i}"} for i in range(_MAX_RESULTS + 1)]
    server = _AurServer(info_body={"type": "multiinfo", "results": rows})
    with pytest.raises(AurError, match="more than"):
        _client(server, tmp_path).info(["some-pkg"])


def test_info_truncates_long_fields(tmp_path):
    record = {**RECORD, "Description": "x" * 10_000}
    server = _AurServer(record=record)
    records = _client(server, tmp_path).info(["some-pkg"])
    assert len(records["some-pkg"]["Description"]) == _MAX_FIELD_BYTES


def test_a_name_longer_than_the_cap_is_refused():
    with pytest.raises(AurError):
        _validate("a" * 300)


def test_snapshot_with_too_many_members_is_refused(tmp_path):
    files = {f"file-{i}": "x" for i in range(_MAX_MEMBERS + 1)}
    server = _AurServer(snapshot=_snapshot(files))
    with pytest.raises(AurError, match="too many members"):
        _client(server, tmp_path).pkgbuild("some-pkg")


def test_an_oversized_cache_entry_is_ignored(tmp_path):
    path = tmp_path / "big.json"
    path.write_text("0" * (_CACHE_READ_MAX_BYTES + 1))
    assert AurClient._read_cache(path) is None


def test_a_malformed_cache_entry_is_ignored(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text('{"package": "x"}')
    assert AurClient._read_cache(path) is None
