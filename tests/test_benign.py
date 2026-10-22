"""The benign scan: a false-positive measurement, not a campaign."""

from __future__ import annotations

import difflib
from pathlib import Path

import yaml

from harness.benign import scan_benign

ROOT = Path(__file__).resolve().parent.parent

_BASE = """\
pkgname=harness-benign
pkgver=1.0.0
pkgrel=1
pkgdesc="benign"
arch=('any')
url="https://github.com/example/harness-benign"
license=('MIT')
source=("https://github.com/example/harness-benign/archive/v1.0.0.tar.gz")
sha256sums=('0000000000000000000000000000000000000000000000000000000000000000')

build() {
  cd "$srcdir/harness-benign-1.0.0"
  make
}
"""


def _diff(new: str) -> str:
    return "".join(difflib.unified_diff(
        _BASE.splitlines(keepends=True), new.splitlines(keepends=True),
        fromfile="a/PKGBUILD", tofile="b/PKGBUILD"))


def _environment() -> dict:
    return yaml.safe_load((ROOT / "defaults" / "environment.yml").read_text())


def test_a_benign_bump_is_not_flagged_and_a_chain_is(tmp_path):
    (tmp_path / "benign-pkg__a..b.diff").write_text(_diff(_BASE.replace("1.0.0", "1.0.1")))
    (tmp_path / "evil-pkg__a..b.diff").write_text(_diff(
        _BASE + '\npost_install() {\n  echo aGVsbG8= | base64 -d | bash\n}\n'))

    report = scan_benign(ROOT, corpus=tmp_path, environment=_environment(),
                         use_cache=False)

    assert report["scanned"] == 2
    assert report["flag_rate"]["denominator_value"] == 2
    assert report["flagged"] >= 1, "the injected chain must be flagged"
    # Addendum 5 §4: the layer-resilience view rides beside the flag rate.
    assert "minimum_layer_cut" in report
    assert isinstance(report["single_layer_failure"], dict)


def test_sampling_scans_a_subset(tmp_path):
    for i in range(4):
        (tmp_path / f"pkg{i}__a..b.diff").write_text(
            _diff(_BASE.replace("1.0.0", f"1.0.{i}")))

    report = scan_benign(ROOT, corpus=tmp_path, environment=_environment(),
                         sample=2, use_cache=False)

    assert report["scanned"] == 2


def _corpus(path: Path, count: int = 4) -> Path:
    path.mkdir()
    for i in range(count):
        (path / f"pkg{i}__a..b.diff").write_text(
            _diff(_BASE.replace("1.0.0", f"1.0.{i}")))
    return path


def test_parallel_and_serial_scans_produce_the_same_report(tmp_path):
    corpus = _corpus(tmp_path / "corpus")
    serial = scan_benign(ROOT, corpus=corpus, environment=_environment(),
                         jobs=1, use_cache=False)
    parallel = scan_benign(ROOT, corpus=corpus, environment=_environment(),
                           jobs=2, use_cache=False)
    assert parallel == serial


def test_a_second_identical_scan_comes_from_the_cache(tmp_path, monkeypatch):
    from harness import benign

    corpus = _corpus(tmp_path / "corpus")
    cache = tmp_path / "cache.jsonl"
    kwargs = {"corpus": corpus, "environment": _environment(),
              "cache_path": cache}
    first = scan_benign(ROOT, **kwargs)

    def no_scan(*_args, **_kwargs):
        raise AssertionError("the cache hit must not rescan")

    monkeypatch.setattr(benign, "_plan", no_scan)
    assert scan_benign(ROOT, **kwargs) == first


def test_the_cache_misses_when_the_corpus_changes(tmp_path):
    corpus = _corpus(tmp_path / "corpus")
    cache = tmp_path / "cache.jsonl"
    kwargs = {"corpus": corpus, "environment": _environment(),
              "cache_path": cache}
    assert scan_benign(ROOT, **kwargs)["scanned"] == 4

    (corpus / "pkg-new__a..b.diff").write_text(
        _diff(_BASE.replace("1.0.0", "1.0.9")))
    assert scan_benign(ROOT, **kwargs)["scanned"] == 5


def test_the_cache_misses_on_a_parameter_change(tmp_path):
    corpus = _corpus(tmp_path / "corpus")
    cache = tmp_path / "cache.jsonl"
    common = {"corpus": corpus, "environment": _environment(),
              "cache_path": cache}
    assert scan_benign(ROOT, sample=1, **common)["sample"] == 1
    assert scan_benign(ROOT, sample=2, **common)["sample"] == 2
    assert scan_benign(ROOT, threshold=1000, **common)["flagged"] == 0


def test_no_cache_neither_reads_nor_writes(tmp_path):
    corpus = _corpus(tmp_path / "corpus")
    cache = tmp_path / "cache.jsonl"
    report = scan_benign(ROOT, corpus=corpus, environment=_environment(),
                         cache_path=cache, use_cache=False)
    assert report["scanned"] == 4
    assert not cache.exists()
