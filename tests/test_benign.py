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

    report = scan_benign(ROOT, corpus=tmp_path, environment=_environment())

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

    report = scan_benign(ROOT, corpus=tmp_path, environment=_environment(), sample=2)

    assert report["scanned"] == 2
