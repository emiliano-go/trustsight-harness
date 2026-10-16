import copy
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
import yaml

from harness.fp_report import write_report

DIFF = '--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1 +1 @@\n-pkgver=1\n+pkgver=2\n'


def inputs(slug="2026-10-16/142307", name="example-bin"):
    return ({"alert_slug": slug, "packages": [{"package": name, "score": 55,
             "findings": [{"rule_id": "C024", "reason": "phantom", "checks": {}}]}]},
            {"findings": [{"index": 0, "rule_id": "C024", "verdict": "FP", "confidence": .95,
                           "reasoning": "absent", "suggested_fix": "check files"}],
             "summary": "False positive", "root_causes": ["phantom"]})


def load(result):
    return json.loads(Path(result["triage_path"]).read_text())


def test_merge_idempotence_and_environment(tmp_path):
    evidence, verdicts = inputs()
    first = write_report(tmp_path, evidence, verdicts, DIFF)
    assert write_report(tmp_path, evidence, verdicts, DIFF) == first
    assert len(load(first)["entries"]) == 1
    environment = Path(first["triage_path"]).with_name("environment.yml")
    env = yaml.safe_load(environment.read_text())
    assert set(env) == {"flag_threshold", "db_state", "trustsight_version"}
    assert env["flag_threshold"] == 35 and env["db_state"] == "cold"
    assert env["trustsight_version"]
    environment.write_text("preserve me\n")
    second = write_report(tmp_path, evidence, verdicts, DIFF.replace("pkgver=2", "pkgver=3"))
    assert len(load(second)["entries"][0]["corpus_paths"]) == 2
    assert environment.read_text() == "preserve me\n"
    other = write_report(tmp_path, *inputs("2026-10-16/152307"))
    assert other["report_path"] != first["report_path"]
    assert len(load(other)["entries"]) == 2
    assert Path(first["report_path"]).exists()


def test_no_implicit_corpus_and_multi_package(tmp_path):
    evidence, verdicts = inputs()
    evidence["packages"] += inputs(name="other")[0]["packages"]
    with pytest.raises(ValueError):
        write_report(tmp_path, evidence, verdicts)
    verdicts["findings"][0]["package"] = "example-bin"
    one = write_report(tmp_path, evidence, verdicts, DIFF)
    assert one["corpus_path"]
    other = copy.deepcopy(verdicts["findings"][0])
    other["package"] = "other"
    verdicts["findings"].append(other)
    with pytest.raises(ValueError):
        write_report(tmp_path, evidence, verdicts, DIFF)
    result = write_report(tmp_path, evidence, verdicts)
    assert result["report_path"] is None and len(result["report_paths"]) == 2
    assert result["corpus_path"] is None
    assert len(list(tmp_path.rglob("*.diff"))) == 1
    assert all(Path(p).exists() for p in result["report_paths"])


@pytest.mark.parametrize("verdict", ["FP", "TP-but-benign", "overweighted", "TP", "uncertain"])
def test_corpus_classification(tmp_path, verdict):
    evidence, verdicts = inputs()
    verdicts["findings"][0]["verdict"] = verdict
    if verdict in {"TP", "uncertain"}:
        with pytest.raises(ValueError):
            write_report(tmp_path, evidence, verdicts, DIFF)
        assert write_report(tmp_path, evidence, verdicts)["corpus_path"] is None
    else:
        assert write_report(tmp_path, evidence, verdicts, DIFF)["corpus_path"]


@pytest.mark.parametrize("field,value", [("confidence", float("nan")), ("confidence", float("inf")),
    ("confidence", -.1), ("confidence", 1.1), ("confidence", True), ("index", True),
    ("index", -1), ("index", 5), ("rule_id", "R007"), ("verdict", "benign")])
def test_invalid_verdict(tmp_path, field, value):
    evidence, verdicts = inputs()
    verdicts["findings"][0][field] = value
    with pytest.raises(ValueError):
        write_report(tmp_path, evidence, verdicts)
    assert not (tmp_path / "benign").exists()


@pytest.mark.parametrize("invalid", ["evidence", "verdicts", "package", "finding", "reasoning"])
def test_invalid_object_types(tmp_path, invalid):
    evidence, verdicts = inputs()
    if invalid == "evidence":
        evidence = []
    elif invalid == "verdicts":
        verdicts = []
    elif invalid == "package":
        evidence["packages"] = [None]
    elif invalid == "finding":
        verdicts["findings"] = [None]
    else:
        verdicts["findings"][0]["reasoning"] = []
    with pytest.raises(TypeError):
        write_report(tmp_path, evidence, verdicts)
    assert not (tmp_path / "benign").exists()


@pytest.mark.parametrize("slug", ["../escape", "2026-02-30/120000", "2026-10-16/250000", "2026-10-16/120000-../../x"])
def test_invalid_slug(tmp_path, slug):
    with pytest.raises(ValueError):
        write_report(tmp_path, *inputs(slug))


@pytest.mark.parametrize("name", ["../escape", "/tmp/escape", ".", "..", "a/b", ""])
def test_invalid_package(tmp_path, name):
    with pytest.raises(ValueError):
        write_report(tmp_path, *inputs(name=name))


@pytest.mark.parametrize("diff", ["", "\0", "--- a/../../escape\n", "+++ /tmp/escape\n", "a" * (512 * 1024 + 1)])
def test_unsafe_diff(tmp_path, diff):
    with pytest.raises(ValueError):
        write_report(tmp_path, *inputs(), diff)


def test_duplicate_and_incomplete_findings(tmp_path):
    evidence, verdicts = inputs()
    verdicts["findings"] *= 2
    with pytest.raises(ValueError):
        write_report(tmp_path, evidence, verdicts)
    verdicts["findings"] = verdicts["findings"][:1]
    evidence["packages"][0]["findings"].append({"rule_id": "R007"})
    with pytest.raises(ValueError):
        write_report(tmp_path, evidence, verdicts, DIFF)


@pytest.mark.parametrize("target", ["benign", "date", "triage.json", "environment.yml", "report", "corpus", ".triage.lock"])
def test_symlinks_rejected(tmp_path, target):
    root = tmp_path / "repo"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    marker = outside / "marker"
    marker.write_text("untouched")
    if target == "benign":
        (root / "benign").symlink_to(outside, target_is_directory=True)
    elif target == "date":
        (root / "benign").mkdir()
        (root / "benign/fp-2026-10-16").symlink_to(outside, target_is_directory=True)
    else:
        result = write_report(root, *inputs(), DIFF)
        path = (Path(result["report_path"]) if target == "report" else
                Path(result["corpus_path"]) if target == "corpus" else
                Path(result["triage_path"]).with_name(target))
        path.unlink()
        path.symlink_to(marker)
    with pytest.raises((ValueError, OSError)):
        write_report(root, *inputs(), DIFF)
    assert marker.read_text() == "untouched"
    assert list(outside.iterdir()) == [marker]


@pytest.mark.parametrize("bad", ["{", "[]", '{"schema_version": 1, "threshold": 35, "entries": [{}]}'])
def test_malformed_old_triage_preserved(tmp_path, bad):
    result = write_report(tmp_path, *inputs())
    path = Path(result["triage_path"])
    path.write_text(bad)
    with pytest.raises(ValueError):
        write_report(tmp_path, *inputs(), DIFF)
    assert path.read_text() == bad
    assert not list(tmp_path.rglob("*.diff"))


def test_concurrent_merges(tmp_path):
    def persist(index):
        return write_report(tmp_path, *inputs(f"2026-10-16/1200{index:02}"))
    with ThreadPoolExecutor(max_workers=5) as pool:
        results = list(pool.map(persist, range(10)))
    assert len(load(results[0])["entries"]) == 10


@pytest.mark.parametrize("replacement", ["TP", "uncertain"])
def test_corpus_cannot_be_retained_with_suspicious_verdict(tmp_path, replacement):
    evidence, verdicts = inputs()
    result = write_report(tmp_path, evidence, verdicts, DIFF)
    before = {p: p.read_bytes() for p in Path(result["triage_path"]).parent.iterdir()}
    verdicts["findings"][0]["verdict"] = replacement
    with pytest.raises(ValueError, match="retaining corpus"):
        write_report(tmp_path, evidence, verdicts)
    assert all(p.read_bytes() == content for p, content in before.items())


def test_partial_judgments_merge_before_corpus_validation(tmp_path):
    evidence, verdicts = inputs()
    evidence["packages"][0]["findings"].append({"rule_id": "R007", "reason": "header"})
    result = write_report(tmp_path, evidence, verdicts)
    second = copy.deepcopy(verdicts)
    second["findings"][0].update(index=1, rule_id="R007", verdict="TP-but-benign")
    result = write_report(tmp_path, evidence, second, DIFF)
    entry = load(result)["entries"][0]
    assert [f["index"] for f in entry["verdicts"]["findings"]] == [0, 1]
    verdicts["findings"][0]["verdict"] = "overweighted"
    result = write_report(tmp_path, evidence, verdicts)
    assert [f["verdict"] for f in load(result)["entries"][0]["verdicts"]["findings"]] == ["overweighted", "TP-but-benign"]
    assert "R007" in Path(result["report_path"]).read_text()


@pytest.mark.parametrize("corpus", [False, True])
@pytest.mark.parametrize("change", ["finding", "version", "metadata"])
def test_changed_evidence_rejected_without_reset(tmp_path, corpus, change):
    evidence, verdicts = inputs()
    result = write_report(tmp_path, evidence, verdicts, DIFF if corpus else None)
    original = Path(result["triage_path"]).read_bytes()
    if change == "finding":
        evidence["packages"][0]["findings"].append({"rule_id": "R007"})
    elif change == "version":
        evidence["packages"][0]["aur_version"] = "new version"
    else:
        evidence["source"] = "different alert provenance"
    with pytest.raises(ValueError, match="changed evidence"):
        write_report(tmp_path, evidence, verdicts)
    assert Path(result["triage_path"]).read_bytes() == original


def test_full_provenance_preserved_on_refetch(tmp_path):
    evidence, verdicts = inputs()
    evidence.update(fetched_at="2026-10-16T15:00:00Z", producer={"version": 2}, raw_alert={"x": [1, 2]})
    evidence["packages"][0]["raw_snapshot"] = {"files": ["PKGBUILD"], "text": "original"}
    original = copy.deepcopy(evidence)
    result = write_report(tmp_path, evidence, verdicts)
    package = load(result)["entries"][0]["evidence"]
    assert package["alert_slug"] == evidence["alert_slug"]
    assert package["fetched_at"] == evidence["fetched_at"]
    assert package["bundle"] == {k: v for k, v in original.items() if k != "packages"}
    assert all(package[k] == v for k, v in original["packages"][0].items())
    assert evidence == original
    evidence["fetched_at"] = "2026-10-16T16:00:00Z"
    result = write_report(tmp_path, evidence, verdicts)
    assert load(result)["entries"][0]["evidence"] == package


def test_report_identity_cannot_collide(tmp_path):
    first = write_report(tmp_path, *inputs("2026-10-16/120000-130000", "demo"))
    before = Path(first["report_path"]).read_bytes()
    second = write_report(tmp_path, *inputs("2026-10-16/130000", "demo-120000"))
    assert first["report_path"] != second["report_path"]
    assert Path(first["report_path"]).read_bytes() == before
    assert len(load(second)["entries"]) == 2


def test_duplicate_old_report_name_rejected(tmp_path):
    first = write_report(tmp_path, *inputs())
    second = write_report(tmp_path, *inputs("2026-10-16/130000"))
    triage = load(second)
    triage["entries"][1]["report_path"] = triage["entries"][0]["report_path"]
    path = Path(first["triage_path"])
    path.write_text(json.dumps(triage))
    before = path.read_bytes()
    with pytest.raises(ValueError, match="artifact names"):
        write_report(tmp_path, *inputs())
    assert path.read_bytes() == before


@pytest.mark.parametrize("diff", [
    "not a diff", "@@ -1 +1 @@\n-a\n+b\n", "--- a/PKGBUILD\n+++ b/PKGBUILD\n",
    "--- a/PKGBUILD\n@@ -1 +1 @@\n-a\n+b\n", DIFF.replace("+++ b/PKGBUILD\n", ""),
    DIFF.replace("@@ -1 +1 @@", "@@ -1,2 +1 @@"),
    DIFF.replace("@@ -1 +1 @@", "@@ -1 +1,2 @@"),
    DIFF.replace("@@ -1 +1 @@", "@@ nonsense @@"), DIFF + "+extra\n",
    DIFF + "--- a/other\n+++ b/other\n@@ -1,2 +1 @@\n-a\n+b\n",
    DIFF + "--- a/other\n+++ b/other\n", DIFF + "junk\n",
    "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1 +1 @@\n same\n",
    "--- a/PKGBUILD\n+++ b/PKGBUILD\n@@ -1 +1 @@\n-same\n+same\n",
])
def test_malformed_unified_diffs_rejected(tmp_path, diff):
    with pytest.raises(ValueError):
        write_report(tmp_path, *inputs(), diff)
    assert not (tmp_path / "benign").exists()


@pytest.mark.parametrize("diff", [DIFF, DIFF + DIFF.replace("PKGBUILD", "example.install"),
    "diff --git a/PKGBUILD b/PKGBUILD\nindex abc123..def456 100644\n" + DIFF,
    "--- /dev/null\n+++ b/PKGBUILD\n@@ -0,0 +1 @@\n+pkgver=2\n",
    "--- a/PKGBUILD\n+++ /dev/null\n@@ -1 +0,0 @@\n-pkgver=1\n",
    DIFF.rstrip() + "\n\\ No newline at end of file\n",
])
def test_valid_structural_diffs(tmp_path, diff):
    assert write_report(tmp_path, *inputs(), diff)["corpus_path"]
