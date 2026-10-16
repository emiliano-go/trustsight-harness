import pytest

from harness import surface
from harness.mcp import server


def test_fp_cli_aliases_and_json_files(tmp_path):
    evidence = tmp_path / "evidence.json"
    evidence.write_text('{"packages": []}')
    args = surface.cli_parser("fp_report").parse_args([
        "--evidence", str(evidence), "--verdicts", '{"findings": []}',
        "--synthetic-diff", "actual text"])
    assert args.evidence == {"packages": []}
    assert args.verdicts == {"findings": []}
    assert args.synthetic_diff == "actual text"
    for flag in ("--alert-slug", "--alert_slug"):
        assert surface.cli_parser("fp_triage").parse_args([flag, "slug"]).alert_slug == "slug"
    assert surface.cli_parser("fp_verify").parse_args([
        "--report-path", "benign/fp-test/triage.json"]).report_path.endswith("triage.json")


@pytest.mark.parametrize("value", ["[]", "null", "1", "{bad"])
def test_dict_cli_requires_json_object(value):
    with pytest.raises(SystemExit):
        surface.cli_parser("fp_report").parse_args([
            "--evidence", value, "--verdicts", "{}"])


def test_postponed_type_conversions():
    assert surface.cli_parser("feed_search").parse_args(["--limit", "7"]).limit == 7
    args = surface.cli_parser("judge_verdict").parse_args([
        "--report-body", "{}", "--flag-threshold", "35", "--mode-gaps", "tree_not_analyzed"])
    assert args.report_body == {}
    assert args.flag_threshold == 35
    assert args.mode_gaps == ["tree_not_analyzed"]


def test_wrappers_delegate(monkeypatch, tmp_path):
    from harness import fp_report, fp_triage

    monkeypatch.setattr(server, "REPO_ROOT", tmp_path)
    feed, aur = object(), object()
    monkeypatch.setattr(server, "_feed_client", lambda: feed)
    monkeypatch.setattr(server, "_aur_client", lambda: aur)
    def triage(slug, *, feed_client, aur_client):
        assert (slug, feed_client, aur_client) == ("slug", feed, aur)
        return {"packages": []}
    def report(root, evidence, verdicts, synthetic_diff=None):
        assert (root, evidence, verdicts, synthetic_diff) == (tmp_path, {}, {}, "diff text")
        return {"report_path": "report"}
    monkeypatch.setattr(fp_triage, "triage_alert", triage)
    monkeypatch.setattr(fp_report, "write_report", report)
    assert server.fp_triage("slug") == {"packages": []}
    assert server.fp_report({}, {}, "diff text") == {"report_path": "report"}


def test_module_entrypoint_registers_fp_tools_before_running(monkeypatch):
    import runpy

    names = set()
    class FakeMCP:
        def __init__(self, *args, **kwargs):
            pass

        def tool(self, *args, **kwargs):
            def register(fn):
                names.add(fn.__name__)
                return fn
            return register

        def resource(self, *args, **kwargs):
            return lambda fn: fn

        def run(self, **kwargs):
            assert {"fp_triage", "fp_report", "fp_verify"} <= names

    monkeypatch.setattr("mcp.server.mcpserver.MCPServer", FakeMCP)
    with pytest.warns(RuntimeWarning, match="found in sys.modules"):
        runpy.run_module("harness.mcp.server", run_name="__main__")
