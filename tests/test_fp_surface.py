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
    from harness import fp_agent, fp_agent_pr, fp_report, fp_triage

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
    def verify(verdict, *, aur_client, feed_client):
        assert (verdict, aur_client, feed_client) == ({}, aur, feed)
        return {"verified": True}
    def render(result, *, target_repo, date, repo_root=None):
        assert (result, target_repo, date) == ({}, "trustsight", "2026-10-16")
        assert repo_root in (None, "")  # default: resolved from the env
        return {"branch": "b"}
    monkeypatch.setattr(fp_triage, "triage_alert", triage)
    monkeypatch.setattr(fp_report, "write_report", report)
    monkeypatch.setattr(fp_agent, "verify_agent_verdict", verify)
    monkeypatch.setattr(fp_agent_pr, "render_pr_content", render)
    assert server.fp_triage("slug") == {"packages": []}
    assert server.fp_report({}, {}, "diff text") == {"report_path": "report"}
    assert server.fp_agent_verify({}) == {"verified": True}
    assert server.fp_agent_pr({}, "trustsight", "2026-10-16") == {"branch": "b"}
    assert server.fp_agent_alert({"kind": "TP", "verified": True, "package": "x",
                                  "ioc_entries": []})["event"] == "trustsight.confirmed-ioc"


def test_agent_wrappers_report_errors(monkeypatch):
    from harness import fp_agent

    def boom(verdict, *, aur_client, feed_client):
        raise fp_agent.ValidationError("bad verdict")
    monkeypatch.setattr(fp_agent, "verify_agent_verdict", boom)
    result = server.fp_agent_verify({})
    assert result["error"] == "bad verdict"


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
            assert {"fp_triage", "fp_report", "fp_verify", "fp_agent_verify",
                    "fp_agent_pr", "fp_agent_alert"} <= names

    monkeypatch.setattr("mcp.server.mcpserver.MCPServer", FakeMCP)
    with pytest.warns(RuntimeWarning, match="found in sys.modules"):
        runpy.run_module("harness.mcp.server", run_name="__main__")
