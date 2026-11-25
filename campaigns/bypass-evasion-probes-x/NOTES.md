# X-series bypass probes

28 rules, 56 cells: every control fires the rule and every bypass leaves it
silent. Measured 24/11/26 on TrustSight 0.30.0 through `harness analyze_diff`
(`db_state: cold`, `flag_threshold: 20`). A run of this campaign gives 56/56
expected outcomes.

| Rule | Evasion | Fix |
|---|---|---|
| X001 | hex-escaped payload in a scalar, `printf '%b' "$_p" \| bash`; the lookahead only reads the raw line | resolve `%b`/scalar escapes before the decode-to-shell check |
| X003 | hex host in `_h`; `curl "http://${_h}/p"` | resolve scalars before the encoded-host test |
| X004 | `TERM="d"umb` (partial quote) | accept quote-concatenated values |
| X005 | home path in `_h`, write in a later line with no literal alias | resolve scalar paths before the home-alias match |
| X006 | shortener host in `_s` | resolve scalars before the shortened-URL match |
| X007 | aggregate of >=2 techniques; dodge every constituent | derived: no cluster can form, fix the constituents |
| X008 | U+180E (invisible but no longer `White_Space`) | add U+180E..U+200F to the deceptive-space class explicitly |
| X009 | client behind `${_clients[$i]}` (unknown index) | treat an unresolved subscript as an unknown client, not as raw text |
| X010 | python network body in `_py`; `python3 -c "$_py"` | resolve `-c "$var"` |
| X011 | manager in `_m`; `"$_m" install` | resolve scalar command words |
| X012 | `CC="$PWD/mcc"` | add `$PWD`/`${PWD}` to the build-dir alternatives |
| X013 | `printf -v HTTPS_PROXY '%s' 'http://…'` | treat `printf -v` as an assignment |
| X015 | `systemctl --now enable` | allow options between `systemctl` and the verb |
| X016 | dynamic-subscript client piped to `gcc` | resolve the subscript before the consumer test |
| X017 | `find . -print0 \| xargs -0 sh -c …` instead of `-exec` | treat `xargs sh -c` as a find executor |
| X018 | `python3 -c 'c="sh"; os.system(c)'` | treat an upper-case exec call on an assembled name as execution |
| X019 | `hostname \| tee "$pkgdir/etc/host-id"` | allow `tee` as a write sink |
| X020 | heredoc target via `$_mf=Makefile` | resolve the heredoc destination before the manifest check |
| X021 | `bash "$(ls "$srcdir/scripts/run.sh")"` | allow command substitution naming the script |
| X022 | `cat "$_d/x.conf.in" > x.conf` with `_d="$srcdir"` | resolve the payload prefix held in a scalar |
| X023 | sink is `busybox sh` | add `busybox` to the script-executor list |
| X024 | `printf -v LD_PRELOAD '%s' "$_p"` | treat `printf -v` as an assignment |
| X025 | `function cp` with the brace on the next line | accept both function spellings |
| X029 | 300-char blob split into two ~150-char scalars | join adjacent literals, or lower the 256-char floor |
| X030 | command word split as `$'\x73'$'\x68'` (1 escape each) | count escapes across adjacent ANSI-C tokens |
| X031 | `dd if="$srcdir/PKGBUILD" \| bash` | add `dd`/`od`/`xxd` to the self-read readers |
| X032 | splice via `c"$_x"rl` | include `$var` inside the quoted-span shape |
| X034 | fetch and executor split across lines | correlate adjacent fetch/exec lines |

## Exclusions

- **X002 rejected**: the bypass `curl""` is an obfuscated *literal* name, not
  the "executable name is not a literal" case the rule claims. A partial-quote
  control `cu"rl"` does not fire X002 either, so no same-behaviour pair exists;
  R001 catches the pipeline.
- **X026/X027**: refusal boundaries over unresolved assignments; not exercised.
- **X028**: needs the previous-commit diff (`pattern_across_commits`); outside
  the `analyze_diff` oracle.
- **X033**: no dedicated dodge found within the budget.
- **X035**: not in the installed registry (X ends at X034).
- **X014** excluded as already known.

## Control caveat

`npm install` inside `build()` emits the `unpinned_build_deps` gap, which the
Judge reads as `fail_closed_catch` before the score check. The X011 control is
therefore placed in `post_install()`, where the rule fires with only the
`tree_not_analyzed` mode gap.
