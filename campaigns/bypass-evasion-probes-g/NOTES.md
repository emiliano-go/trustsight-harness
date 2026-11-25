# G-series bypass probes

Correlation rules do not run through `analyze_diff`; they run in the
`correlation` lane over a JSON payload of package records. Each shape below is
a control cell (`expect_fire`) followed by a bypass cell (`expect_absent`), and
a run of this campaign produces 34/34 expected outcomes: 17 controls detected,
17 bypasses (rule silent) across 15 rules, with G001 and G010 carrying two
shapes each.

Measured 24/11/26 on TrustSight 0.30.0, `db_state: cold`.

| Rule | Evasion | Matcher | Required matcher change |
|---|---|---|---|
| G001 | Split one host across `evilcdn.example` and `evilcdn.example:8443` (3+2) so no group reaches `min_packages=5`; or name the five packages one family (`evil-i18n-aa`…) under one maintainer so `_one_name_family` stands the group down. | `analysis/correlation.py:161` `shared_gained_host` | Group by registrable domain after dropping the port (or canonicalise the port away) before the join; the correlation is host-level, not port-level. |
| G002 | Same 300-char hex literal spelled lowercase in one package and uppercase in the other; the join key is sha256 of the exact text. | `analysis/correlation.py:233` `shared_added_literal` | Fold case for hex/base64-shaped literals (or hash the decoded bytes) before the digest join. |
| G004 | Same dependency and same host, host spelling differs only by case (`cdn.example` vs `CDN.EXAMPLE`); the join is the raw (name, host) tuple. | `analysis/correlation.py:421` | Case-fold the host (DNS is case-insensitive) before the join. |
| G005 | Same impersonation campaign split across an invisible character in the maintainer key (`evil` vs `evil\u200b`), so each group stays below `min_members=3`. | `analysis/correlation.py:460` | Strip zero-width/format characters from the maintainer key before grouping. |
| G003 | Give every adopted package the same `previous_maintainer`; the predecessor-rename stand-down then excuses a coordinated takeover. | `analysis/correlation.py:311` `coordinated_adoption` | The stand-down must require evidence of a rename (same pkgbase/related names or one predecessor handle matching the new one), not merely a shared predecessor. |
| G006 | Scope holds `campaign.example`, the record gains `campaign.example:8443`; the comparison is raw string. | `full_aur/_pipeline_helpers.py:528` | Canonicalise both sides (as G001 does) before the scope intersection. |
| G007 | Scope URL `https://scheme.example/x.sh`, gained URL `http://scheme.example/x.sh` (or `:8443`); `canonical_payload_url` keeps scheme and port. | `analysis/pipeline/_analyze_helpers.py:93` | Canonicalise scheme/port for campaign-scope matching; the endpoint is the same. |
| G008 | An aged sockpuppet: one prior maintainer event 400+ days ago puts `first_seen` outside the novelty window, so the burst stands down. | `analysis/correlation.py:505` | Novelty should key on the first event *of this adoption burst*, or treat a long-dormant account taking over many dormant packages as novel. |
| G010 | Same port split as G001, through the contacts lane; the same name-family stand-down also silences it. | `analysis/contacts.py:162` | Same host normalisation as G001. |
| G011 | Set `maintainer_established: true` (any prior cycle event) and the five-package burst is dropped before the burst test. | `analysis/correlation.py:1054` | An established account creating several `brand_new`/`placeholder` packages in one window is still a burst; the established flag must not suppress it. |
| G012 | Name the members as one related cluster (`sonora`, `sonora-bin`, `sonora-qt`) across three maintainers; `_one_related_cluster` stands the shared H075 signal down. | `analysis/correlation.py:747` | The family excuse should require one maintainer; cross-maintainer payload sharing under related names is the attack, not a family release. |
| G013 | Same payload URL over `https://` in one package and `http://` in another. | `analysis/correlation.py:783` | Canonicalise scheme/port in `canonical_payload_url` for the join. |
| G014 | Adopt a dormant cohort whose package names share a prefix (`vim`, `vimium`, `vimpc`): `_one_related_cluster` treats three different projects as one family and stands the window down. | `analysis/correlation.py:817` | The related-name stand-down must require one project (shared repo/pkgbase), not a shared prefix. |
| G015 | Adopt the dormant cohort from a recorded maintainer rather than from orphan; `orphan_only=true` skips every history row with a non-empty predecessor. | `analysis/correlation.py:881` | Track recent adoptions from recorded maintainers too when the cohort is dormant and then pushes together. |
| G016 | The account's package fired `X011`, which is outside `SHARED_PAYLOAD_RULES`, so no sibling context is emitted. | `analysis/correlation.py:659` | The trigger set must include the other high-severity payload rules, not only the curated list. |

## Rejected as not the same claim

- **G009**: out of reach - matching is exact against operator-curated state, so
  a listed subject always fires.
- **W013** is a disclosure that only exists once a campaign matches; it is not
  an independent attack surface.

## Parser robustness (not counted)

A `last_modified` supplied as an ISO-8601 string instead of an epoch number is
silently ignored by the dormancy counter (`isinstance(int, float)`), so the
same records stay below `min_dormant`. The live corpus supplies epochs, so an
attacker cannot choose the representation; recorded as a type-robustness note,
not a bypass.

## Ordering note

The correlation lane seeds state that later cells can see: G008's control must
run before its bypass, or the bypass's seeded transition silences the control.
Cells are committed control-first for this reason.
