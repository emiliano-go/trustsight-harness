---
description: The two external, read-only MCP tools — the AUR downloader and the watcher feed reader — and the limits they hold themselves to.
---

# External Tools

The MCP server exposes two tools that read from outside the repository: the
AUR and the TrustSight watcher feed. Both are public, unauthenticated, GET-only
services that ask callers to be gentle, so both are paced and bounded in the
same way ([`harness/net.py`](../../harness/net.py)).

Neither tool fetches a URL that appears *inside* a PKGBUILD (self-security
[H2](../security.md#h2-no-fetching-of-generated-urls)). The only hosts reached
are `aur.archlinux.org` and the configured feed host; every URL is built from a
validated package name and a fixed path.

Nothing either tool does is unbounded. A response is read through a byte cap, a
snapshot is decompressed in memory under a member and total-size cap, and a
whole call runs under a wall-clock deadline that also caps the rate-limit pause,
the retry sleep and the socket read. An `info` call accepts at most 2000 names
and parses at most 20000 records. See
[H3](../security.md#h3-bounded-reads) for the full table.

Both tools require `httpx`, which ships in the `mcp` extra:

```bash
uv sync --extra mcp
```

They are MCP tools and, like every operation, CLI subcommands too
(`python -m harness aur_info --packages NAME`, `python -m harness feed_health`,
…); see the [CLI reference](cli.md#every-mcp-operation-is-also-a-subcommand).

## AUR

The AUR is capped at **4000 requests a day per IP**; a `multiinfo` call must
fit about 200 names and a 4443-byte URI; search terms must be at least two
characters. Bulk consumers are pointed at the metadata archives instead of the
RPC.

| Tool | What it does |
|---|---|
| `aur_info(packages)` | Metadata (version, deps, maintainer, votes) via the v5 RPC. Batches are split to fit the name and URI caps. |
| `aur_pkgbuild(package)` | The build files from the package's snapshot tarball: the `PKGBUILD` text and the list of files in the snapshot. |

Both validate the name against the Arch package charset before it becomes part
of a URL. `aur_pkgbuild` reads the tarball in memory, bounds its decompressed
size, never extracts to disk, and caches the result by
`(base, version, LastModified)`.

The client spends **half** the published daily cap (2000 requests) with a
one-second minimum gap, and carries the window across processes in a ledger
under the cache directory, so a restart cannot spend the cap again.

## Watcher feed

The feed at `watcher.trustsight.org` preserves every alert the AUR watcher
publishes. The API is read-only, CORS-open, and capped at **120 requests a
minute** per client, answering `429` with a `Retry-After` header.

| Tool | Endpoint |
|---|---|
| `feed_search(q, event, day, since, until, limit)` | `/api/feed` |
| `feed_latest(n)` | `/api/latest` or `/api/latest/{n}` |
| `feed_by_date(date, timeframe)` | `/api/date/{date}[/{timeframe}]` |
| `feed_by_package(name)` | `/api/package/{name}` |
| `feed_by_rule(rule_id)` | `/api/rule/{id}` |
| `feed_message(slug)` | `/api/messages/{slug}` |
| `feed_stats()` | `/api/stats` |
| `feed_health()` | `/health` (not rate limited) |

`date` is `YYYY-MM-DD`; `timeframe` is `HH`, `HH-HH` or `HHMM-HHMM`, all UTC.
The base URL is `https://watcher.trustsight.org` unless `WATCHER_FEED_URL` is
set. The client paces itself at half the cap (60 a minute).

A notification means a published rule matched a package change. It is evidence,
not a verdict, and it is not permission to install.

## Environment

| Variable | Effect |
|---|---|
| `WATCHER_FEED_URL` | Override the feed base URL. |
| `HARNESS_NET_CACHE_DIR` | Where the AUR cache and the rate-limit ledgers live (default `.mcp-scratch/net`). |

!!! note "Reproducibility"

    These tools read live, changing sources, so they are for inspection and
    recon, never for a campaign result. A campaign measures a pinned
    TrustSight against committed inputs; a feed query or a downloaded
    PKGBUILD is not part of any record.
