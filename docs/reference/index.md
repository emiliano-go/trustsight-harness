---
description: Complete reference documentation for the harness CLI, campaign configuration, record schema, terminal statuses, and exit codes.
---

# Reference

Authoritative descriptions of every interface the harness exposes. For the
reasoning behind them, see [Explanation](../explanation/index.md).

| Page | What it covers |
|---|---|
| [CLI](cli.md) | `python -m harness <campaign>` and `python -m harness regression`. |
| [Campaign Configuration](campaign-config.md) | Every key of `campaign.yml`, its type, and whether it is required. |
| [Record Schema](record-schema.md) | `record.json`, field by field, including the forbidden fields. |
| [Terminal Statuses](statuses.md) | The eleven terminal statuses and the order the Judge applies them in. |
| [Exit Codes](exit-codes.md) | 0, 1, 2; and why "bypasses found" is not among them. |
