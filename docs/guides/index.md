---
description: Task-oriented guides for writing campaigns, running the harness in CI, and auditing results.
---

# Guides

These pages are task-oriented. They assume you have already installed the
harness and run the shipped campaign.

<div class="grid cards" markdown>

-   [**Writing a Campaign**](writing-a-campaign.md)

    Configure `campaign.yml`, choose a generator, declare constraints, and
    pre-register stop conditions.

-   [**Replaying Watcher Alerts**](watcher-replay.md)

    Capture stored alerts and replay them against the rule ledger, so the
    reproducibility claim is measured on the real stream.

-   [**Using in CI**](using-in-ci.md)

    Gate pull requests on the regression gate or on a campaign record.

-   [**Auditing Results**](auditing-results.md)

    A campaign finished and you need to decide what it actually proved.

</div>
