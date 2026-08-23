---
description: The fastest path from a clean checkout to a campaign record you can read.
---

# Getting Started

The fastest path from a clean checkout to a record you can read. Follow these
pages in order.

<div class="grid cards" markdown>

-   [**Installation**](installation.md)

    Install with `uv`, pointed at the exact TrustSight build you intend to
    measure. The harness refuses to run against a different one.

-   [**Running a Campaign**](running-a-campaign.md)

    Run the campaign the repository ships with, read the summary it prints, and
    find the traces behind every number in it.

-   [**Reading a Record**](reading-a-record.md)

    Every field of `record.json`: what it measured, and what it is evidence for.

</div>

Once you have run the shipped campaign, the [Guides](../guides/index.md) cover
writing your own, and the [Explanation](../explanation/index.md) covers why the
pipeline refuses as much as it does.

!!! note "One prerequisite worth stating"

    You need a TrustSight checkout or an installed release. The harness measures
    a pinned build; it does not vendor one. See
    [Installation](installation.md#pointing-at-the-build-under-test).
