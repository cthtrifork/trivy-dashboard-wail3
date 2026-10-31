# Features

What the app does, in detail. The README has the short version.

- **Priorities** – a ranked shortlist by tier (Act now / Fix soon / Plan / Monitor). Each score is a sum of readable reasons (CISA **KEV**, **EPSS**, CVSS severity, attack vector, fix availability) with tunable rules and presets: [`scoring.md`](scoring.md).
- **Vulnerabilities in context of the SBOM** – every finding is tied to the SBOM component that carries it. A finding shows the route from the image through its dependencies, and a selected component in the dependency graph shows its blast radius (everything that requires it, directly or through others). When several components carry the same CVE, one assessment can cover them all. The SBOM tab lists the CycloneDX components with search and type filters.
- **Assessment help** – the VEX editor shows the CVSS vector in plain words. It offers example wording per status and justification, and an optional review date after which the finding returns to the list.
- **VEX** – assessments are stored per image repository and carry over to new tags. Export or import OpenVEX (v0.2.0).
- **Compare** – diff two tags or digests: severity deltas, added / removed vulnerabilities, package changes.
- **Vulnerabilities** – severity cards, search, sortable table, details; ignore rules and vendor statuses hide settled findings.
- **Help** – a built-in dialog explains KEV, EPSS, VEX statuses, justifications and SBOM.
