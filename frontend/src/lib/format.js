import { Browser } from "@wailsio/runtime";
// Lowest CVSS v3 score of each severity band. Advisories such as GHSA ids often carry a severity but no
// vector, and a blank score next to a HIGH pill reads as harmless; show the band floor, marked with "~".
const CVSS_FLOOR = { CRITICAL: 9, HIGH: 7, MEDIUM: 4, LOW: 0.1 };
export const cvssFloor = (severity) => CVSS_FLOOR[severity] ?? 0;
// Score used to order rows: reported CVSS, else the band floor, so an unscored HIGH sorts with the 7s.
export const effectiveScore = (v) => v.score || cvssFloor(v.severity);
// Trivy's data-source ids as people know them; anything else is shown as Trivy names it.
const SOURCES = {
  redhat: "Red Hat",
  nvd: "NVD",
  ghsa: "GitHub Advisory",
  alma: "AlmaLinux",
  rocky: "Rocky Linux",
  azure: "Azure Linux",
  bitnami: "Bitnami",
  ubuntu: "Ubuntu",
  debian: "Debian",
  alpine: "Alpine",
  amazon: "Amazon Linux",
  "oracle-oval": "Oracle Linux",
  photon: "Photon OS",
  suse: "SUSE",
  "cbl-mariner": "CBL-Mariner",
  "arch-linux": "Arch Linux",
  k8s: "Kubernetes",
  osv: "OSV",
};
export const sourceName = (id) => SOURCES[id] ?? id;
export const pct = (x) => (x * 100 < 0.1 ? "<0.1%" : (x * 100).toFixed(x >= 0.1 ? 0 : 1) + "%");

export const TIER_COLOR = { "Act now": "--CRITICAL", "Fix soon": "--HIGH", Plan: "--MEDIUM", Monitor: "--UNKNOWN" };
export const tierStyle = (tier) => ({ "--c": `var(${TIER_COLOR[tier]})`, "--on": `var(--on${TIER_COLOR[tier]})` });

// Column explanations, shown as header tooltips in both finding tables.
export const COLUMN_HELP = {
  priority: "Our own ranking: exploitation evidence (CISA KEV, EPSS) first, then reachability and severity. Higher number = fix sooner.",
  severity: "Severity rating from the vulnerability database (Critical, High, Medium, Low).",
  score:
    "CVSS base score, 0 to 10, from Red Hat, else NVD, else the highest any source published. How bad the flaw is in the worst case, not how likely it is to be exploited.",
  epss: "EPSS: estimated probability that the flaw is exploited in the wild within the next 30 days.",
  signals: "KEV = listed by CISA as known exploited. VEX = a statement you recorded about this finding.",
  estimated: "No CVSS score is published; this is the lowest score of the severity band.",
  fixed: "First package version that contains a fix.",
  installed: "Package version found in the image.",
};

export const STATUS_LABEL = {
  affected: "Affected",
  not_affected: "Not affected",
  fixed: "Fixed",
  under_investigation: "Under investigation",
};
export const JUSTIFICATIONS = {
  component_not_present: "Component not present",
  vulnerable_code_not_present: "Vulnerable code not present",
  vulnerable_code_not_in_execute_path: "Vulnerable code not in execute path",
  vulnerable_code_cannot_be_controlled_by_adversary: "Code cannot be controlled by an adversary",
  inline_mitigations_already_exist: "Inline mitigations already exist",
};
// The same justifications in plain words, for the assess drawer.
export const JUSTIFICATION_PLAIN = {
  component_not_present: "The component isn't in the image",
  vulnerable_code_not_present: "The vulnerable code isn't there",
  vulnerable_code_not_in_execute_path: "The vulnerable code is never run",
  vulnerable_code_cannot_be_controlled_by_adversary: "An attacker can't control it",
  inline_mitigations_already_exist: "A mitigation already blocks it",
};
export const RESOLVED = new Set(["not_affected", "fixed"]);
// Expiry is a UTC date (YYYY-MM-DD) and the day itself still counts, mirroring VEXEntry.Expired in Go.
export const isExpired = (e) => !!e?.expires && new Date().toISOString().slice(0, 10) > e.expires;
// A resolved assessment hides its finding until it expires; after that it only annotates it.
export const suppresses = (e) => !!e && RESOLVED.has(e.status) && !isExpired(e);

export function ago(ms) {
  const s = Math.max(0, (Date.now() - ms) / 1000);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  const d = Math.floor(s / 86400);
  return d === 1 ? "yesterday" : `${d} days ago`;
}

export function bytes(n) {
  if (n < 1024) return n + " B";
  const u = ["KB", "MB", "GB"];
  let i = -1;
  do {
    n /= 1024;
    i++;
  } while (n >= 1024 && i < u.length - 1);
  return n.toFixed(n >= 100 ? 0 : 1) + " " + u[i];
}

// Details page for a finding: Trivy's primary URL, else NVD for CVE ids.
export const detailUrl = (v) =>
  /^https?:\/\//.test(v.url) ? v.url : /^CVE-\d{4}-\d+$/i.test(v.id) ? `https://nvd.nist.gov/vuln/detail/${v.id.toUpperCase()}` : "";
export const openUrl = (url) => {
  try {
    Promise.resolve(Browser.OpenURL(url)).catch(() => window.open(url, "_blank", "noopener"));
  } catch {
    window.open(url, "_blank", "noopener");
  }
};
