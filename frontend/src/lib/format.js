export const pct = (x) => (x * 100 < 0.1 ? "<0.1%" : (x * 100).toFixed(x >= 0.1 ? 0 : 1) + "%");

export const TIER_COLOR = { "Act now": "--CRITICAL", "Fix soon": "--HIGH", Plan: "--MEDIUM", Monitor: "--UNKNOWN" };
export const tierStyle = (tier) => ({ "--c": `var(${TIER_COLOR[tier]})` });

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
export const RESOLVED = new Set(["not_affected", "fixed"]);
// Expiry is a UTC date (YYYY-MM-DD) and the day itself still counts, mirroring VEXEntry.Expired in Go.
export const isExpired = (e) => !!e?.expires && new Date().toISOString().slice(0, 10) > e.expires;
// A resolved assessment hides its finding until it expires; after that it only annotates it.
export const suppresses = (e) => !!e && RESOLVED.has(e.status) && !isExpired(e);

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
