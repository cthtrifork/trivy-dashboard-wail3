export const pct = (x) => (x * 100 < 0.1 ? "<0.1%" : (x * 100).toFixed(x >= 0.1 ? 0 : 1) + "%");

export const TIER_COLOR = { "Act now": "--CRITICAL", "Fix soon": "--HIGH", Plan: "--MEDIUM", Monitor: "--UNKNOWN" };
export const tierStyle = (tier) => ({ "--c": `var(${TIER_COLOR[tier]})` });

export const STATUS_LABEL = { affected: "Affected", not_affected: "Not affected", fixed: "Fixed", under_investigation: "Under investigation" };
export const JUSTIFICATIONS = {
  component_not_present: "Component not present",
  vulnerable_code_not_present: "Vulnerable code not present",
  vulnerable_code_not_in_execute_path: "Vulnerable code not in execute path",
  vulnerable_code_cannot_be_controlled_by_adversary: "Code cannot be controlled by an adversary",
  inline_mitigations_already_exist: "Inline mitigations already exist",
};
export const RESOLVED = new Set(["not_affected", "fixed"]);
