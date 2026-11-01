// Headline plus a few labelled facts from a CVSS v3 vector (the long prose stays in v.attack).
const AV = { N: "Network", A: "Adjacent network", L: "Local access", P: "Physical access" };
const WHO = {
  N: "Anyone on the network",
  A: "Someone on the same network",
  L: "Someone already inside the container or host",
  P: "Someone with physical access",
};
const EFFECT = { C: "read data they should not", I: "change data they should not", A: "knock it offline" };
const IMPACT = { C: "Confidentiality", I: "Integrity", A: "Availability" };

export const metric = (vector, key) => new RegExp(`(?:^|/)${key}:([A-Z])`).exec(vector || "")?.[1];

function needs(vector) {
  const pr = metric(vector, "PR");
  const ui = metric(vector, "UI");
  const parts = [];
  if (pr === "L" || pr === "H") parts.push(pr === "L" ? "A login" : "Admin rights");
  if (ui === "R") parts.push("A user action");
  return parts.length ? parts.join(" + ") : "Nothing";
}

// Impact letters rated High; when none is, the ones rated Low.
function impacts(vector) {
  for (const level of ["H", "L"]) {
    const hit = Object.keys(IMPACT).filter((k) => metric(vector, k) === level);
    if (hit.length) return { keys: hit, level };
  }
  return { keys: [], level: "N" };
}

function headline(vector) {
  const av = metric(vector, "AV");
  if (!av) return "The attack path is unknown: no CVSS vector is published.";
  const { keys, level } = impacts(vector);
  if (av === "P") return "Needs physical access to the machine.";
  if (!keys.length) return `${WHO[av]} can reach it, but the impact is negligible.`;
  const effect = keys.length === 3 && level === "H" ? "take it over" : keys.map((k) => EFFECT[k]).join(" and ");
  return `${WHO[av]} can ${effect}${level === "L" ? ", to a limited degree" : ""}.`;
}

// "CVSS 7.5 (High)"; an unscored advisory shows its severity band instead.
export function cvssText(v) {
  const sev = v.severity ? v.severity[0] + v.severity.slice(1).toLowerCase() : "Unknown";
  return v.score ? `${v.score.toFixed(1)} (${sev})` : `${sev} (no score published)`;
}

export function glance(v) {
  const vector = v.vector || "";
  const av = metric(vector, "AV");
  const { keys, level } = impacts(vector);
  return {
    headline: headline(vector),
    facts: [
      { label: "CVSS", value: cvssText(v) },
      { label: "Attack from", value: av ? AV[av] : "Unknown" },
      { label: "Needs", value: vector ? needs(vector) : "Unknown" },
      { label: "Impact", value: keys.length ? keys.map((k) => IMPACT[k]).join(", ") + (level === "L" ? " (low)" : "") : "None rated" },
      { label: "Fix", value: v.fixed || "None yet", mono: !!v.fixed },
    ],
  };
}
