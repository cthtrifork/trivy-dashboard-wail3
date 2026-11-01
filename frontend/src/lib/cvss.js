const NHL = { N: "None", L: "Low", H: "High" };
const AV = { N: "Network", A: "Adjacent network", L: "Local", P: "Physical" };
const V3 = {
  AV: ["Attack vector", AV],
  AC: ["Attack complexity", { L: "Low", H: "High" }],
  PR: ["Privileges required", NHL],
  UI: ["User interaction", { N: "None", R: "Required" }],
  S: ["Scope", { U: "Unchanged", C: "Changed" }],
  C: ["Confidentiality impact", NHL],
  I: ["Integrity impact", NHL],
  A: ["Availability impact", NHL],
};
const V4 = {
  AV: ["Attack vector", AV],
  AC: ["Attack complexity", { L: "Low", H: "High" }],
  AT: ["Attack requirements", { N: "None", P: "Present" }],
  PR: ["Privileges required", NHL],
  UI: ["User interaction", { N: "None", P: "Passive", A: "Active" }],
  VC: ["Confidentiality impact", NHL],
  VI: ["Integrity impact", NHL],
  VA: ["Availability impact", NHL],
  SC: ["Subsequent confidentiality", NHL],
  SI: ["Subsequent integrity", NHL],
  SA: ["Subsequent availability", NHL],
};
const IMP2 = { N: "None", P: "Partial", C: "Complete" };
const V2 = {
  AV: ["Attack vector", AV],
  AC: ["Attack complexity", { H: "High", M: "Medium", L: "Low" }],
  Au: ["Authentication", { M: "Multiple", S: "Single", N: "None" }],
  C: ["Confidentiality impact", IMP2],
  I: ["Integrity impact", IMP2],
  A: ["Availability impact", IMP2],
};

// [{ code: "AV:N", label: "Attack vector", value: "Network" }, ...] in vector order; unknown metrics are skipped.
export function breakdown(vector) {
  if (!vector) return [];
  const [head, ...rest] = vector.split("/");
  const table = head === "CVSS:4.0" ? V4 : head.startsWith("CVSS:3") ? V3 : V2;
  const parts = head.startsWith("CVSS:") ? rest : [head, ...rest];
  const out = [];
  for (const part of parts) {
    const [key, val] = part.split(":");
    const meta = table[key];
    if (meta?.[1][val]) out.push({ code: part, label: meta[0], value: meta[1][val] });
  }
  return out;
}
