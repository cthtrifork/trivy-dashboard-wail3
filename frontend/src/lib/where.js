// Where a finding's package sits in the image: the shortest route from a direct dependency of the
// image (usually a binary such as usr/local/bin/podman) down to the vulnerable package, from the SBOM graph.
const MAX_VISITED = 20000; // a hub such as stdlib can have hundreds of parents; this only bounds a pathological graph

// purl first, then name@version, the same order buildDepGraph uses on the Go side.
export function indexNodes(depNodes) {
  const byPURL = new Map();
  const byNV = new Map();
  for (const n of Object.values(depNodes ?? {})) {
    if (n.purl) byPURL.set(n.purl, n);
    byNV.set(`${n.name}@${n.version}`.toLowerCase(), n);
  }
  return { byPURL, byNV };
}

// The shortest route from a direct dependency of the image down to start (a node), as { chain, others },
// or null when start does not hang off any root. chain is root first, start last; others counts the
// other direct dependencies that also lead to it.
export function routeTo(result, start) {
  const nodes = result?.depNodes;
  if (!nodes || !start) return null;
  const roots = new Set(result.depRoots);
  const next = new Map([[start.ref, null]]); // ref -> the ref one step closer to the package
  const queue = [start.ref];
  let first = null;
  let reached = 0;
  for (let i = 0; i < queue.length && i < MAX_VISITED; i++) {
    const ref = queue[i];
    if (roots.has(ref)) {
      first ??= ref; // breadth first, so the first root found has the shortest route
      reached++;
      continue;
    }
    for (const p of nodes[ref].parents) {
      if (nodes[p] && !next.has(p)) {
        next.set(p, ref);
        queue.push(p);
      }
    }
  }
  if (!first) return null;
  const chain = [];
  for (let ref = first; ref; ref = next.get(ref)) chain.push(nodes[ref]);
  return { chain, others: reached - 1 };
}

// Returns { chain: [node, ...root first, vulnerable package last], others } or null when the package
// is not in the graph or is itself a direct dependency (an OS package: nothing to show).
export function findingPath(result, index, v) {
  const start = index.byPURL.get(v.purl) ?? index.byNV.get(`${v.package}@${v.installed}`.toLowerCase());
  if (!start || new Set(result.depRoots).has(start.ref)) return null;
  return routeTo(result, start);
}

// Everything that requires ref, directly or through others: { hops, direct, transitive, findings }.
// hops maps each such component (and ref itself, at 0) to its distance in requires-edges; findings
// counts the findings that sit in those components, not in ref.
export function blastRadius(depNodes, ref) {
  const hops = new Map([[ref, 0]]);
  const queue = [ref];
  for (let i = 0; i < queue.length; i++) {
    for (const p of depNodes[queue[i]].parents) {
      if (depNodes[p] && !hops.has(p)) {
        hops.set(p, hops.get(queue[i]) + 1);
        queue.push(p);
      }
    }
  }
  let direct = 0;
  let findings = 0;
  for (const [r, h] of hops) {
    if (h === 1) direct++;
    if (h) findings += depNodes[r].own.length;
  }
  return { hops, direct, transitive: hops.size - 1 - direct, findings };
}
