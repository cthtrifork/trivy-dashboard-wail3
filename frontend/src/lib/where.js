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

// Returns { chain: [node, ...root first, vulnerable package last], others } or null when the package
// is not in the graph or is itself a direct dependency (an OS package: nothing to show). others counts
// the other direct dependencies that also lead to it.
export function findingPath(result, index, v) {
  const nodes = result?.depNodes;
  if (!nodes) return null;
  const start = index.byPURL.get(v.purl) ?? index.byNV.get(`${v.package}@${v.installed}`.toLowerCase());
  if (!start) return null;
  const roots = new Set(result.depRoots);
  if (roots.has(start.ref)) return null;

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
