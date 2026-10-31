export function sortRows(rows, state, key) {
  const val = (r) => {
    const v = key(r, state.sort);
    return typeof v === "string" ? v.toLowerCase() : v;
  };
  return [...rows].sort((a, b) => {
    const x = val(a),
      y = val(b);
    return (x < y ? -1 : x > y ? 1 : 0) * state.dir;
  });
}

export function sortBy(state, col) {
  state.dir = state.sort === col ? -state.dir : 1;
  state.sort = col;
}

export const sortClass = (state, col) => (state.sort === col ? (state.dir > 0 ? "asc" : "desc") : "");
