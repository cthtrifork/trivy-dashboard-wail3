// Minimal force-directed graph on <canvas>: pan, zoom, drag, directed edges.
// No dependencies. Nodes with a `depth` are pulled towards a horizontal band
// so dependency graphs read top-down (image → packages → their dependencies).

const LEVEL = 120;
const MAX_SPEED = 40; // px per step: a safety net against runaway nodes

export class Graph {
  constructor(canvas, { onSelect = () => {}, onHover = () => {} } = {}) {
    this.c = canvas;
    this.ctx = canvas.getContext("2d");
    this.onSelect = onSelect;
    this.onHover = onHover;
    this.nodes = [];
    this.edges = [];
    this.byId = new Map();
    this.pos = new Map(); // id -> {x,y}, remembered across setData calls
    this.k = 1; this.tx = 0; this.ty = 0;
    this.alpha = 0;
    this.autoFit = true;
    this.selected = null;
    this.hover = null;
    this.showLabels = "auto";
    this.raf = 0;

    new ResizeObserver(() => this.resize()).observe(canvas.parentElement);
    canvas.addEventListener("pointerdown", (e) => this.down(e));
    canvas.addEventListener("pointermove", (e) => this.move(e));
    canvas.addEventListener("pointerup", (e) => this.up(e));
    canvas.addEventListener("pointerleave", () => { if (!this.drag) this.setHover(null); });
    canvas.addEventListener("wheel", (e) => this.wheel(e), { passive: false });
    canvas.addEventListener("dblclick", () => this.fit());
  }

  // nodes: {id,label,sub,r,fill,ring,shape,depth,hl}; edges: [fromId,toId]
  setData(nodes, edges) {
    for (const n of this.nodes) this.pos.set(n.id, { x: n.x, y: n.y });
    this.nodes = nodes.map((n, i) => {
      const p = this.pos.get(n.id);
      const a = i * 2.399963; // golden angle spiral for fresh nodes
      const rad = 30 * Math.sqrt(i + 1);
      return { ...n, x: p ? p.x : Math.cos(a) * rad, y: p ? p.y : (n.depth || 0) * LEVEL + Math.sin(a) * 20, vx: 0, vy: 0, fixed: false };
    });
    this.byId = new Map(this.nodes.map((n, i) => [n.id, i]));
    this.edges = edges.filter(([a, b]) => this.byId.has(a) && this.byId.has(b)).map(([a, b]) => [this.byId.get(a), this.byId.get(b)]);
    this.adj = this.nodes.map(() => new Set());
    this.deg = this.nodes.map(() => 0);
    for (const [a, b] of this.edges) { this.adj[a].add(b); this.adj[b].add(a); this.deg[a]++; this.deg[b]++; }
    this.autoFit = true;
    this.alpha = 1;
    this.kick();
  }

  select(id, { center = false } = {}) {
    this.selected = id;
    if (center) this.centerOn(id);
    this.draw();
  }

  centerOn(id) {
    const n = this.nodes[this.byId.get(id)];
    if (!n) return;
    this.autoFit = false;
    const { w, h } = this.size();
    this.k = Math.max(this.k, 1);
    this.tx = w / 2 - n.x * this.k;
    this.ty = h / 2 - n.y * this.k;
    this.draw();
  }

  screenPos(id) {
    const n = this.nodes[this.byId.get(id)];
    if (!n) return null;
    const r = this.c.getBoundingClientRect();
    return { x: r.left + n.x * this.k + this.tx, y: r.top + n.y * this.k + this.ty };
  }

  size() { return { w: this.c.clientWidth, h: this.c.clientHeight }; }

  resize() {
    const dpr = window.devicePixelRatio || 1;
    const { w, h } = this.size();
    if (!w || !h) return;
    this.c.width = Math.round(w * dpr);
    this.c.height = Math.round(h * dpr);
    if (this.autoFit) this.fit(false);
    this.draw();
  }

  fit(user = true) {
    if (!this.nodes.length) return;
    const { w, h } = this.size();
    if (!w || !h) return;
    let x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity;
    for (const n of this.nodes) {
      x0 = Math.min(x0, n.x - n.r); x1 = Math.max(x1, n.x + n.r);
      y0 = Math.min(y0, n.y - n.r); y1 = Math.max(y1, n.y + n.r);
    }
    const pad = 50, bottom = 40; // extra room at the bottom for the legend
    this.k = Math.min(1.6, (w - pad * 2) / Math.max(x1 - x0, 1), (h - pad * 2 - bottom) / Math.max(y1 - y0, 1));
    this.tx = w / 2 - ((x0 + x1) / 2) * this.k;
    this.ty = (h - bottom) / 2 - ((y0 + y1) / 2) * this.k;
    if (user) this.autoFit = true;
    this.draw();
  }

  // ---- simulation ----
  kick() {
    if (!this.raf) this.raf = requestAnimationFrame(() => this.frame());
  }

  frame() {
    this.raf = 0;
    const steps = this.nodes.length > 250 ? 1 : 2;
    for (let i = 0; i < steps; i++) this.step();
    this.alpha *= 0.985;
    if (this.autoFit && this.alpha > 0.1) this.fit(false);
    this.draw();
    if (this.alpha > 0.015 || this.drag) this.kick();
  }

  step() {
    const ns = this.nodes, a = this.alpha;
    for (let i = 0; i < ns.length; i++) {
      const p = ns[i];
      for (let j = i + 1; j < ns.length; j++) {
        const q = ns[j];
        let dx = p.x - q.x, dy = p.y - q.y;
        let d2 = dx * dx + dy * dy;
        if (d2 > 90000) continue;
        if (d2 < 1) { dx = Math.random() - 0.5; dy = Math.random() - 0.5; d2 = 1; }
        const d = Math.sqrt(d2);
        const f = (2600 / Math.max(d2, 400)) * a;
        const fx = (dx / d) * f, fy = (dy / d) * f;
        p.vx += fx; p.vy += fy; q.vx -= fx; q.vy -= fy;
      }
    }
    for (const [ai, bi] of this.edges) {
      const p = ns[ai], q = ns[bi];
      const dx = q.x - p.x, dy = q.y - p.y;
      const d = Math.sqrt(dx * dx + dy * dy) || 1;
      const rest = 70 + p.r + q.r;
      const f = (d - rest) * 0.05 * a;
      const fx = (dx / d) * f, fy = (dy / d) * f;
      // Weight by degree (as d3-force does): the endpoint with more links moves less.
      // Without this a hub with hundreds of links receives all of their force at once and
      // is flung to infinity, which is what real Go-module graphs (one root, ~350 children) do.
      const sum = this.deg[ai] + this.deg[bi];
      const wp = this.deg[bi] / sum, wq = this.deg[ai] / sum;
      p.vx += fx * wp; p.vy += fy * wp; q.vx -= fx * wq; q.vy -= fy * wq;
    }
    for (const n of ns) {
      if (n.fixed) { n.vx = n.vy = 0; continue; }
      n.vy += ((n.depth || 0) * LEVEL - n.y) * 0.02 * a; // layer bands
      n.vx += -n.x * 0.002 * a;
      n.vx *= 0.8; n.vy *= 0.8;
      const speed = Math.hypot(n.vx, n.vy);
      if (speed > MAX_SPEED) { n.vx *= MAX_SPEED / speed; n.vy *= MAX_SPEED / speed; }
      n.x += n.vx; n.y += n.vy;
      if (!Number.isFinite(n.x) || !Number.isFinite(n.y)) { n.x = n.y = n.vx = n.vy = 0; } // never let one bad node blank the canvas
    }
  }

  // ---- drawing ----
  draw() {
    const ctx = this.ctx, dpr = window.devicePixelRatio || 1;
    const { w, h } = this.size();
    if (!w || !h) return;
    const css = getComputedStyle(document.documentElement);
    const col = (v) => css.getPropertyValue(v).trim();
    const text = col("--text"), mute = col("--mute"), accent = col("--accent");

    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, w, h);
    ctx.setTransform(dpr * this.k, 0, 0, dpr * this.k, dpr * this.tx, dpr * this.ty);

    const sel = this.selected != null ? this.byId.get(this.selected) : undefined;
    const focus = new Set();
    if (sel !== undefined) { focus.add(sel); this.adj[sel].forEach((i) => focus.add(i)); }
    const hov = this.hover != null ? this.byId.get(this.hover) : undefined;
    const active = (i) => sel === undefined || focus.has(i);

    // edges
    for (const [ai, bi] of this.edges) {
      const p = this.nodes[ai], q = this.nodes[bi];
      const hot = sel !== undefined && (ai === sel || bi === sel);
      ctx.globalAlpha = hot ? 1 : sel !== undefined ? 0.1 : 0.45;
      ctx.strokeStyle = hot ? accent : mute;
      ctx.fillStyle = ctx.strokeStyle;
      ctx.lineWidth = (hot ? 2 : 1) / this.k;
      const dx = q.x - p.x, dy = q.y - p.y, d = Math.hypot(dx, dy) || 1;
      const ux = dx / d, uy = dy / d;
      const sx = p.x + ux * p.r, sy = p.y + uy * p.r, ex = q.x - ux * (q.r + 1), ey = q.y - uy * (q.r + 1);
      ctx.beginPath(); ctx.moveTo(sx, sy); ctx.lineTo(ex, ey); ctx.stroke();
      const s = Math.max(5, 7 / this.k);
      ctx.beginPath();
      ctx.moveTo(ex, ey);
      ctx.lineTo(ex - ux * s - uy * s * 0.5, ey - uy * s + ux * s * 0.5);
      ctx.lineTo(ex - ux * s + uy * s * 0.5, ey - uy * s - ux * s * 0.5);
      ctx.fill();
    }

    // nodes
    ctx.globalAlpha = 1;
    const labelAll = this.showLabels === "all" || (this.showLabels === "auto" && (this.nodes.length <= 40 || this.k > 1.3));
    const labelled = [];
    this.nodes.forEach((n, i) => {
      const on = active(i);
      ctx.globalAlpha = on ? 1 : 0.3;
      if (n.hl) { ctx.beginPath(); ctx.arc(n.x, n.y, n.r + 7, 0, 7); ctx.fillStyle = "#f5b80060"; ctx.fill(); }
      ctx.beginPath();
      if (n.shape === "square") ctx.roundRect(n.x - n.r, n.y - n.r, n.r * 2, n.r * 2, 3);
      else ctx.arc(n.x, n.y, n.r, 0, 7);
      ctx.fillStyle = n.fill;
      ctx.fill();
      ctx.lineWidth = (n.ring ? 3 : 1.2) / Math.min(this.k, 1.5);
      ctx.strokeStyle = n.ring || mute;
      ctx.stroke();
      if (i === sel || i === hov) {
        ctx.lineWidth = 2 / this.k; ctx.strokeStyle = text;
        ctx.beginPath();
        if (n.shape === "square") ctx.roundRect(n.x - n.r - 3, n.y - n.r - 3, n.r * 2 + 6, n.r * 2 + 6, 4);
        else ctx.arc(n.x, n.y, n.r + 3, 0, 7);
        ctx.stroke();
      }
      if (on && (labelAll || i === sel || i === hov || n.hl || (sel !== undefined && focus.has(i)) || n.always)) labelled.push(n);
    });

    ctx.globalAlpha = 1;
    ctx.font = `${12 / Math.min(Math.max(this.k, 0.6), 1.4)}px system-ui, sans-serif`;
    ctx.textAlign = "center"; ctx.textBaseline = "top";
    const bg = col("--panel");
    // Selected/hovered labels always show in full. The rest are shortened and skipped
    // when they would overlap one already placed, so a dense graph stays readable.
    const fontPx = 12 / Math.min(Math.max(this.k, 0.6), 1.4);
    const shorten = (s) => (s.length > 30 ? "…" + s.slice(-29) : s);
    const rank = (n) => (n === this.nodes[sel] || n === this.nodes[hov] ? 0 : n.hl ? 1 : n.always ? 2 : 3);
    labelled.sort((x, y) => rank(x) - rank(y) || y.r - x.r);
    const placed = [];
    for (const n of labelled) {
      const important = rank(n) === 0;
      const t = important ? n.label + (n.sub ? " " + n.sub : "") : shorten(n.label);
      const w = ctx.measureText(t).width, y = n.y + n.r + 4;
      const box = [n.x - w / 2 - 2, y - 1, n.x + w / 2 + 2, y + fontPx + 1];
      if (!important && placed.some((r) => box[0] < r[2] && box[2] > r[0] && box[1] < r[3] && box[3] > r[1])) continue;
      placed.push(box);
      ctx.lineWidth = 3 / this.k; ctx.strokeStyle = bg; ctx.strokeText(t, n.x, y);
      ctx.fillStyle = text; ctx.fillText(t, n.x, y);
    }
  }

  // ---- interaction ----
  local(e) {
    const r = this.c.getBoundingClientRect();
    return { sx: e.clientX - r.left, sy: e.clientY - r.top };
  }
  world(sx, sy) { return { x: (sx - this.tx) / this.k, y: (sy - this.ty) / this.k }; }

  hit(sx, sy) {
    const { x, y } = this.world(sx, sy);
    let best = -1, bd = Infinity;
    this.nodes.forEach((n, i) => {
      const d = Math.hypot(n.x - x, n.y - y);
      if (d <= n.r + 4 / this.k && d < bd) { best = i; bd = d; }
    });
    return best;
  }

  down(e) {
    const { sx, sy } = this.local(e);
    const i = this.hit(sx, sy);
    this.c.setPointerCapture(e.pointerId);
    this.drag = { i, sx, sy, moved: false, tx: this.tx, ty: this.ty };
    if (i >= 0) this.nodes[i].fixed = true;
  }

  move(e) {
    const { sx, sy } = this.local(e);
    const d = this.drag;
    if (!d) {
      const i = this.hit(sx, sy);
      this.setHover(i >= 0 ? this.nodes[i].id : null);
      this.c.style.cursor = i >= 0 ? "pointer" : "grab";
      return;
    }
    if (Math.hypot(sx - d.sx, sy - d.sy) > 3) d.moved = true;
    if (!d.moved) return;
    this.autoFit = false;
    if (d.i >= 0) {
      const p = this.world(sx, sy);
      Object.assign(this.nodes[d.i], { x: p.x, y: p.y });
      this.alpha = Math.max(this.alpha, 0.3);
      this.kick();
    } else {
      this.tx = d.tx + (sx - d.sx);
      this.ty = d.ty + (sy - d.sy);
      this.draw();
    }
  }

  up() {
    const d = this.drag;
    this.drag = null;
    if (!d) return;
    if (d.i >= 0) {
      this.nodes[d.i].fixed = false;
      if (!d.moved) this.onSelect(this.nodes[d.i].id);
    } else if (!d.moved) this.onSelect(null);
  }

  setHover(id) {
    if (id === this.hover) return;
    this.hover = id;
    this.onHover(id);
    this.draw();
  }

  wheel(e) {
    e.preventDefault();
    const { sx, sy } = this.local(e);
    const f = Math.exp(-e.deltaY * 0.0015);
    const k = Math.min(4, Math.max(0.1, this.k * f));
    const p = this.world(sx, sy);
    this.k = k;
    this.tx = sx - p.x * k;
    this.ty = sy - p.y * k;
    this.autoFit = false;
    this.draw();
  }
}
