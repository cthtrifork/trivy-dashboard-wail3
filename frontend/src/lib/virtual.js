// Windowed rendering for long lists: only the rows in (or near) the scroll viewport are in the DOM,
// padded above and below by spacers, so memory stays flat however many rows there are.
//
// Rows may differ in height (wrapped text, an expanded detail, an open editor). Each rendered row
// is measured and remembered; rows never seen yet are assumed to be as tall as the average one.
// Row heights only change on interaction or resize, so measuring runs after renders, clicks, form
// input, <details> toggles and container resizes instead of observing every row.
import { computed, onBeforeUnmount, onUpdated, ref, watch } from "vue";

export function useVirtualList(items, { key, estimate = 40, gap = 0, overscan = 6 } = {}) {
  const scroller = ref(null);
  const scrollTop = ref(0);
  const viewport = ref(800);
  const version = ref(0);
  const heights = new Map(); // key -> measured height including `gap`
  const nodes = new Map(); // key -> rendered element
  const keyOf = new WeakMap(); // element -> key it is registered under
  let measured = 0,
    total = 0,
    raf = 0,
    cleanup = null;

  const average = () => (measured ? total / measured : estimate);

  // offsets[i] is the top of row i; the last entry is the full height of the list.
  const offsets = computed(() => {
    version.value;
    const list = items.value;
    const fallback = average() + gap;
    const out = new Float64Array(list.length + 1);
    for (let i = 0; i < list.length; i++) out[i + 1] = out[i] + (heights.get(key(list[i], i)) ?? fallback);
    return out;
  });

  // Separate computeds so a scroll only re-renders when the window actually moves.
  const first = computed(() => {
    const o = offsets.value;
    let lo = 0,
      hi = o.length - 1;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      o[mid + 1] > scrollTop.value ? (hi = mid) : (lo = mid + 1);
    }
    return Math.max(0, lo - overscan);
  });
  const last = computed(() => {
    const o = offsets.value,
      n = o.length - 1,
      bottom = scrollTop.value + viewport.value;
    let i = first.value;
    while (i < n && o[i] < bottom) i++;
    return Math.min(n, i + overscan);
  });

  const rows = computed(() => items.value.slice(first.value, last.value).map((item, i) => ({ item, index: first.value + i })));
  const before = computed(() => offsets.value[first.value]);
  const after = computed(() => offsets.value[offsets.value.length - 1] - offsets.value[last.value]);

  function measure() {
    raf = 0;
    let changed = false;
    for (const [k, node] of nodes) {
      const h = node.getBoundingClientRect().height;
      if (!h) continue; // hidden panel: nothing to learn
      const prev = heights.get(k);
      if (prev === undefined) {
        measured++;
        total += h;
      }
      if (prev === undefined || Math.abs(prev - (h + gap)) > 0.5) {
        heights.set(k, h + gap);
        changed = true;
      }
    }
    if (changed) version.value++;
  }
  const schedule = () => {
    raf ||= requestAnimationFrame(measure);
  };

  const vMeasure = {
    mounted(el, b) {
      keyOf.set(el, b.value);
      nodes.set(b.value, el);
    },
    updated(el, b) {
      const prev = keyOf.get(el);
      if (prev !== b.value) {
        nodes.delete(prev);
        keyOf.set(el, b.value);
        nodes.set(b.value, el);
      }
    },
    beforeUnmount(el) {
      const k = keyOf.get(el);
      if (nodes.get(k) === el) nodes.delete(k);
    },
  };

  function attach(el) {
    cleanup?.();
    cleanup = null;
    if (!el) return;
    const onScroll = () => (scrollTop.value = el.scrollTop);
    const ro = new ResizeObserver(() => {
      viewport.value = el.clientHeight || viewport.value;
      heights.clear(); // wrapping depends on width
      version.value++;
      schedule();
    });
    const events = ["click", "input", "change"];
    el.addEventListener("scroll", onScroll, { passive: true });
    events.forEach((e) => el.addEventListener(e, schedule));
    el.addEventListener("toggle", schedule, true); // does not bubble
    ro.observe(el);
    viewport.value = el.clientHeight || viewport.value;
    scrollTop.value = el.scrollTop;
    cleanup = () => {
      el.removeEventListener("scroll", onScroll);
      events.forEach((e) => el.removeEventListener(e, schedule));
      el.removeEventListener("toggle", schedule, true);
      ro.disconnect();
    };
  }
  watch(scroller, attach, { flush: "post", immediate: true });

  // A different list (filter, sort, new scan) invalidates what was measured.
  watch(items, () => {
    heights.clear();
    version.value++;
  });
  onUpdated(schedule);
  onBeforeUnmount(() => {
    cleanup?.();
    cancelAnimationFrame(raf);
  });

  // Bring row `i` to the top of the viewport. Rows never measured are estimated, so once they have
  // rendered the real element is aligned too.
  function scrollToIndex(i) {
    const el = scroller.value;
    if (!el || i < 0) return;
    el.scrollTop = offsets.value[i];
    requestAnimationFrame(() => requestAnimationFrame(() => nodes.get(key(items.value[i], i))?.scrollIntoView({ block: "start" })));
  }

  return { scroller, rows, before, after, vMeasure, scrollToIndex };
}
