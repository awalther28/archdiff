import { useCallback, useEffect, useMemo, useRef, useState, type PointerEvent as ReactPointerEvent, type WheelEvent as ReactWheelEvent } from 'react';
import type { Diff, Graph } from '../schema/types';
import type { DeltaIndex, UnionGraph } from '../lib/derive';
import type { Layout } from '../layout/layout';
import type { FocusSets, Selection } from '../lib/focus';
import { GraphPane, type ViewTransform } from './GraphPane';

interface Props {
  base: Graph;
  head: Graph;
  diff: Diff;
  union: UnionGraph;
  layout: Layout;
  delta: DeltaIndex;
  focus: FocusSets | null;
  selected: Selection | null;
  identical: boolean;
  onSelect: (s: Selection | null) => void;
}

const MIN_K = 0.15;
const MAX_K = 4;

/**
 * Two panes, one layout, one camera. Pan/zoom is shared so the reader's eye
 * can move horizontally between "before" and "after" and land on the same
 * node at the same pixel offset.
 */
export function SplitView(p: Props) {
  const [view, setView] = useState<ViewTransform>({ k: 1, tx: 0, ty: 0 });
  const [size, setSize] = useState<{ w: number; h: number }>({ w: 800, h: 600 });
  const [dragging, setDragging] = useState(false);
  const drag = useRef<{ x: number; y: number; tx: number; ty: number; moved: boolean } | null>(null);
  const firstSvg = useRef<SVGSVGElement | null>(null);
  const userMoved = useRef(false);

  // Track pane size (both panes are equal width, so one observer suffices).
  useEffect(() => {
    const el = firstSvg.current;
    if (!el || typeof ResizeObserver === 'undefined') return;
    const ro = new ResizeObserver((entries) => {
      const r = entries[0]?.contentRect;
      if (r && r.width > 0 && r.height > 0) setSize({ w: r.width, h: r.height });
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const fitTo = useCallback(
    (bbox: { x: number; y: number; w: number; h: number }, pad = 40, maxK = 1.25) => {
      const w = size.w;
      const h = size.h - 40; // leave room for the pane header
      const k = Math.max(MIN_K, Math.min(maxK, (w - pad * 2) / Math.max(1, bbox.w), (h - pad * 2) / Math.max(1, bbox.h)));
      const tx = (w - bbox.w * k) / 2 - bbox.x * k;
      const ty = 40 + (h - bbox.h * k) / 2 - bbox.y * k;
      setView({ k, tx, ty });
    },
    [size],
  );

  const fitAll = useCallback(() => fitTo({ x: 0, y: 0, w: p.layout.width, h: p.layout.height }, 28), [fitTo, p.layout]);

  // Initial fit and refit on resize until the user takes control.
  useEffect(() => {
    if (!userMoved.current) fitAll();
  }, [fitAll]);

  // Fit to the focused nodes when focus changes.
  const focusKey = useMemo(() => (p.focus ? [...p.focus.primary].sort().join('|') + '#' + [...p.focus.secondary].sort().join('|') : ''), [p.focus]);
  useEffect(() => {
    if (!p.focus) return;
    const ids = [...p.focus.primary, ...p.focus.secondary];
    const boxes = ids.map((id) => p.layout.nodes.get(id)).filter((b): b is NonNullable<typeof b> => !!b);
    if (boxes.length === 0) return;
    const x0 = Math.min(...boxes.map((b) => b.x - b.width / 2));
    const y0 = Math.min(...boxes.map((b) => b.y - b.height / 2));
    const x1 = Math.max(...boxes.map((b) => b.x + b.width / 2));
    const y1 = Math.max(...boxes.map((b) => b.y + b.height / 2));
    fitTo({ x: x0, y: y0, w: x1 - x0, h: y1 - y0 }, 60, 1.25);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [focusKey, fitTo]);

  const onWheel = useCallback((e: ReactWheelEvent<SVGSVGElement>) => {
    e.preventDefault();
    userMoved.current = true;
    const rect = e.currentTarget.getBoundingClientRect();
    const cx = e.clientX - rect.left;
    const cy = e.clientY - rect.top;
    setView((v) => {
      const k = Math.max(MIN_K, Math.min(MAX_K, v.k * Math.exp(-e.deltaY * 0.0018)));
      const r = k / v.k;
      return { k, tx: cx - (cx - v.tx) * r, ty: cy - (cy - v.ty) * r };
    });
  }, []);

  const onPointerDown = useCallback((e: ReactPointerEvent<SVGSVGElement>) => {
    if (e.button !== 0) return;
    e.currentTarget.setPointerCapture?.(e.pointerId);
    drag.current = { x: e.clientX, y: e.clientY, tx: view.tx, ty: view.ty, moved: false };
  }, [view]);

  const onPointerMove = useCallback((e: ReactPointerEvent<SVGSVGElement>) => {
    const d = drag.current;
    if (!d) return;
    const dx = e.clientX - d.x;
    const dy = e.clientY - d.y;
    if (!d.moved && Math.hypot(dx, dy) < 3) return;
    d.moved = true;
    userMoved.current = true;
    setDragging(true);
    setView((v) => ({ ...v, tx: d.tx + dx, ty: d.ty + dy }));
  }, []);

  const onPointerUp = useCallback(() => {
    drag.current = null;
    setDragging(false);
  }, []);

  // Wheel listeners added by React are passive in some browsers; attach a
  // non-passive one so preventDefault stops page scroll.
  useEffect(() => {
    const el = firstSvg.current?.parentElement?.parentElement;
    if (!el) return;
    const stop = (e: WheelEvent) => { if ((e.target as Element | null)?.closest('svg')) e.preventDefault(); };
    el.addEventListener('wheel', stop, { passive: false });
    return () => el.removeEventListener('wheel', stop);
  }, []);

  const common = { union: p.union, layout: p.layout, delta: p.delta, focus: p.focus, selected: p.selected, view, onSelect: p.onSelect, onWheel, onPointerDown, onPointerMove, onPointerUp, dragging };

  return (
    <div className="split" data-testid="split-view">
      <GraphPane side="base" ref_={p.diff.base.ref} graph={p.base} identical={p.identical} svgRef={(el) => { firstSvg.current = el; }} {...common} />
      <GraphPane side="head" ref_={p.diff.head.ref} graph={p.head} identical={p.identical} {...common} />
      <div className="pane-tools" style={{ right: 10 }}>
        <button type="button" className="iconbtn" title="Fit to view" aria-label="Fit to view" onClick={() => { userMoved.current = false; fitAll(); }}>
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"><path d="M4 9V4h5M20 9V4h-5M4 15v5h5M20 15v5h-5" /></svg>
        </button>
      </div>
    </div>
  );
}
