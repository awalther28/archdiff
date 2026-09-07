export function Legend() {
  return (
    <div className="legend" aria-label="Legend">
      <span className="item"><svg width="26" height="10"><line x1="0" y1="5" x2="26" y2="5" stroke="var(--text-2)" strokeWidth="1.6" /></svg><span className="lbl">confirmed edge</span></span>
      <span className="item"><svg width="26" height="10"><line x1="0" y1="5" x2="26" y2="5" stroke="var(--uncertain)" strokeWidth="1.6" strokeDasharray="5 4" /></svg><span className="lbl">? not evaluated</span></span>
      <span className="item"><svg width="26" height="10"><line x1="0" y1="5" x2="26" y2="5" stroke="var(--cross)" strokeWidth="2.2" /></svg><span className="lbl">crosses scope</span></span>
      <span className="item"><svg width="14" height="12"><rect x="1" y="1" width="12" height="10" rx="2" fill="none" stroke="var(--added)" strokeWidth="2" /></svg><span className="lbl">added</span></span>
      <span className="item"><svg width="14" height="12"><rect x="1" y="1" width="12" height="10" rx="2" fill="none" stroke="var(--removed)" strokeWidth="2" /></svg><span className="lbl">removed</span></span>
      <span className="item"><svg width="14" height="12"><rect x="1" y="1" width="12" height="10" rx="2" fill="none" stroke="var(--changed)" strokeWidth="2" /></svg><span className="lbl">changed</span></span>
      <span className="item"><svg width="14" height="12"><rect x="1" y="1" width="12" height="10" rx="2" fill="url(#hatch)" stroke="var(--uncertain)" strokeWidth="1.2" strokeDasharray="3 2" /></svg><span className="lbl">unresolved at plan</span></span>
      <span className="item"><svg width="14" height="12"><rect x="1" y="1" width="12" height="10" rx="2" fill="var(--surface-2)" stroke="var(--text-3)" strokeWidth="1.2" strokeDasharray="2 2" /></svg><span className="lbl">external</span></span>
      <span className="item"><svg width="14" height="12"><rect x="1" y="1" width="12" height="10" rx="2" fill="var(--ink)" /><text x="7" y="9.5" textAnchor="middle" fontSize="9" fontWeight="700" fill="var(--ink-text)" fontFamily="var(--font-mono)">*</text></svg><span className="lbl">wildcard</span></span>
    </div>
  );
}
