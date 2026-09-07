import type { PathConfidence } from '../schema/types';
import { shortAddress } from '../lib/derive';

export function SeverityChip({ severity }: { severity?: string }) {
  if (!severity) return null;
  return <span className={`chip sev-${severity}`}>{severity}</span>;
}

/**
 * Confirmed vs conditional must be unmistakable at a glance. Confirmed is
 * solid ink; conditional is an outlined, dashed chip with a question mark,
 * and the word itself is always present so the distinction survives
 * colour-blindness, greyscale printing and screen readers.
 */
export function ConfidenceChip({ confidence }: { confidence: PathConfidence }) {
  return (
    <span className={`chip ${confidence}`} data-confidence={confidence} title={confidence === 'confirmed' ? 'Every edge on this path was fully evaluated' : 'At least one edge on this path could not be evaluated (see Not evaluated)'}>
      {confidence === 'conditional' ? '? conditional' : 'confirmed'}
    </span>
  );
}

export function DeltaChip({ kind }: { kind: 'added' | 'removed' | 'changed' }) {
  return <span className={`chip ${kind}`}>{kind}</span>;
}

export function AddrChip({ id, active, onClick }: { id: string; active?: boolean; onClick?: (id: string) => void }) {
  return (
    <button type="button" className={`addr${active ? ' hi' : ''}`} title={id} onClick={(e) => { e.stopPropagation(); onClick?.(id); }}>
      {shortAddress(id)}
    </button>
  );
}
