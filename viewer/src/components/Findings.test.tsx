import { fireEvent, render, screen, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { DiffView } from './DiffView';
import { baseGraph, headGraph, starDiff } from '../test/fixtures';

const scenario = { id: 'star', label: 'PR-1', base: 'base.graph.json', head: 'head.graph.json', diff: 'expected.diff.json' };
const POLICY = 'aws:111122223333:us-east-1/aws_iam_policy.app_data';

describe('findings panel', () => {
  it('lists findings in rank order with severity, kind, title and detail', () => {
    const diff = starDiff();
    diff.findings.push({ rank: 2, severity: 'low', kind: 'structural_change', title: 'Second finding', node_ids: [] });
    diff.findings.reverse(); // out of order on purpose
    render(<DiffView scenario={scenario} base={baseGraph()} head={headGraph()} diff={diff} />);
    const cards = screen.getAllByTestId('finding');
    expect(cards).toHaveLength(2);
    expect(cards[0]).toHaveTextContent('01');
    expect(cards[0]).toHaveTextContent('high');
    expect(cards[0]).toHaveTextContent('New wildcard capability');
    expect(cards[0]).toHaveTextContent('app-admin role gained s3:* on all resources');
    expect(cards[0]).toHaveTextContent(/widened from/);
    expect(cards[1]).toHaveTextContent('Second finding');
  });

  it('clicking a finding focuses its nodes in both panes and dims the rest', () => {
    render(<DiffView scenario={scenario} base={baseGraph()} head={headGraph()} diff={starDiff()} />);
    const card = screen.getByTestId('finding');
    fireEvent.click(card);
    expect(card).toHaveAttribute('aria-pressed', 'true');
    for (const paneId of ['pane-base', 'pane-head']) {
      const pane = screen.getByTestId(paneId);
      const policy = pane.querySelector(`[data-node-id="${POLICY}"]`)!;
      expect(policy.querySelector('.node-halo')).not.toBeNull();
      expect(policy).not.toHaveClass('dimmed');
      const gha = pane.querySelector('[data-node-id$="aws_iam_role.gha"]')!;
      expect(gha).toHaveClass('dimmed');
    }
    // Escape clears focus
    fireEvent.keyDown(window, { key: 'Escape' });
    expect(card).toHaveAttribute('aria-pressed', 'false');
    expect(screen.getByTestId('pane-base').querySelector('[data-node-id$="aws_iam_role.gha"]')).not.toHaveClass('dimmed');
  });

  it('shows the semantic capability delta with the wildcard called out', () => {
    render(<DiffView scenario={scenario} base={baseGraph()} head={headGraph()} diff={starDiff()} />);
    const added = screen.getByTestId('capability-added');
    expect(added).toHaveTextContent('s3:*');
    expect(within(added).getByText('*', { selector: '.chip.wild' })).toBeInTheDocument();
    const removed = screen.getByTestId('capability-removed');
    expect(removed).toHaveTextContent('s3:GetObject, s3:ListBucket');
  });

  it('shows load-bearing stats and refs', () => {
    const slot = document.createElement('div');
    slot.id = 'topbar-slot';
    document.body.appendChild(slot);
    render(<DiffView scenario={scenario} base={baseGraph()} head={headGraph()} diff={starDiff()} />);
    expect(slot).toHaveTextContent('main');
    expect(slot).toHaveTextContent('pr-1-star-policy');
    expect(slot).toHaveTextContent('10 nodes compared');
    expect(slot).toHaveTextContent('0 modules skipped');
    slot.remove();
  });
});

describe('graph rendering of special nodes and deltas', () => {
  it('renders wildcard, unresolved and external nodes distinctly', () => {
    render(<DiffView scenario={scenario} base={baseGraph()} head={headGraph()} diff={starDiff()} />);
    const pane = screen.getByTestId('pane-head');
    const wild = pane.querySelector('[data-node-id$="wildcard.all"]')!;
    expect(wild).toHaveAttribute('data-wildcard', 'true');
    expect(wild).toHaveClass('wildcard');
    expect(wild).toHaveTextContent('*');
    const kms = pane.querySelector('[data-node-id$="aws_kms_key.main"]')!;
    expect(kms).toHaveAttribute('data-resolution', 'unresolved_at_plan');
    expect(kms).toHaveClass('unresolved');
    expect(within(kms as HTMLElement).getByText('?')).toBeInTheDocument();
    const ext = pane.querySelector('[data-node-id$="external.audit_role"]')!;
    expect(ext).toHaveClass('external');
    expect(within(ext as HTMLElement).getByText('ext')).toBeInTheDocument();
  });

  it('marks the changed edge on both sides, pointing at the bucket before and the wildcard after', () => {
    render(<DiffView scenario={scenario} base={baseGraph()} head={headGraph()} diff={starDiff()} />);
    const before = screen.getByTestId('pane-base').querySelectorAll('[data-edge-id$="#stmt:ReadData"]');
    const after = screen.getByTestId('pane-head').querySelectorAll('[data-edge-id$="#stmt:ReadData"]');
    expect(before).toHaveLength(1);
    expect(after).toHaveLength(1);
    expect(before[0]).toHaveAttribute('data-delta', 'changed');
    expect(after[0]).toHaveAttribute('data-delta', 'changed');
    expect(before[0]).toHaveTextContent('s3:GetObject, s3:ListBucket');
    expect(after[0]).toHaveTextContent('s3:* on *');
    // every other edge is unchanged
    const others = [...screen.getByTestId('pane-head').querySelectorAll('[data-testid="edge"]')].filter((e) => !e.getAttribute('data-edge-id')!.endsWith('#stmt:ReadData'));
    expect(others.length).toBe(7);
    for (const e of others) expect(e).toHaveAttribute('data-delta', 'unchanged');
  });

  it('opens the inspector with a before/after comparison when the changed edge is clicked', () => {
    render(<DiffView scenario={scenario} base={baseGraph()} head={headGraph()} diff={starDiff()} />);
    const edge = screen.getByTestId('pane-head').querySelector('[data-edge-id$="#stmt:ReadData"]')!;
    fireEvent.click(edge);
    const insp = screen.getByTestId('inspector');
    expect(insp).toHaveTextContent('changed');
    expect(insp).toHaveTextContent('before · main');
    expect(insp).toHaveTextContent('after · pr-1-star-policy');
    expect(insp).toHaveTextContent('s3:GetObject, s3:ListBucket');
    expect(insp).toHaveTextContent('s3:*');
    expect(insp).toHaveTextContent('wildcard.all');
  });

  it('warns visibly on a low-confidence scope and lists it under Not evaluated', () => {
    const head = headGraph();
    for (const n of head.nodes) if (n.scope.key.startsWith('aws:9999')) n.scope = { ...n.scope, confidence: 'low', source: 'variable_heuristic' };
    head.scopes = head.scopes.map((s) => (s.key.startsWith('aws:9999') ? { ...s, confidence: 'low', source: 'variable_heuristic' } : s));
    render(<DiffView scenario={scenario} base={baseGraph()} head={head} diff={starDiff()} />);
    const pane = screen.getByTestId('pane-head');
    expect(within(pane).getByTestId('scope-low-confidence')).toHaveTextContent(/low-confidence scope/i);
    const cluster = pane.querySelector('[data-scope="aws:999988887777:us-east-1"]')!;
    expect(cluster).toHaveAttribute('data-confidence', 'low');
    expect(cluster.querySelector('.cluster-box')).toHaveClass('low');
    expect(screen.getByTestId('unknown-scope')).toHaveTextContent('aws:999988887777:us-east-1');
  });

  it('draws ghosts for nodes absent on one side so both panes keep the same coordinate system', () => {
    const head = headGraph();
    const diff = starDiff();
    const extra = { ...head.nodes[0], id: 'aws:111122223333:us-east-1/aws_iam_role.new', logical_address: 'aws_iam_role.new', name: 'new-role', type: 'principal' as const, digest: '0000000000000001' };
    head.nodes.push(extra);
    diff.structural.nodes.added.push(extra.id);
    render(<DiffView scenario={scenario} base={baseGraph()} head={head} diff={diff} />);
    const b = screen.getByTestId('pane-base').querySelector(`[data-node-id="${extra.id}"]`)!;
    const a = screen.getByTestId('pane-head').querySelector(`[data-node-id="${extra.id}"]`)!;
    expect(b).toHaveAttribute('data-ghost', 'true');
    expect(a).toHaveAttribute('data-ghost', 'false');
    expect(a).toHaveAttribute('data-delta', 'added');
    expect(a.getAttribute('transform')).toEqual(b.getAttribute('transform'));
  });
});
