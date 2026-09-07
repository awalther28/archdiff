import { render, screen, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { DiffView } from './DiffView';
import { baseGraph, headGraph, noopDiff, noopGraph } from '../test/fixtures';

const scenario = { id: 'refactor-noop', label: 'PR-2', base: 'base.graph.json', head: 'refactor-noop.graph.json', diff: 'refactor-noop.diff.json' };

describe('empty diff (SCHEMA.md §8)', () => {
  it('renders an affirmative "no permission changes" result, not an empty container', () => {
    render(<DiffView scenario={scenario} base={baseGraph()} head={noopGraph()} diff={noopDiff()} />);
    expect(screen.getByTestId('diff-view')).toHaveAttribute('data-empty', 'true');
    const empty = screen.getByTestId('empty-diff');
    expect(within(empty).getByRole('heading', { name: /no permission changes/i })).toBeInTheDocument();
    // Evidence the viewer computed itself, not just the differ's word.
    expect(within(empty).getAllByText(/digests identical/i)).toHaveLength(2);
    expect(within(empty).getByText('2cc8862700014f6a')).toBeInTheDocument();
    expect(within(empty).getByText(/unchanged/)).toBeInTheDocument();
    expect(empty).toHaveTextContent(/1 module skipped by digest/);
    // No findings list, no inconsistency alert, no spinner.
    expect(screen.queryAllByTestId('finding')).toHaveLength(0);
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    expect(screen.queryByText(/loading/i)).not.toBeInTheDocument();
  });

  it('still draws both graphs, marks them identical, and places every node at the same coordinates on both sides', () => {
    render(<DiffView scenario={scenario} base={baseGraph()} head={noopGraph()} diff={noopDiff()} />);
    const before = screen.getByTestId('pane-base');
    const after = screen.getByTestId('pane-head');
    expect(within(before).getByText('identical')).toBeInTheDocument();
    expect(within(after).getByText('identical')).toBeInTheDocument();
    const bn = within(before).getAllByTestId('node');
    const an = within(after).getAllByTestId('node');
    expect(bn).toHaveLength(10);
    expect(an).toHaveLength(10);
    const pos = (els: HTMLElement[]) => Object.fromEntries(els.map((e) => [e.dataset.nodeId, e.getAttribute('transform')]));
    expect(pos(bn)).toEqual(pos(an));
    for (const n of [...bn, ...an]) expect(n).toHaveAttribute('data-delta', 'unchanged');
  });

  it('keeps the "Not evaluated" section visible with pre-existing unknowns', () => {
    render(<DiffView scenario={scenario} base={baseGraph()} head={noopGraph()} diff={noopDiff()} />);
    const un = screen.getByTestId('unevaluated');
    expect(within(un).getByText(/did not change/i)).toBeInTheDocument();
    expect(within(un).getAllByTestId('unknown-edge')).toHaveLength(2);
    expect(within(un).getAllByTestId('unknown-node')).toHaveLength(3);
  });

  it('flags a diff that claims empty while the graphs actually differ', () => {
    render(<DiffView scenario={scenario} base={baseGraph()} head={headGraph()} diff={noopDiff()} />);
    expect(screen.getByRole('alert')).toHaveTextContent(/inconsistent/i);
  });
});
