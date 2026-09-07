import { render, screen, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { PathRow } from './FindingsPanel';
import { DiffView } from './DiffView';
import { baseGraph, headGraph, starDiff } from '../test/fixtures';
import type { PathEntry } from '../schema/types';

const scenario = { id: 'star', label: 'PR-1', base: 'base.graph.json', head: 'head.graph.json', diff: 'expected.diff.json' };

describe('conditional vs confirmed (SCHEMA.md §4, §7)', () => {
  const conditionalPath: PathEntry = {
    path: ['aws:111122223333:us-east-1/external.audit_role', 'aws:111122223333:us-east-1/aws_iam_role.app_admin'],
    hops: 1,
    crosses_scopes: false,
    terminal_capabilities: ['s3:GetObject'],
    confidence: 'conditional',
  };
  const confirmedPath: PathEntry = {
    path: ['aws:999988887777:us-east-1/aws_iam_role.gha', 'aws:999988887777:us-east-1/aws_iam_role.mgmt_deploy', 'aws:111122223333:us-east-1/aws_iam_role.app_admin'],
    hops: 2,
    crosses_scopes: true,
    terminal_capabilities: ['s3:GetObject', 's3:ListBucket'],
    confidence: 'confirmed',
  };

  it('a conditional path is never presented as confirmed', () => {
    render(<PathRow p={conditionalPath} sign="added" graph={headGraph()} focus={null} onFocus={() => {}} />);
    const row = screen.getByTestId('path-added');
    expect(row).toHaveAttribute('data-confidence', 'conditional');
    expect(row).toHaveClass('conditional');
    const chip = within(row).getByText(/conditional/, { selector: '.chip' });
    expect(chip).toHaveAttribute('data-confidence', 'conditional');
    expect(chip).toHaveTextContent('? conditional');
    expect(within(row).queryByText('confirmed', { selector: '.chip' })).not.toBeInTheDocument();
    expect(row.querySelector('[data-confidence="confirmed"]')).toBeNull();
    // and it says why, in words
    expect(within(row).getByText(/could not be evaluated/i)).toBeInTheDocument();
    expect(within(row).getByText(/not counted as a confirmed capability/i)).toBeInTheDocument();
  });

  it('a confirmed path is presented as confirmed, with its cross-scope marker', () => {
    render(<PathRow p={confirmedPath} sign="added" graph={headGraph()} focus={null} onFocus={() => {}} />);
    const row = screen.getByTestId('path-added');
    expect(row).toHaveAttribute('data-confidence', 'confirmed');
    expect(within(row).getByText('confirmed', { selector: '.chip' })).toHaveAttribute('data-confidence', 'confirmed');
    expect(within(row).queryByText(/conditional/)).not.toBeInTheDocument();
    expect(within(row).getByText('crosses scope')).toBeInTheDocument();
  });

  it('downgrades a path the differ labelled confirmed when the graph shows an unevaluated hop', () => {
    const mislabeled: PathEntry = { ...conditionalPath, confidence: 'confirmed' };
    render(<PathRow p={mislabeled} sign="added" graph={headGraph()} focus={null} onFocus={() => {}} />);
    expect(screen.getByTestId('path-added')).toHaveAttribute('data-confidence', 'conditional');
  });

  it('renders unevaluated edges with an explicit marker in both panes', () => {
    render(<DiffView scenario={scenario} base={baseGraph()} head={headGraph()} diff={starDiff()} />);
    for (const paneId of ['pane-base', 'pane-head']) {
      const pane = screen.getByTestId(paneId);
      const audit = pane.querySelector('[data-edge-id$="#trust:audit"]')!;
      expect(audit).toHaveAttribute('data-unevaluated', 'true');
      expect(within(audit as HTMLElement).getByTestId('unevaluated-marker')).toHaveTextContent('condition');
      const kms = pane.querySelector('[data-edge-id$="#stmt:unresolved"]')!;
      expect(kms).toHaveAttribute('data-unevaluated', 'true');
      const mgmt = pane.querySelector('[data-edge-id$="#trust:mgmt"]')!;
      expect(mgmt).toHaveAttribute('data-unevaluated', 'false');
      expect(mgmt).toHaveAttribute('data-cross-scope', 'true');
      expect(within(mgmt as HTMLElement).getByTestId('cross-scope-marker')).toBeInTheDocument();
      const attach = pane.querySelector('[data-edge-id$="#attach:app_data"]')!;
      expect(attach).toHaveAttribute('data-cross-scope', 'false');
    }
  });

  it('capability rows carry their confidence', () => {
    const diff = starDiff();
    diff.semantic.capabilities.added.push({ principal: 'aws:111122223333:us-east-1/aws_iam_role.app_admin', actions: ['kms:Decrypt'], resource_patterns: ['*'], confidence: 'conditional' });
    render(<DiffView scenario={scenario} base={baseGraph()} head={headGraph()} diff={diff} />);
    const rows = screen.getAllByTestId('capability-added');
    expect(rows.map((r) => r.getAttribute('data-confidence'))).toEqual(['confirmed', 'conditional']);
    expect(rows[1]).toHaveClass('conditional');
  });
});
