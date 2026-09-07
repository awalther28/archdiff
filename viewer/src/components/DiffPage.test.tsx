import { render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { DiffPage } from './DiffPage';

function mockFetch() {
  return vi.fn(async (url: string) => {
    const name = url.split('/').pop()!;
    try {
      const body = readFileSync(join(process.cwd(), 'public', 'data', name), 'utf8');
      return { ok: true, status: 200, statusText: 'OK', json: async () => JSON.parse(body) };
    } catch {
      return { ok: false, status: 404, statusText: 'Not Found', json: async () => ({}) };
    }
  });
}

describe('DiffPage runtime loading', () => {
  beforeEach(() => { vi.stubGlobal('fetch', mockFetch()); });
  afterEach(() => { vi.unstubAllGlobals(); });

  it('fetches base, head and diff from data/ at runtime and renders the star-policy scenario', async () => {
    render(<DiffPage scenario={{ id: 'star', label: 'PR-1', base: 'base.graph.json', head: 'head.graph.json', diff: 'expected.diff.json' }} />);
    expect(await screen.findByTestId('diff-view')).toHaveAttribute('data-empty', 'false');
    expect(screen.getByTestId('finding')).toHaveTextContent('s3:*');
    const calls = (fetch as unknown as ReturnType<typeof vi.fn>).mock.calls.map((c) => c[0] as string);
    expect(calls).toEqual(expect.arrayContaining(['/data/base.graph.json', '/data/head.graph.json', '/data/expected.diff.json']));
  });

  it('renders the empty-diff scenario', async () => {
    render(<DiffPage scenario={{ id: 'noop', label: 'PR-2', base: 'base.graph.json', head: 'refactor-noop.graph.json', diff: 'refactor-noop.diff.json' }} />);
    expect(await screen.findByTestId('empty-diff')).toBeInTheDocument();
  });

  it('reports a missing file instead of rendering a blank page', async () => {
    render(<DiffPage scenario={{ id: 'x', label: 'X', base: 'base.graph.json', head: 'missing.graph.json', diff: 'expected.diff.json' }} />);
    expect(await screen.findByRole('alert')).toHaveTextContent(/404/);
  });
});
