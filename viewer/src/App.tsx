import { useEffect, useState } from 'react';
import { Navigate, NavLink, Route, Routes, useParams } from 'react-router-dom';
import { loadManifest } from './lib/load';
import { applyTheme, nextTheme, readTheme, type Theme } from './lib/theme';
import type { Manifest } from './schema/types';
import { DiffPage } from './components/DiffPage';

export function App() {
  const [manifest, setManifest] = useState<Manifest | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [theme, setTheme] = useState<Theme>(() => readTheme());

  useEffect(() => {
    loadManifest().then(setManifest).catch((e: Error) => setError(e.message));
  }, []);

  useEffect(() => applyTheme(theme), [theme]);

  if (error) {
    return (
      <div className="state error">
        <div>Could not load <code>data/scenarios.json</code></div>
        <code>{error}</code>
      </div>
    );
  }
  if (!manifest) return <div className="state">Loading…</div>;
  const first = manifest.scenarios[0];

  return (
    <Routes>
      <Route
        path="/s/:id"
        element={<Shell manifest={manifest} theme={theme} onTheme={() => setTheme(nextTheme(theme))} />}
      />
      <Route path="*" element={first ? <Navigate to={`/s/${first.id}`} replace /> : <div className="state">No scenarios in manifest</div>} />
    </Routes>
  );
}

function Shell({ manifest, theme, onTheme }: { manifest: Manifest; theme: Theme; onTheme: () => void }) {
  const { id } = useParams();
  const scenario = manifest.scenarios.find((s) => s.id === id);
  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <span className="name">Permission Graph</span>
          <span className="ver">diff · schema 1.0</span>
        </div>
        <nav className="tabs" aria-label="Scenarios">
          {manifest.scenarios.map((s) => (
            <NavLink key={s.id} to={`/s/${s.id}`} className={({ isActive }) => `tab${isActive ? ' active' : ''}`} title={s.summary}>
              {s.label}
            </NavLink>
          ))}
        </nav>
        <div className="spacer" />
        <div id="topbar-slot" style={{ display: 'contents' }} />
        <button className="iconbtn" onClick={onTheme} title={`Theme: ${theme} (click to change)`} aria-label={`Theme: ${theme}`}>
          {theme === 'dark' ? <MoonIcon /> : theme === 'light' ? <SunIcon /> : <AutoIcon />}
        </button>
      </header>
      {scenario ? <DiffPage key={scenario.id} scenario={scenario} /> : <div className="state">Unknown scenario “{id}”</div>}
    </div>
  );
}

function SunIcon() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round">
      <circle cx="12" cy="12" r="4" />
      <path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" />
    </svg>
  );
}
function MoonIcon() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z" />
    </svg>
  );
}
function AutoIcon() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
      <circle cx="12" cy="12" r="9" />
      <path d="M12 3a9 9 0 0 1 0 18z" fill="currentColor" stroke="none" />
    </svg>
  );
}
