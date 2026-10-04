/* Tresc powiadomienia w panelu. Nowe wpisy maja `data` (sekcje z
   formatting.py): naglowek sekcji, punkty, aplikacje jako mini-paski z
   minutami, tytuly TV jako lista. Stare wpisy (bez `data`) - sam tekst. */
import React from 'react';
import { fmtMinutes } from '../charts';

function Section({ s }) {
  const max = Math.max(1, ...s.apps.map((a) => a.minutes));
  return (
    <div>
      {(s.label || s.summary) && (
        <div className="note-section-head">
          {s.kind === 'tv' && s.label ? '📺 ' : ''}
          {s.label && <strong>{s.label}</strong>}
          {s.label && s.summary && <span className="dim"> · </span>}
          {s.summary && <span className={s.label ? 'dim' : ''}>{s.summary}</span>}
        </div>
      )}
      {s.facts.length > 0 && (
        <ul className="note-list">{s.facts.map((f) => <li key={f}>{f}</li>)}</ul>
      )}
      {s.apps.length > 0 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 4, marginTop: 6 }}>
          {s.facts.length > 0 && <div className="note-sub">{s.apps_label}</div>}
          {s.apps.map((a) => (
            <div key={a.app} className="mini-bar">
              <span className="label">{a.app}</span>
              <div className="bar-track">
                <div className="bar-fill" style={{ width: `${(a.minutes / max) * 100}%`, background: 'var(--gradient-ai)' }} />
              </div>
              <span className="mono dim" style={{ textAlign: 'right' }}>
                {s.approx ? '~' : ''}{fmtMinutes(a.minutes)}
              </span>
            </div>
          ))}
          {s.apps_more > 0 && <span className="dim" style={{ fontSize: '0.76rem' }}>+{s.apps_more} innych</span>}
        </div>
      )}
      {s.titles.length > 0 && (
        <>
          {(s.facts.length > 0 || s.apps.length > 0) && <div className="note-sub">Co leciało</div>}
          <ul className="note-list">
            {s.titles.map((t) => <li key={t}>{t}</li>)}
            {s.titles_more > 0 && <li className="dim">+{s.titles_more} więcej</li>}
          </ul>
        </>
      )}
      {s.exact?.length > 0 && (
        <>
          <div className="note-sub">{s.exact_label || 'Dokładnie'}</div>
          <ul className="note-list">
            {s.exact.map((e) => <li key={e.app}>{e.app} {fmtMinutes(e.minutes)}</li>)}
          </ul>
        </>
      )}
      {s.after?.map((line) => <div key={line} className="dim" style={{ fontSize: '0.78rem', marginTop: 4 }}>{line}</div>)}
    </div>
  );
}

export default function NoteBody({ note }) {
  const sections = note.data?.sections;
  if (!Array.isArray(sections)) {
    return <div className="row-body note-text" style={{ marginTop: 4 }}>{note.text}</div>;
  }
  return (
    <div className="note-sections">
      {sections.map((s, i) => <Section key={`${s.label}-${i}`} s={s} />)}
      {note.data.note && <div className="dim" style={{ fontSize: '0.72rem' }}>{note.data.note}</div>}
    </div>
  );
}
