import React from 'react';
import { useTheme } from '../context/ThemeContext';

export default function Footer({ onOpenShortcuts }) {
  const { setShowCookieModal } = useTheme();

  return (
    <footer
      style={{
        marginTop: 'auto',
        borderTop: '1px solid var(--border)',
        backgroundColor: 'var(--bg-surface)',
        padding: '24px 20px',
        fontSize: '12px',
        color: 'var(--text-secondary)',
        transition: 'background-color var(--transition-smooth), border-color var(--transition-smooth)',
      }}
    >
      <div
        style={{
          maxWidth: '1440px',
          margin: '0 auto',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '16px',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>SentinelDB</span>
          <span>•</span>
          <span>Security Event Monitoring & Threat Analytics Platform</span>
          <span>•</span>
          <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>v1.0.0</span>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          <button
            type="button"
            onClick={() => setShowCookieModal(true)}
            style={{
              background: 'none',
              border: 'none',
              color: 'var(--accent)',
              fontSize: '12px',
              cursor: 'pointer',
              textDecoration: 'underline',
              padding: 0,
            }}
          >
            Cookie settings
          </button>
          <span>•</span>
          <button
            type="button"
            onClick={onOpenShortcuts}
            style={{
              background: 'none',
              border: 'none',
              color: 'var(--accent)',
              fontSize: '12px',
              cursor: 'pointer',
              textDecoration: 'underline',
              padding: 0,
            }}
          >
            Keyboard shortcuts
          </button>
        </div>
      </div>
    </footer>
  );
}
