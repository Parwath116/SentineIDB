import React from 'react';
import { useTheme } from '../context/ThemeContext';

export default function CookieBanner() {
  const { consent, updateConsent, showCookieModal, setShowCookieModal } = useTheme();

  // If first visit, show bottom banner
  const isFirstVisit = consent === null;

  if (!isFirstVisit && !showCookieModal) {
    return null;
  }

  return (
    <div
      role="dialog"
      aria-labelledby="cookie-banner-title"
      aria-describedby="cookie-banner-desc"
      style={{
        position: 'fixed',
        bottom: showCookieModal ? '50%' : '16px',
        left: showCookieModal ? '50%' : '16px',
        transform: showCookieModal ? 'translate(-50%, 50%)' : 'none',
        maxWidth: showCookieModal ? '480px' : '520px',
        width: 'calc(100% - 32px)',
        backgroundColor: 'var(--bg-surface)',
        border: '1px solid var(--border)',
        borderRadius: '8px',
        boxShadow: 'var(--shadow-xl)',
        padding: '20px',
        zIndex: 1000,
        transition: 'all var(--transition-normal)',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: '12px', marginBottom: '12px' }}>
        <div style={{ padding: '6px', borderRadius: '6px', background: 'var(--accent-light)', color: 'var(--accent)' }}>
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 2a10 10 0 1 0 10 10 4 4 0 0 1-5-5 4 4 0 0 1-5-5" />
            <path d="M8.5 8.5v.01" />
            <path d="M16 15.5v.01" />
            <path d="M12 12v.01" />
            <path d="M11 17v.01" />
            <path d="M7 13v.01" />
          </svg>
        </div>
        <div style={{ flex: 1 }}>
          <h3 id="cookie-banner-title" style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '4px' }}>
            {showCookieModal ? 'Privacy & Preference Settings' : 'Telemetry & Preference Storage'}
          </h3>
          <p id="cookie-banner-desc" style={{ fontSize: '13px', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
            SentinelDB stores only local interface settings: dark/light theme choice and analyst session tokens. No third-party tracking, advertising, or profiling cookies are used.
          </p>
        </div>
      </div>

      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px', marginTop: '16px' }}>
        <button
          type="button"
          onClick={() => {
            updateConsent('declined');
            setShowCookieModal(false);
          }}
          style={{
            padding: '8px 16px',
            fontSize: '13px',
            fontWeight: 500,
            borderRadius: '6px',
            backgroundColor: 'transparent',
            border: '1px solid var(--border)',
            color: 'var(--text-secondary)',
            cursor: 'pointer',
            transition: 'background-color var(--transition-normal), border-color var(--transition-normal)',
          }}
          onMouseEnter={(e) => (e.currentTarget.style.backgroundColor = 'var(--bg-surface-raised)')}
          onMouseLeave={(e) => (e.currentTarget.style.backgroundColor = 'transparent')}
        >
          Decline (Session Only)
        </button>
        <button
          type="button"
          onClick={() => {
            updateConsent('accepted');
            setShowCookieModal(false);
          }}
          style={{
            padding: '8px 18px',
            fontSize: '13px',
            fontWeight: 500,
            borderRadius: '6px',
            backgroundColor: 'var(--accent)',
            border: 'none',
            color: '#ffffff',
            cursor: 'pointer',
            transition: 'background-color var(--transition-normal)',
          }}
          onMouseEnter={(e) => (e.currentTarget.style.backgroundColor = 'var(--accent-hover)')}
          onMouseLeave={(e) => (e.currentTarget.style.backgroundColor = 'var(--accent)')}
        >
          Accept Preferences
        </button>
      </div>
    </div>
  );
}
