import React, { createContext, useContext, useEffect, useState } from 'react';

const ThemeContext = createContext({
  theme: 'light',
  toggleTheme: () => {},
  consent: null,
  updateConsent: () => {},
  showCookieModal: false,
  setShowCookieModal: () => {},
});

export function ThemeProvider({ children }) {
  const [consent, setConsent] = useState(() => {
    try {
      return localStorage.getItem('sdb_consent');
    } catch {
      return null;
    }
  });

  const [showCookieModal, setShowCookieModal] = useState(false);

  const [theme, setTheme] = useState(() => {
    try {
      const storedConsent = localStorage.getItem('sdb_consent');
      if (storedConsent === 'accepted') {
        const saved = localStorage.getItem('sdb_theme');
        if (saved) return saved;
      }
      return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    } catch {
      return 'light';
    }
  });

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    if (consent === 'accepted') {
      try {
        localStorage.setItem('sdb_theme', theme);
      } catch {}
    } else {
      try {
        localStorage.removeItem('sdb_theme');
      } catch {}
    }
  }, [theme, consent]);

  useEffect(() => {
    const mq = window.matchMedia('(prefers-color-scheme: dark)');
    const handler = (e) => {
      if (consent !== 'accepted') {
        setTheme(e.matches ? 'dark' : 'light');
      }
    };
    mq.addEventListener('change', handler);
    return () => mq.removeEventListener('change', handler);
  }, [consent]);

  const toggleTheme = () => {
    setTheme((prev) => (prev === 'dark' ? 'light' : 'dark'));
  };

  const updateConsent = (val) => {
    setConsent(val);
    try {
      localStorage.setItem('sdb_consent', val);
      if (val === 'accepted') {
        localStorage.setItem('sdb_theme', theme);
      } else {
        localStorage.removeItem('sdb_theme');
      }
    } catch {}
  };

  return (
    <ThemeContext.Provider
      value={{
        theme,
        toggleTheme,
        consent,
        updateConsent,
        showCookieModal,
        setShowCookieModal,
      }}
    >
      {children}
    </ThemeContext.Provider>
  );
}

export function useTheme() {
  return useContext(ThemeContext);
}
