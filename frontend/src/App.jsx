import React, { useEffect, useState } from 'react';
import { BrowserRouter, Routes, Route, Navigate, useNavigate, useLocation } from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext';
import { ThemeProvider, useTheme } from './context/ThemeContext';

import Navbar from './components/Navbar';
import Footer from './components/Footer';
import ScrollProgress from './components/ScrollProgress';
import BackToTop from './components/BackToTop';
import CookieBanner from './components/CookieBanner';
import ShortcutsModal from './components/ShortcutsModal';
import ErrorBoundary from './components/ErrorBoundary';

import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import Alerts from './pages/Alerts';
import AttackChains from './pages/AttackChains';
import LogSearch from './pages/LogSearch';
import Performance from './pages/Performance';
import Help from './pages/Help';

function ProtectedRoute({ children }) {
  const { user, loading } = useAuth();
  if (loading) {
    return (
      <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <div className="sdb-skeleton" style={{ width: '120px', height: '24px', borderRadius: '4px' }} />
      </div>
    );
  }
  if (!user) {
    return <Navigate to="/login" replace />;
  }
  return children;
}

function GlobalShortcutsHandler({ onOpenShortcuts }) {
  const navigate = useNavigate();
  const location = useLocation();
  const { toggleTheme } = useTheme();

  useEffect(() => {
    let lastKey = '';
    let lastTime = 0;

    const handleKeyDown = (e) => {
      // Ignore if active element is an input, textarea, or select
      const tag = document.activeElement?.tagName?.toLowerCase();
      if (tag === 'input' || tag === 'textarea' || tag === 'select' || document.activeElement?.isContentEditable) {
        return;
      }

      const now = Date.now();
      const key = e.key;

      // Handle '?' for shortcuts modal
      if (key === '?') {
        e.preventDefault();
        onOpenShortcuts();
        return;
      }

      // Handle 't' or 'T' for toggle theme
      if (key.toLowerCase() === 't') {
        e.preventDefault();
        toggleTheme();
        return;
      }

      // Handle '/' for search
      if (key === '/') {
        e.preventDefault();
        if (location.pathname !== '/search') {
          navigate('/search');
        } else {
          const input = document.querySelector('input[type="text"]');
          if (input) input.focus();
        }
        return;
      }

      // Sequence check for 'G' then key
      if (now - lastTime < 1000 && lastKey.toLowerCase() === 'g') {
        const target = key.toLowerCase();
        if (target === 'd') {
          e.preventDefault();
          navigate('/');
        } else if (target === 'a') {
          e.preventDefault();
          navigate('/alerts');
        } else if (target === 'c') {
          e.preventDefault();
          navigate('/chains');
        } else if (target === 's') {
          e.preventDefault();
          navigate('/search');
        }
        lastKey = '';
        return;
      }

      lastKey = key;
      lastTime = now;
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [navigate, location, toggleTheme, onOpenShortcuts]);

  return null;
}

function MainLayout() {
  const [shortcutsOpen, setShortcutsOpen] = useState(false);
  const location = useLocation();
  const isLoginPage = location.pathname === '/login';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', minHeight: '100vh' }}>
      <ScrollProgress />
      <GlobalShortcutsHandler onOpenShortcuts={() => setShortcutsOpen(true)} />

      {!isLoginPage && <Navbar onOpenShortcuts={() => setShortcutsOpen(true)} />}

      <main style={{ flex: 1 }}>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route
            path="/"
            element={
              <ProtectedRoute>
                <ErrorBoundary pageName="Dashboard">
                  <Dashboard />
                </ErrorBoundary>
              </ProtectedRoute>
            }
          />
          <Route
            path="/alerts"
            element={
              <ProtectedRoute>
                <ErrorBoundary pageName="Live Alerts">
                  <Alerts />
                </ErrorBoundary>
              </ProtectedRoute>
            }
          />
          <Route
            path="/chains"
            element={
              <ProtectedRoute>
                <ErrorBoundary pageName="Attack Chains">
                  <AttackChains />
                </ErrorBoundary>
              </ProtectedRoute>
            }
          />
          <Route
            path="/search"
            element={
              <ProtectedRoute>
                <ErrorBoundary pageName="Log Search">
                  <LogSearch />
                </ErrorBoundary>
              </ProtectedRoute>
            }
          />
          <Route
            path="/performance"
            element={
              <ProtectedRoute>
                <ErrorBoundary pageName="Performance & Benchmarks">
                  <Performance />
                </ErrorBoundary>
              </ProtectedRoute>
            }
          />
          <Route
            path="/help"
            element={
              <ProtectedRoute>
                <ErrorBoundary pageName="Help & Documentation">
                  <Help />
                </ErrorBoundary>
              </ProtectedRoute>
            }
          />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>

      {!isLoginPage && <Footer onOpenShortcuts={() => setShortcutsOpen(true)} />}

      <BackToTop />
      <CookieBanner />
      <ShortcutsModal isOpen={shortcutsOpen} onClose={() => setShortcutsOpen(false)} />
    </div>
  );
}

export default function App() {
  return (
    <ThemeProvider>
      <AuthProvider>
        <BrowserRouter>
          <MainLayout />
        </BrowserRouter>
      </AuthProvider>
    </ThemeProvider>
  );
}
