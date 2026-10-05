import React, { createContext, useContext, useState, useEffect } from 'react';

const AuthContext = createContext({
  token: null,
  user: null,
  login: async () => {},
  logout: () => {},
  loading: true,
});

export function AuthProvider({ children }) {
  const [token, setToken] = useState(() => sessionStorage.getItem('sdb_token'));
  const [user, setUser] = useState(() => {
    const raw = sessionStorage.getItem('sdb_user');
    return raw ? JSON.parse(raw) : null;
  });
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function verify() {
      if (!token) {
        setLoading(false);
        return;
      }
      try {
        const res = await fetch('/api/auth/me', {
          headers: { Authorization: `Bearer ${token}` },
        });
        if (res.ok) {
          const data = await res.json();
          setUser(data);
          sessionStorage.setItem('sdb_user', JSON.stringify(data));
        } else {
          logout();
        }
      } catch {
        // offline or connection issue
      } finally {
        setLoading(false);
      }
    }
    verify();
  }, [token]);

  const login = async (username, password) => {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Authentication failed' }));
      throw new Error(err.detail || 'Authentication failed');
    }
    const data = await res.json();
    setToken(data.token);
    setUser(data.user);
    sessionStorage.setItem('sdb_token', data.token);
    sessionStorage.setItem('sdb_user', JSON.stringify(data.user));
    return data.user;
  };

  const logout = () => {
    setToken(null);
    setUser(null);
    sessionStorage.removeItem('sdb_token');
    sessionStorage.removeItem('sdb_user');
  };

  return (
    <AuthContext.Provider value={{ token, user, login, logout, loading }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  return useContext(AuthContext);
}
