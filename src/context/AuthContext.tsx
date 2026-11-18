import React, { createContext, useCallback, useContext, useEffect, useState } from 'react';
import type { StudentUser } from '../../shared/types';
import { apiRequest, setCsrfToken } from '../api/client';

interface AuthContextValue {
  user: StudentUser | null;
  loading: boolean;
  sessionNotice: string | null;
  clearSessionNotice: () => void;
  login: (email: string, password: string) => Promise<void>;
  register: (params: {
    fullName: string;
    email: string;
    password: string;
    confirmPassword: string;
  }) => Promise<void>;
  logout: () => Promise<void>;
  refreshSession: () => Promise<void>;
  setUser: React.Dispatch<React.SetStateAction<StudentUser | null>>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<StudentUser | null>(null);
  const [loading, setLoading] = useState(true);
  const [sessionNotice, setSessionNotice] = useState<string | null>(null);

  const clearSessionNotice = useCallback(() => {
    setSessionNotice(null);
  }, []);

  const refreshSession = useCallback(async () => {
    try {
      const res = await apiRequest<{ user: StudentUser; csrfToken: string }>('/api/auth/me');
      setCsrfToken(res.csrfToken);
      setUser(res.user);
      setSessionNotice(null);
    } catch {
      setCsrfToken(null);
      setUser(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refreshSession();
  }, [refreshSession]);

  useEffect(() => {
    function handleAuthExpired(event: Event) {
      const detail = (event as CustomEvent<{ message?: string }>).detail;
      setCsrfToken(null);
      setUser(null);
      setSessionNotice(
        detail?.message || 'Your session has expired. Please sign in again to continue.'
      );
    }
    window.addEventListener('securelens:auth-expired', handleAuthExpired);
    return () => {
      window.removeEventListener('securelens:auth-expired', handleAuthExpired);
    };
  }, []);

  const login = useCallback(async (email: string, password: string) => {
    const res = await apiRequest<{ user: StudentUser; csrfToken: string }>('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });
    setCsrfToken(res.csrfToken);
    setUser(res.user);
    setSessionNotice(null);
  }, []);

  const register = useCallback(
    async (params: { fullName: string; email: string; password: string; confirmPassword: string }) => {
      const res = await apiRequest<{ user: StudentUser; csrfToken: string }>('/api/auth/register', {
        method: 'POST',
        body: JSON.stringify(params),
      });
      setCsrfToken(res.csrfToken);
      setUser(res.user);
      setSessionNotice(null);
    },
    []
  );

  const logout = useCallback(async () => {
    try {
      await apiRequest('/api/auth/logout', { method: 'POST' });
    } finally {
      setCsrfToken(null);
      setUser(null);
      setSessionNotice(null);
    }
  }, []);

  return (
    <AuthContext.Provider
      value={{
        user,
        loading,
        sessionNotice,
        clearSessionNotice,
        login,
        register,
        logout,
        refreshSession,
        setUser,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used inside AuthProvider');
  return ctx;
}
