import React, { createContext, useCallback, useContext, useEffect, useState } from "react";
import { alertsApi, authApi, getStoredToken, setStoredToken } from "../services/api";

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [openAlertsCount, setOpenAlertsCount] = useState(0);

  const refreshOpenAlertsCount = useCallback(async () => {
    if (!getStoredToken()) {
      setOpenAlertsCount(0);
      return;
    }
    try {
      const data = await alertsApi.list("OPEN");
      setOpenAlertsCount((data.alerts || []).length);
    } catch {
      // Ignore transient errors when refreshing badge
    }
  }, []);

  const loadSession = useCallback(async () => {
    const token = getStoredToken();
    if (!token) {
      setUser(null);
      setLoading(false);
      return;
    }
    try {
      const data = await authApi.me();
      setUser(data.user);
      await refreshOpenAlertsCount();
    } catch {
      setStoredToken(null);
      setUser(null);
    } finally {
      setLoading(false);
    }
  }, [refreshOpenAlertsCount]);

  useEffect(() => {
    loadSession();
  }, [loadSession]);

  const login = async (identifier, masterPassword) => {
    const data = await authApi.login({ identifier, master_password: masterPassword });
    setStoredToken(data.access_token);
    setUser(data.user);
    await refreshOpenAlertsCount();
    return data;
  };

  const register = async (username, email, masterPassword) => {
    return authApi.register({ username, email, master_password: masterPassword });
  };

  const logout = async () => {
    try {
      if (getStoredToken()) {
        await authApi.logout();
      }
    } catch {
      // Clear local session even if server token already expired
    } finally {
      setStoredToken(null);
      setUser(null);
      setOpenAlertsCount(0);
    }
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        loading,
        openAlertsCount,
        refreshOpenAlertsCount,
        login,
        register,
        logout,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error("useAuth must be used inside an AuthProvider");
  }
  return ctx;
}
