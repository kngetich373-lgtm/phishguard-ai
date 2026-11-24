import { createContext, useContext, useEffect, useState } from "react";
import { fetchMe, logoutUser } from "../api/client";

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const token = localStorage.getItem("pg_token");
    if (!token) {
      setLoading(false);
      return;
    }
    fetchMe()
      .then((res) => setUser(res.data))
      .catch(() => {
        localStorage.removeItem("pg_token");
        localStorage.removeItem("pg_refresh_token");
      })
      .finally(() => setLoading(false));
  }, []);

  const login = (token, userData, refreshToken) => {
    localStorage.setItem("pg_token", token);
    if (refreshToken) localStorage.setItem("pg_refresh_token", refreshToken);
    setUser(userData);
  };

  const logout = async () => {
    const refreshToken = localStorage.getItem("pg_refresh_token");
    try {
      await logoutUser(refreshToken);
    } catch (error) {
      console.error("Could not revoke the server session during logout", error);
    }
    localStorage.removeItem("pg_refresh_token");
    localStorage.removeItem("pg_token");
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ user, login, logout, loading }}>
      {children}
    </AuthContext.Provider>
  );
}

export const useAuth = () => useContext(AuthContext);
