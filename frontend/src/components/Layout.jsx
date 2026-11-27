import React, { useState } from "react";
import { NavLink, useNavigate } from "react-router-dom";
import {
  LayoutDashboard,
  KeyRound,
  Activity,
  BellRing,
  Bot,
  Settings,
  LogOut,
  Shield,
  Menu,
  X,
} from "lucide-react";
import { useAuth } from "../context/AuthContext";

export function Layout({ children }) {
  const { user, openAlertsCount, logout } = useAuth();
  const navigate = useNavigate();
  const [mobileOpen, setMobileOpen] = useState(false);

  const handleLogout = async () => {
    await logout();
    navigate("/login");
  };

  const navItems = [
    { to: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
    { to: "/vault", label: "My Vault", icon: KeyRound },
    { to: "/activity", label: "Activity History", icon: Activity },
    {
      to: "/alerts",
      label: "Security Alerts",
      icon: BellRing,
      badge: openAlertsCount > 0 ? openAlertsCount : null,
    },
    { to: "/assistant", label: "AI Security Assistant", icon: Bot },
    { to: "/settings", label: "Account Settings", icon: Settings },
  ];

  return (
    <div className="app-shell">
      <aside className={`sidebar ${mobileOpen ? "open" : ""}`}>
        <div className="brand">
          <div className="brand-icon">
            <Shield size={20} />
          </div>
          <div>
            <div className="brand-title">VaultGuard</div>
            <div className="brand-subtitle">Security & Vault</div>
          </div>
        </div>

        <nav className="nav-list">
          {navItems.map((item) => {
            const Icon = item.icon;
            return (
              <NavLink
                key={item.to}
                to={item.to}
                onClick={() => setMobileOpen(false)}
                className={({ isActive }) => `nav-item ${isActive ? "active" : ""}`}
              >
                <span className="nav-item-left">
                  <Icon size={18} />
                  <span>{item.label}</span>
                </span>
                {item.badge && <span className="nav-badge">{item.badge}</span>}
              </NavLink>
            );
          })}
        </nav>

        <div className="sidebar-footer">
          {user && (
            <div className="user-pill">
              <div className="user-avatar">{user.username?.slice(0, 2).toUpperCase()}</div>
              <div className="user-meta">
                <div className="user-name">{user.username}</div>
                <div className="user-email">{user.email}</div>
              </div>
            </div>
          )}
          <button type="button" className="nav-item" onClick={handleLogout}>
            <span className="nav-item-left">
              <LogOut size={18} />
              <span>Logout</span>
            </span>
          </button>
        </div>
      </aside>

      <div className="main-area">
        <header className="mobile-topbar">
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <Shield size={20} color="#22d3ee" />
            <strong>VaultGuard</strong>
          </div>
          <button
            type="button"
            className="btn btn-secondary btn-sm"
            onClick={() => setMobileOpen((prev) => !prev)}
            aria-label="Toggle navigation"
          >
            {mobileOpen ? <X size={18} /> : <Menu size={18} />}
          </button>
        </header>

        <main className="content-container">{children}</main>
      </div>
    </div>
  );
}
