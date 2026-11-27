import React, { useEffect, useState } from "react";
import {
  Plus,
  Search,
  Eye,
  EyeOff,
  Copy,
  Check,
  Pencil,
  Trash2,
  ExternalLink,
  Lock,
} from "lucide-react";
import { vaultApi } from "../services/api";
import { CredentialModal } from "../components/CredentialModal";
import { formatTimestamp } from "../components/RiskBadge";
import { useAuth } from "../context/AuthContext";

export function VaultPage() {
  const { refreshOpenAlertsCount } = useAuth();
  const [credentials, setCredentials] = useState([]);
  const [search, setSearch] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [feedback, setFeedback] = useState("");

  // Tracks revealed plaintext passwords keyed by credential id
  const [revealedPasswords, setRevealedPasswords] = useState({});
  const [copiedKey, setCopiedKey] = useState("");

  // Modal state
  const [modalOpen, setModalOpen] = useState(false);
  const [modalMode, setModalMode] = useState("add");
  const [editingItem, setEditingItem] = useState(null);

  const loadCredentials = async (query = search) => {
    setLoading(true);
    setError("");
    try {
      const data = await vaultApi.list(query);
      setCredentials(data.credentials || []);
    } catch (err) {
      setError(err.message || "Failed to load credentials.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadCredentials("");
  }, []);

  const handleSearchSubmit = (e) => {
    e.preventDefault();
    loadCredentials(search);
  };

  const handleToggleReveal = async (credId) => {
    if (revealedPasswords[credId]) {
      setRevealedPasswords((prev) => {
        const next = { ...prev };
        delete next[credId];
        return next;
      });
      return;
    }

    try {
      const res = await vaultApi.retrieve(credId);
      setRevealedPasswords((prev) => ({
        ...prev,
        [credId]: res.credential.password,
      }));
      await refreshOpenAlertsCount();
    } catch (err) {
      setError(err.message || "Failed to decrypt credential.");
    }
  };

  const handleCopy = async (cred, field) => {
    try {
      let valueToCopy = cred[field];
      if (field === "password") {
        if (revealedPasswords[cred.id]) {
          valueToCopy = revealedPasswords[cred.id];
        } else {
          const res = await vaultApi.retrieve(cred.id);
          valueToCopy = res.credential.password;
          await refreshOpenAlertsCount();
        }
      }
      await navigator.clipboard.writeText(valueToCopy || "");
      const key = `${cred.id}-${field}`;
      setCopiedKey(key);
      setFeedback(`Copied ${field} for ${cred.website}.`);
      setTimeout(() => {
        setCopiedKey("");
        setFeedback("");
      }, 2200);
    } catch (err) {
      setError(err.message || "Unable to copy to clipboard.");
    }
  };

  const handleOpenAdd = () => {
    setModalMode("add");
    setEditingItem(null);
    setModalOpen(true);
  };

  const handleOpenEdit = async (cred) => {
    try {
      // Retrieve full decrypted credential before editing
      const res = await vaultApi.retrieve(cred.id);
      setModalMode("edit");
      setEditingItem(res.credential);
      setModalOpen(true);
      await refreshOpenAlertsCount();
    } catch (err) {
      setError(err.message || "Unable to load credential for editing.");
    }
  };

  const handleSaveModal = async (payload) => {
    if (modalMode === "edit" && editingItem) {
      await vaultApi.update(editingItem.id, payload);
      setRevealedPasswords((prev) => {
        const next = { ...prev };
        delete next[editingItem.id];
        return next;
      });
      setFeedback(`Updated encrypted credential for ${payload.website}.`);
    } else {
      await vaultApi.create(payload);
      setFeedback(`Encrypted and stored credential for ${payload.website}.`);
    }
    await loadCredentials(search);
    await refreshOpenAlertsCount();
  };

  const handleDelete = async (cred) => {
    if (!window.confirm(`Delete credential for "${cred.website}"? This cannot be undone.`)) {
      return;
    }
    try {
      await vaultApi.remove(cred.id);
      setFeedback(`Deleted credential for ${cred.website}.`);
      await loadCredentials(search);
      await refreshOpenAlertsCount();
    } catch (err) {
      setError(err.message || "Failed to delete credential.");
    }
  };

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">Encrypted Credential Vault</h1>
          <p className="page-subtitle">
            All usernames, passwords, URLs, and notes are protected with AES-256-GCM authenticated encryption
          </p>
        </div>
        <button type="button" className="btn btn-primary" onClick={handleOpenAdd}>
          <Plus size={16} /> Add Credential
        </button>
      </div>

      {error && <div className="alert-banner alert-error">{error}</div>}
      {feedback && <div className="alert-banner alert-success">{feedback}</div>}

      <div className="card" style={{ marginBottom: 20 }}>
        <form onSubmit={handleSearchSubmit} style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
          <div style={{ flex: 1, minWidth: 220, position: "relative" }}>
            <input
              className="input"
              placeholder="Search by website, service, URL, or username..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>
          <button type="submit" className="btn btn-secondary">
            <Search size={15} /> Search
          </button>
          {search && (
            <button
              type="button"
              className="btn btn-secondary"
              onClick={() => {
                setSearch("");
                loadCredentials("");
              }}
            >
              Clear
            </button>
          )}
        </form>
      </div>

      <div className="card">
        {loading ? (
          <p style={{ color: "var(--text-secondary)" }}>Decrypting vault index...</p>
        ) : credentials.length === 0 ? (
          <div style={{ textAlign: "center", padding: "36px 16px" }}>
            <Lock size={34} color="#22d3ee" style={{ marginBottom: 12 }} />
            <h3 style={{ marginBottom: 6 }}>No credentials found</h3>
            <p style={{ color: "var(--text-secondary)", fontSize: "0.9rem", marginBottom: 16 }}>
              Add your first website login to store it safely with AES-256-GCM encryption.
            </p>
            <button type="button" className="btn btn-primary" onClick={handleOpenAdd}>
              <Plus size={16} /> Add Credential
            </button>
          </div>
        ) : (
          <div className="table-wrapper">
            <table className="table">
              <thead>
                <tr>
                  <th>Website / Service</th>
                  <th>Username / Email</th>
                  <th>Password</th>
                  <th>Last Updated</th>
                  <th style={{ textAlign: "right" }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {credentials.map((cred) => {
                  const revealed = revealedPasswords[cred.id];
                  return (
                    <tr key={cred.id}>
                      <td>
                        <div style={{ fontWeight: 600 }}>{cred.website}</div>
                        {cred.url && (
                          <a
                            href={cred.url.startsWith("http") ? cred.url : `https://${cred.url}`}
                            target="_blank"
                            rel="noreferrer"
                            style={{ fontSize: "0.78rem", display: "inline-flex", alignItems: "center", gap: 4 }}
                          >
                            {cred.url} <ExternalLink size={11} />
                          </a>
                        )}
                        {cred.notes && (
                          <div style={{ fontSize: "0.78rem", color: "var(--text-muted)", marginTop: 3 }}>
                            {cred.notes}
                          </div>
                        )}
                      </td>
                      <td>
                        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                          <span className="mono">{cred.username}</span>
                          <button
                            type="button"
                            className="btn btn-secondary btn-sm"
                            onClick={() => handleCopy(cred, "username")}
                            title="Copy username"
                          >
                            {copiedKey === `${cred.id}-username` ? <Check size={13} /> : <Copy size={13} />}
                          </button>
                        </div>
                      </td>
                      <td>
                        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                          <span className="mono">{revealed || cred.password_masked}</span>
                          <button
                            type="button"
                            className="btn btn-secondary btn-sm"
                            onClick={() => handleToggleReveal(cred.id)}
                            title={revealed ? "Hide password" : "Reveal password"}
                          >
                            {revealed ? <EyeOff size={13} /> : <Eye size={13} />}
                          </button>
                          <button
                            type="button"
                            className="btn btn-secondary btn-sm"
                            onClick={() => handleCopy(cred, "password")}
                            title="Copy password"
                          >
                            {copiedKey === `${cred.id}-password` ? <Check size={13} /> : <Copy size={13} />}
                          </button>
                        </div>
                      </td>
                      <td style={{ color: "var(--text-secondary)", fontSize: "0.8rem" }}>
                        {formatTimestamp(cred.updated_at)}
                      </td>
                      <td>
                        <div style={{ display: "flex", justifyContent: "flex-end", gap: 8 }}>
                          <button
                            type="button"
                            className="btn btn-secondary btn-sm"
                            onClick={() => handleOpenEdit(cred)}
                            title="Edit credential"
                          >
                            <Pencil size={13} /> Edit
                          </button>
                          <button
                            type="button"
                            className="btn btn-danger btn-sm"
                            onClick={() => handleDelete(cred)}
                            title="Delete credential"
                          >
                            <Trash2 size={13} />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <CredentialModal
        isOpen={modalOpen}
        mode={modalMode}
        initialData={editingItem}
        onClose={() => setModalOpen(false)}
        onSave={handleSaveModal}
      />
    </div>
  );
}
