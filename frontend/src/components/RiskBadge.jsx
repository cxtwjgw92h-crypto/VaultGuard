import React from "react";
import { ShieldCheck, AlertTriangle, ShieldAlert } from "lucide-react";

export function RiskBadge({ level, score }) {
  const normalized = (level || "LOW").toUpperCase();

  if (normalized === "HIGH") {
    return (
      <span className="badge badge-high">
        <ShieldAlert size={13} />
        HIGH{score !== undefined ? ` (${score})` : ""}
      </span>
    );
  }
  if (normalized === "MEDIUM") {
    return (
      <span className="badge badge-medium">
        <AlertTriangle size={13} />
        MEDIUM{score !== undefined ? ` (${score})` : ""}
      </span>
    );
  }
  return (
    <span className="badge badge-low">
      <ShieldCheck size={13} />
      LOW{score !== undefined ? ` (${score})` : ""}
    </span>
  );
}

export function formatTimestamp(isoString) {
  if (!isoString) return "—";
  const date = new Date(isoString);
  if (Number.isNaN(date.getTime())) return isoString;
  return date.toLocaleString();
}
