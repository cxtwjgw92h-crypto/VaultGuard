import React, { useEffect, useState } from "react";
import { Bot, Send, ShieldCheck } from "lucide-react";
import { assistantApi } from "../services/api";
import { RiskBadge } from "../components/RiskBadge";

const QUICK_QUESTIONS = [
  "Why was my account marked as high risk?",
  "Summarize my recent security activity",
  "Explain the difference between Low, Medium, and High risk",
  "What security actions should I take right now?",
];

export function AssistantPage() {
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState("");
  const [sending, setSending] = useState(false);
  const [posture, setPosture] = useState("LOW");
  const [mode, setMode] = useState("rule-based-local");
  const [error, setError] = useState("");

  useEffect(() => {
    const loadInitialSummary = async () => {
      try {
        const res = await assistantApi.summary();
        setPosture(res.posture?.replace(" RISK", "") || "LOW");
        setMode(res.mode || "rule-based-local");
        setMessages([
          {
            role: "assistant",
            text: res.answer,
            recommendations: res.recommendations || [],
          },
        ]);
      } catch (err) {
        setError(err.message || "Failed to initialize AI Security Assistant.");
      }
    };
    loadInitialSummary();
  }, []);

  const askQuestion = async (questionText) => {
    const trimmed = questionText.trim();
    if (!trimmed || sending) return;

    setError("");
    setMessages((prev) => [...prev, { role: "user", text: trimmed }]);
    setInput("");
    setSending(true);

    try {
      const res = await assistantApi.ask(trimmed);
      setPosture(res.posture?.replace(" RISK", "") || "LOW");
      setMode(res.mode || "rule-based-local");
      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          text: res.answer,
          recommendations: res.recommendations || [],
        },
      ]);
    } catch (err) {
      setError(err.message || "Assistant request failed.");
    } finally {
      setSending(false);
    }
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    askQuestion(input);
  };

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-title">AI Security Assistant</h1>
          <p className="page-subtitle">
            Explains security events, risk scores, and recommended actions using sanitized telemetry only
          </p>
        </div>
        <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
          <span className="badge badge-cyan">Mode: {mode}</span>
          <RiskBadge level={posture} />
        </div>
      </div>

      <div className="alert-banner alert-info">
        <ShieldCheck size={18} />
        <span>
          Privacy Guarantee: Master passwords, encryption keys, and decrypted vault credentials are never shared with the AI assistant.
        </span>
      </div>

      {error && <div className="alert-banner alert-error">{error}</div>}

      <div className="card">
        <div className="quick-prompts">
          {QUICK_QUESTIONS.map((q) => (
            <button
              key={q}
              type="button"
              className="chip"
              onClick={() => askQuestion(q)}
              disabled={sending}
            >
              {q}
            </button>
          ))}
        </div>

        <div className="chat-box">
          {messages.map((msg, idx) => (
            <div
              key={idx}
              className={`chat-msg ${msg.role === "user" ? "chat-user" : "chat-assistant"}`}
            >
              <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 5, fontSize: "0.75rem", color: "var(--text-muted)" }}>
                {msg.role === "assistant" ? <Bot size={14} color="#22d3ee" /> : null}
                <strong>{msg.role === "user" ? "You" : "VaultGuard Security Assistant"}</strong>
              </div>
              <div>{msg.text}</div>
              {msg.recommendations && msg.recommendations.length > 0 && (
                <div style={{ marginTop: 10, paddingTop: 10, borderTop: "1px solid var(--border-color)" }}>
                  <div style={{ fontSize: "0.78rem", color: "var(--accent-cyan)", fontWeight: 600, marginBottom: 4 }}>
                    Recommended Actions:
                  </div>
                  <ul style={{ paddingLeft: 18, fontSize: "0.84rem", color: "var(--text-secondary)" }}>
                    {msg.recommendations.map((rec, i) => (
                      <li key={i} style={{ marginBottom: 3 }}>
                        {rec}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          ))}
          {sending && (
            <div className="chat-msg chat-assistant">Analyzing security telemetry...</div>
          )}
        </div>

        <form onSubmit={handleSubmit} style={{ display: "flex", gap: 10 }}>
          <input
            className="input"
            placeholder="Ask about your risk score, alerts, or recent logins..."
            value={input}
            onChange={(e) => setInput(e.target.value)}
          />
          <button type="submit" className="btn btn-primary" disabled={sending || !input.trim()}>
            <Send size={15} /> Ask
          </button>
        </form>
      </div>
    </div>
  );
}
