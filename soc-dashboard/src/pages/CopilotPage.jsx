import React, { useState } from "react";
import {
  Bot,
  Shield,
  Send,
  Sparkles,
  Activity,
  Loader2,
  Code,
  Terminal,
} from "lucide-react";
import { api } from "../api/client";

export default function CopilotPage() {
  const [messages, setMessages] = useState([
    {
      id: "m-1",
      sender: "copilot",
      text: "Incident Copilot reasoning engine active. Ready to interpret SHAP TreeExplainer attributions, generate perimeter firewall syntax (iptables / nftables / Snort), structure mitigation playbooks, or review defense dossier findings.",
      data: null,
    },
  ]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);

  const quickPrompts = [
    "Explain the research gap for examiners",
    "How do I triage a volumetric DDoS attack (T1498)?",
    "Generate a Snort rule for SSH brute force",
    "Explain why SHAP TreeExplainer is better than LIME here",
  ];

  const handleSend = async (queryText) => {
    const q = queryText || input;
    if (!q.trim()) return;

    const userMsg = {
      id: `u-${Date.now()}`,
      sender: "user",
      text: q,
    };

    setMessages((prev) => [...prev, userMsg]);
    setInput("");
    setLoading(true);

    try {
      const res = await api.askCopilot(q);
      const botMsg = {
        id: `c-${Date.now()}`,
        sender: "copilot",
        text: res.summary,
        data: res,
      };
      setMessages((prev) => [...prev, botMsg]);
    } catch (err) {
      setMessages((prev) => [
        ...prev,
        {
          id: `c-${Date.now()}`,
          sender: "copilot",
          text: `Query processing error: ${err.message}`,
        },
      ]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        height: "calc(100vh - 110px)",
        gap: "12px",
      }}
    >
      {/* Header Command Strip */}
      <div className="command-strip">
        <div className="command-strip-left">
          <div className="command-deck-title">
            <Bot size={16} />
            <span>ANALYST COPILOT & REASONING ASSISTANT</span>
            <span className="sec-badge sec-badge-mitre">XAI INFERENCE</span>
          </div>

          <div className="command-status-pills">
            <span className="status-pip active">
              SHAP ATTRIBUTION TRANSLATOR
            </span>
            <span className="status-pip active">RULE GENERATOR READY</span>
          </div>
        </div>
      </div>

      {/* Chat Messages Window */}
      <div
        className="panel"
        style={{
          flex: 1,
          overflowY: "auto",
          display: "flex",
          flexDirection: "column",
          gap: "12px",
          padding: "16px",
          background: "var(--bg-inset)",
        }}
      >
        {messages.map((m) => {
          const isUser = m.sender === "user";
          return (
            <div
              key={m.id}
              style={{
                display: "flex",
                justifyContent: isUser ? "flex-end" : "flex-start",
              }}
            >
              <div
                style={{
                  maxWidth: "78%",
                  background: isUser
                    ? "var(--cyan-subtle)"
                    : "var(--bg-surface)",
                  border: isUser
                    ? "1px solid var(--cyan-border)"
                    : "1px solid var(--border-hairline)",
                  borderRadius: "var(--radius-xs)",
                  padding: "12px 14px",
                  color: "#fff",
                }}
              >
                {!isUser && (
                  <div
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: "6px",
                      marginBottom: "6px",
                    }}
                  >
                    <Shield size={13} style={{ color: "var(--cyan-bright)" }} />
                    <span
                      style={{
                        fontSize: "11px",
                        color: "var(--cyan-bright)",
                        fontFamily: "var(--font-mono)",
                        fontWeight: 600,
                      }}
                    >
                      COPILOT INTELLIGENCE
                    </span>
                  </div>
                )}

                <p
                  style={{
                    fontSize: "12.5px",
                    lineHeight: 1.55,
                    color: "var(--text-primary)",
                  }}
                >
                  {m.text}
                </p>

                {m.data && (
                  <div
                    style={{
                      marginTop: "10px",
                      display: "flex",
                      flexDirection: "column",
                      gap: "8px",
                    }}
                  >
                    {m.data.shap_insight && (
                      <div
                        className="syntax-block"
                        style={{ margin: 0, padding: "8px 10px" }}
                      >
                        <div
                          style={{
                            fontSize: "10px",
                            color: "var(--cyan-bright)",
                            fontFamily: "var(--font-mono)",
                            textTransform: "uppercase",
                            marginBottom: "3px",
                            display: "flex",
                            alignItems: "center",
                            gap: "4px",
                          }}
                        >
                          <Activity size={11} />
                          <span>SHAP Local Feature Attribution:</span>
                        </div>
                        <p
                          style={{
                            fontSize: "11.5px",
                            color: "#cbd5e1",
                            lineHeight: 1.4,
                          }}
                        >
                          {m.data.shap_insight}
                        </p>
                      </div>
                    )}

                    {m.data.remediation_steps && (
                      <div
                        style={{
                          background: "var(--bg-surface-elevated)",
                          padding: "8px 12px",
                          borderRadius: "var(--radius-xs)",
                          border: "1px solid var(--border-hairline)",
                        }}
                      >
                        <div
                          style={{
                            fontSize: "10.5px",
                            fontWeight: 600,
                            color: "var(--signal-high)",
                            marginBottom: "4px",
                            textTransform: "uppercase",
                            fontFamily: "var(--font-mono)",
                          }}
                        >
                          Recommended Remediation Playbook:
                        </div>
                        <ul
                          style={{
                            paddingLeft: "16px",
                            fontSize: "12px",
                            color: "var(--text-secondary)",
                            lineHeight: 1.5,
                          }}
                        >
                          {m.data.remediation_steps.map((step, idx) => (
                            <li key={idx}>{step}</li>
                          ))}
                        </ul>
                      </div>
                    )}

                    {m.data.recommended_rule && (
                      <div className="syntax-block">
                        <div className="syntax-header">
                          <span className="syntax-tag">
                            Generated Firewall Drop Syntax
                          </span>
                        </div>
                        <code>{m.data.recommended_rule}</code>
                      </div>
                    )}

                    {m.data.sigma_rule && (
                      <div className="syntax-block">
                        <div className="syntax-header">
                          <span className="syntax-tag">
                            Generated Sigma Detection Rule
                          </span>
                        </div>
                        <code>{m.data.sigma_rule}</code>
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>
          );
        })}

        {loading && (
          <div style={{ display: "flex", justifyContent: "flex-start" }}>
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: "8px",
                background: "var(--bg-surface)",
                border: "1px solid var(--border-hairline)",
                borderRadius: "var(--radius-xs)",
                padding: "8px 12px",
                color: "var(--text-muted)",
                fontSize: "11.5px",
                fontFamily: "var(--font-mono)",
              }}
            >
              <Loader2 size={13} className="spin" />
              <span>Evaluating flow telemetry & ATT&CK mitigations...</span>
            </div>
          </div>
        )}
      </div>

      {/* Suggested Quick Prompts */}
      <div
        style={{
          display: "flex",
          gap: "6px",
          overflowX: "auto",
          paddingBottom: "2px",
        }}
      >
        {quickPrompts.map((p, idx) => (
          <button
            key={idx}
            className="sec-btn sec-btn-ghost sec-btn-sm"
            style={{ fontSize: "11px", whiteSpace: "nowrap" }}
            onClick={() => handleSend(p)}
          >
            <Sparkles size={11} style={{ opacity: 0.6 }} />
            <span>{p}</span>
          </button>
        ))}
      </div>

      {/* Input Box */}
      <form
        onSubmit={(e) => {
          e.preventDefault();
          handleSend();
        }}
        style={{ display: "flex", gap: "8px" }}
      >
        <input
          type="text"
          className="sec-input"
          style={{ flex: 1, padding: "8px 12px", fontSize: "12.5px" }}
          placeholder="Inquire regarding alert context, attribution metrics, or remediation syntax..."
          value={input}
          onChange={(e) => setInput(e.target.value)}
          disabled={loading}
        />
        <button
          type="submit"
          className="sec-btn sec-btn-primary"
          disabled={loading || !input.trim()}
        >
          <Send size={13} />
          <span>Dispatch Query</span>
        </button>
      </form>
    </div>
  );
}
