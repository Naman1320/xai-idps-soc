import React, { useState, useEffect } from "react";
import { api } from "../api/client";
import { X, AlertTriangle, CheckCircle2 } from "lucide-react";

export default function PreventionPage() {
  const [status, setStatus] = useState(null);
  const [blocks, setBlocks] = useState([]);
  const [selectedBlock, setSelectedBlock] = useState(null);
  const [loading, setLoading] = useState(true);
  const [dryRun, setDryRun] = useState(true);
  const [showBlockModal, setShowBlockModal] = useState(false);
  const [copiedKey, setCopiedKey] = useState(null);
  const [feedback, setFeedback] = useState(null);

  // Modal form state
  const [newIp, setNewIp] = useState("");
  const [newReason, setNewReason] = useState("");
  const [newAttack, setNewAttack] = useState("DDoS");

  const loadPreventionData = async () => {
    try {
      setLoading(true);
      const [st, bl] = await Promise.all([
        api.getPreventionStatus(),
        api.getBlockedIps(),
      ]);
      setStatus(st);
      const list = bl || [];
      setBlocks(list);
      setDryRun(st.dry_run);
      if (list.length > 0 && !selectedBlock) {
        setSelectedBlock(list[0]);
      }
    } catch (err) {
      console.error("Failed to load IPS data:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadPreventionData();
  }, []);

  const handleToggleDryRun = async () => {
    try {
      const next = !dryRun;
      await api.toggleDryRun(next);
      setDryRun(next);
      setFeedback({
        type: "info",
        text: `Containment safety mode switched to ${next ? "Dry-Run Simulation" : "Live Kernel Enforcement"}.`,
      });
      setTimeout(() => setFeedback(null), 4000);
    } catch (err) {
      setFeedback({
        type: "error",
        text: "Failed to toggle safety harness: " + err.message,
      });
    }
  };

  const handleUnblock = async (ip) => {
    try {
      await api.unblockIp(ip);
      await loadPreventionData();
      if (selectedBlock && selectedBlock.ip === ip) {
        setSelectedBlock((prev) =>
          prev ? { ...prev, status: "unblocked" } : null,
        );
      }
      setFeedback({
        type: "info",
        text: `Perimeter drop rule removed for host ${ip}.`,
      });
      setTimeout(() => setFeedback(null), 4000);
    } catch (err) {
      setFeedback({
        type: "error",
        text: "Failed to release IP: " + err.message,
      });
    }
  };

  const handleManualBlock = async (e) => {
    e.preventDefault();
    if (!newIp.trim()) return;
    try {
      const deployed = await api.blockIp({
        ip: newIp,
        reason: newReason || "Manual analyst containment action",
        attack_class: newAttack,
        risk_score: 0.9,
        duration_minutes: 60,
      });
      setShowBlockModal(false);
      setNewIp("");
      setNewReason("");
      await loadPreventionData();
      setSelectedBlock(deployed);
      setFeedback({
        type: "success",
        text: `Deployed quarantine rule for ${newIp}.`,
      });
      setTimeout(() => setFeedback(null), 4000);
    } catch (err) {
      setFeedback({
        type: "error",
        text: "Failed to deploy drop rule: " + err.message,
      });
    }
  };

  const copyToClipboard = (text, key) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  // Generate multi-platform rules for selected IP
  const activeIp = selectedBlock?.ip || "192.168.10.45";
  const activeAttack = selectedBlock?.attack_class || "DDoS";

  const multiPlatformRules = {
    iptables: `sudo iptables -I INPUT -s ${activeIp} -j DROP`,
    nftables: `sudo nft add rule inet filter input ip saddr ${activeIp} drop`,
    ufw: `sudo ufw insert 1 deny from ${activeIp} to any`,
    aws_sg: `aws ec2 revoke-security-group-ingress --group-id sg-0123456789abcdef0 --protocol tcp --port 80 --cidr ${activeIp}/32`,
    snort: `drop tcp ${activeIp} any -> any any (msg:"XAI-IDPS Auto-Drop: ${activeAttack}"; sid:1000999; rev:1;)`,
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "14px" }}>
      {/* 1. IPS Command & Safety Ribbon */}
      <div className="command-strip">
        <div className="command-strip-left">
          <div className="command-deck-title">
            <span>PERIMETER CONTAINMENT & FIREWALL ORCHESTRATOR</span>
            <span className="sec-badge sec-badge-neutral">
              SOAR // NETFILTER
            </span>
          </div>

          <div className="command-status-pills">
            <span className="status-pip active">
              {blocks.filter((b) => b.status === "active").length} ACTIVE
              PERIMETER DROPS
            </span>
            <span className="status-pip active">
              SYNTAX: IPTABLES / NFTABLES / AWS SG
            </span>
          </div>
        </div>

        <div className="command-strip-actions">
          <button
            className={`sec-btn ${dryRun ? "sec-btn-ghost" : "sec-btn-danger"} sec-btn-sm`}
            onClick={handleToggleDryRun}
            title="Toggle safety mode between dry-run simulation and live kernel enforcement"
          >
            <span>SAFETY:</span>
            <span style={{ fontFamily: "var(--font-mono)", fontWeight: 700 }}>
              {dryRun ? "[DRY-RUN SAFE]" : "[LIVE ENFORCEMENT]"}
            </span>
          </button>

          <button
            className="sec-btn sec-btn-primary sec-btn-sm"
            onClick={() => setShowBlockModal(true)}
          >
            <span>+ Deploy Quarantine</span>
          </button>
        </div>
      </div>

      {feedback && (
        <div
          style={{
            padding: "10px 14px",
            borderRadius: "4px",
            fontSize: "12px",
            fontFamily: "var(--font-mono)",
            display: "flex",
            alignItems: "center",
            gap: "8px",
            background:
              feedback.type === "error"
                ? "rgba(244, 63, 94, 0.1)"
                : "rgba(16, 185, 129, 0.1)",
            border: `1px solid ${feedback.type === "error" ? "var(--crimson-bright)" : "var(--emerald-bright)"}`,
            color:
              feedback.type === "error"
                ? "var(--crimson-bright)"
                : "var(--emerald-bright)",
          }}
        >
          {feedback.type === "error" ? (
            <AlertTriangle size={14} />
          ) : (
            <CheckCircle2 size={14} />
          )}
          <span>{feedback.text}</span>
        </div>
      )}

      {/* 2. Asymmetric Tactical Split: Left (58% Active Blocklist Registry) + Right (42% Multi-Platform Rule Inspector) */}
      <div className="tactical-split-55-45">
        {/* Left: Active Blocklist Registry */}
        <div className="panel">
          <div className="panel-header">
            <div className="panel-title">
              <svg
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
              >
                <circle cx="12" cy="12" r="10" />
                <line x1="4.93" y1="4.93" x2="19.07" y2="19.07" />
              </svg>
              <span>Perimeter Drop Rule Registry</span>
            </div>
            <span className="panel-badge">{blocks.length} TOTAL ENTRIES</span>
          </div>

          <div className="panel-body-flush sec-table-container">
            <table className="sec-table">
              <thead>
                <tr>
                  <th style={{ width: "85px" }}>Status</th>
                  <th>Target IP</th>
                  <th>Threat Vector</th>
                  <th style={{ width: "80px" }}>Risk</th>
                  <th>Reason / Trigger</th>
                  <th style={{ width: "70px", textAlign: "right" }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {loading ? (
                  <tr>
                    <td
                      colSpan="6"
                      style={{
                        textAlign: "center",
                        padding: "24px",
                        color: "var(--text-muted)",
                      }}
                    >
                      Loading containment registry...
                    </td>
                  </tr>
                ) : blocks.length === 0 ? (
                  <tr>
                    <td
                      colSpan="6"
                      style={{
                        textAlign: "center",
                        padding: "24px",
                        color: "var(--text-muted)",
                      }}
                    >
                      No active drop rules deployed.
                    </td>
                  </tr>
                ) : (
                  blocks.map((b) => {
                    const isSelected = selectedBlock?.id === b.id;
                    const isActive = b.status === "active";
                    return (
                      <tr
                        key={b.id}
                        className={isSelected ? "active" : ""}
                        onClick={() => setSelectedBlock(b)}
                      >
                        <td>
                          {isActive ? (
                            <span className="sec-badge sec-badge-crit">
                              [DROP]
                            </span>
                          ) : (
                            <span className="sec-badge sec-badge-neutral">
                              [RELEASE]
                            </span>
                          )}
                        </td>
                        <td>
                          <span
                            className="mono-ip"
                            style={{
                              color: isActive
                                ? "var(--signal-crit)"
                                : "var(--text-muted)",
                            }}
                          >
                            {b.ip}
                          </span>
                        </td>
                        <td>
                          <span className="sec-badge sec-badge-high">
                            {b.attack_class}
                          </span>
                        </td>
                        <td>
                          <span className="mono-time" style={{ color: "#fff" }}>
                            {(b.risk_score * 100).toFixed(0)}%
                          </span>
                        </td>
                        <td>
                          <span
                            style={{
                              fontSize: "11px",
                              color: "var(--text-secondary)",
                            }}
                          >
                            {b.reason}
                          </span>
                        </td>
                        <td style={{ textAlign: "right" }}>
                          {isActive ? (
                            <button
                              className="sec-btn sec-btn-ghost sec-btn-sm"
                              onClick={(e) => {
                                e.stopPropagation();
                                handleUnblock(b.ip);
                              }}
                              style={{ padding: "2px 6px", fontSize: "10.5px" }}
                              title="Revoke drop rule and restore ingress route"
                            >
                              Revoke
                            </button>
                          ) : (
                            <span
                              style={{
                                fontSize: "10.5px",
                                color: "var(--text-dim)",
                                fontFamily: "var(--font-mono)",
                              }}
                            >
                              RELEASED
                            </span>
                          )}
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Right: Multi-Platform Rule Inspector & Syntax Generator */}
        <div style={{ display: "flex", flexDirection: "column", gap: "14px" }}>
          <div className="panel">
            <div className="panel-header">
              <div className="panel-title">
                <svg
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="2"
                >
                  <polyline points="4 17 10 11 4 5" />
                  <line x1="12" y1="19" x2="20" y2="19" />
                </svg>
                <span>Firewall Rule Syntax Generator</span>
              </div>
              <span className="panel-badge">
                {selectedBlock ? selectedBlock.ip : "NO TARGET SELECTED"}
              </span>
            </div>

            <div
              className="panel-body"
              style={{ display: "flex", flexDirection: "column", gap: "12px" }}
            >
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  fontSize: "11.5px",
                  color: "var(--text-muted)",
                  borderBottom: "1px solid var(--border-hairline)",
                  paddingBottom: "8px",
                }}
              >
                <span>Target Coordinates:</span>
                <span className="mono-ip" style={{ color: "#fff" }}>
                  {activeIp} / 32
                </span>
              </div>

              {/* Linux iptables */}
              <div className="syntax-block">
                <div className="syntax-header">
                  <span className="syntax-tag">Linux Netfilter / iptables</span>
                  <button
                    className="sec-btn sec-btn-ghost sec-btn-sm"
                    onClick={() =>
                      copyToClipboard(multiPlatformRules.iptables, "iptables")
                    }
                    style={{ padding: "1px 5px", fontSize: "10px" }}
                  >
                    {copiedKey === "iptables" ? "COPIED!" : "COPY"}
                  </button>
                </div>
                <code>{multiPlatformRules.iptables}</code>
              </div>

              {/* Modern nftables */}
              <div className="syntax-block">
                <div className="syntax-header">
                  <span className="syntax-tag">Modern nftables</span>
                  <button
                    className="sec-btn sec-btn-ghost sec-btn-sm"
                    onClick={() =>
                      copyToClipboard(multiPlatformRules.nftables, "nftables")
                    }
                    style={{ padding: "1px 5px", fontSize: "10px" }}
                  >
                    {copiedKey === "nftables" ? "COPIED!" : "COPY"}
                  </button>
                </div>
                <code>{multiPlatformRules.nftables}</code>
              </div>

              {/* AWS Security Group CLI */}
              <div className="syntax-block">
                <div className="syntax-header">
                  <span className="syntax-tag">AWS Security Group CLI</span>
                  <button
                    className="sec-btn sec-btn-ghost sec-btn-sm"
                    onClick={() =>
                      copyToClipboard(multiPlatformRules.aws_sg, "aws_sg")
                    }
                    style={{ padding: "1px 5px", fontSize: "10px" }}
                  >
                    {copiedKey === "aws_sg" ? "COPIED!" : "COPY"}
                  </button>
                </div>
                <code>{multiPlatformRules.aws_sg}</code>
              </div>

              {/* Snort Rule */}
              <div className="syntax-block">
                <div className="syntax-header">
                  <span className="syntax-tag">
                    Snort 3 / Suricata Drop Signature
                  </span>
                  <button
                    className="sec-btn sec-btn-ghost sec-btn-sm"
                    onClick={() =>
                      copyToClipboard(multiPlatformRules.snort, "snort")
                    }
                    style={{ padding: "1px 5px", fontSize: "10px" }}
                  >
                    {copiedKey === "snort" ? "COPIED!" : "COPY"}
                  </button>
                </div>
                <code>{multiPlatformRules.snort}</code>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Manual Quarantine Modal */}
      {showBlockModal && (
        <div className="modal-overlay" onClick={() => setShowBlockModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <span className="modal-title">
                DEPLOY PERIMETER CONTAINMENT RULE
              </span>
              <button
                className="sec-btn sec-btn-ghost sec-btn-sm"
                onClick={() => setShowBlockModal(false)}
              >
                <X size={14} />
              </button>
            </div>

            <form onSubmit={handleManualBlock}>
              <div
                className="modal-body"
                style={{
                  display: "flex",
                  flexDirection: "column",
                  gap: "14px",
                }}
              >
                <div>
                  <label
                    style={{
                      fontSize: "11px",
                      color: "var(--text-muted)",
                      display: "block",
                      marginBottom: "4px",
                      textTransform: "uppercase",
                      fontFamily: "var(--font-mono)",
                    }}
                  >
                    Target IP / Subnet (/32)
                  </label>
                  <input
                    type="text"
                    className="sec-input"
                    style={{ width: "100%", fontFamily: "var(--font-mono)" }}
                    placeholder="e.g. 192.168.10.88"
                    value={newIp}
                    onChange={(e) => setNewIp(e.target.value)}
                    required
                  />
                </div>

                <div>
                  <label
                    style={{
                      fontSize: "11px",
                      color: "var(--text-muted)",
                      display: "block",
                      marginBottom: "4px",
                      textTransform: "uppercase",
                      fontFamily: "var(--font-mono)",
                    }}
                  >
                    Correlated Attack Vector
                  </label>
                  <select
                    className="sec-select"
                    style={{ width: "100%" }}
                    value={newAttack}
                    onChange={(e) => setNewAttack(e.target.value)}
                  >
                    <option value="DDoS">DDoS Volumetric</option>
                    <option value="PortScan">PortScan Sweep</option>
                    <option value="SSH-Patator">SSH Brute Force</option>
                    <option value="Web Attack">Web Injection / Exploit</option>
                    <option value="Botnet">Botnet C2</option>
                  </select>
                </div>

                <div>
                  <label
                    style={{
                      fontSize: "11px",
                      color: "var(--text-muted)",
                      display: "block",
                      marginBottom: "4px",
                      textTransform: "uppercase",
                      fontFamily: "var(--font-mono)",
                    }}
                  >
                    Operational Justification
                  </label>
                  <input
                    type="text"
                    className="sec-input"
                    style={{ width: "100%" }}
                    placeholder="e.g. Repeated authentication threshold violation detected by XAI classifier"
                    value={newReason}
                    onChange={(e) => setNewReason(e.target.value)}
                  />
                </div>
              </div>

              <div className="modal-footer">
                <button
                  type="button"
                  className="sec-btn sec-btn-ghost"
                  onClick={() => setShowBlockModal(false)}
                >
                  Cancel
                </button>
                <button type="submit" className="sec-btn sec-btn-danger">
                  Commit Drop Rule
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
