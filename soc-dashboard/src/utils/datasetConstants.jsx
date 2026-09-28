import React from "react";
import {
  Database,
  Wifi,
  Factory,
  HeartPulse,
  Server,
  Radio,
} from "lucide-react";

export const DOMAINS = {
  network: {
    id: "network",
    label: "Enterprise Network",
    tag: "NET",
    color: "#3b82f6",
    bg: "rgba(59, 130, 246, 0.12)",
    border: "rgba(59, 130, 246, 0.35)",
    icon: Server,
    description: "Core backbone, enterprise firewalls, PCAP NetFlow",
  },
  iot: {
    id: "iot",
    label: "Internet of Things",
    tag: "IoT",
    color: "#a855f7",
    bg: "rgba(168, 85, 247, 0.12)",
    border: "rgba(168, 85, 247, 0.35)",
    icon: Wifi,
    description: "Smart devices, edge cameras, MQTT/CoAP gateways",
  },
  iiot: {
    id: "iiot",
    label: "Industrial IoT (OT)",
    tag: "IIoT",
    color: "#f59e0b",
    bg: "rgba(245, 158, 11, 0.12)",
    border: "rgba(245, 158, 11, 0.35)",
    icon: Factory,
    description: "SCADA, PLC telemetry, Modbus/OPC-UA sensors",
  },
  iomt: {
    id: "iomt",
    label: "Medical IoMT",
    tag: "IoMT",
    color: "#10b981",
    bg: "rgba(16, 185, 129, 0.12)",
    border: "rgba(16, 185, 129, 0.35)",
    icon: HeartPulse,
    description: "Clinical infusion pumps, bedside monitors, HL7/DICOM",
  },
};

export const DATASETS = {
  CICIoT2023: {
    id: "CICIoT2023",
    displayName: "CICIoT2023",
    shortName: "CIC-IoT",
    domain: "iot",
    color: "#a855f7",
    bg: "rgba(168, 85, 247, 0.14)",
    border: "rgba(168, 85, 247, 0.4)",
    icon: Wifi,
    defaultModel: "Random Forest",
    defaultAccuracy: 0.815,
    defaultF1: 0.784,
  },
  "Edge-IIoTset": {
    id: "Edge-IIoTset",
    displayName: "Edge-IIoTset",
    shortName: "Edge-IIoT",
    domain: "iiot",
    color: "#f59e0b",
    bg: "rgba(245, 158, 11, 0.14)",
    border: "rgba(245, 158, 11, 0.4)",
    icon: Factory,
    defaultModel: "Random Forest",
    defaultAccuracy: 0.923,
    defaultF1: 0.918,
  },
  "NF-ToN-IoT-v3": {
    id: "NF-ToN-IoT-v3",
    displayName: "NF-ToN-IoT-v3",
    shortName: "NF-ToN",
    domain: "iot",
    color: "#06b6d4",
    bg: "rgba(6, 182, 212, 0.14)",
    border: "rgba(6, 182, 212, 0.4)",
    icon: Radio,
    defaultModel: "XGBoost",
    defaultAccuracy: 0.755,
    defaultF1: 0.715,
  },
  "CIC-IDS2017": {
    id: "CIC-IDS2017",
    displayName: "CIC-IDS2017",
    shortName: "CIC-IDS",
    domain: "network",
    color: "#3b82f6",
    bg: "rgba(59, 130, 246, 0.14)",
    border: "rgba(59, 130, 246, 0.4)",
    icon: Server,
    defaultModel: "XGBoost",
    defaultAccuracy: 0.978,
    defaultF1: 0.976,
  },
  "IoMT-CareFlow": {
    id: "IoMT-CareFlow",
    displayName: "IoMT-CareFlow",
    shortName: "CareFlow",
    domain: "iomt",
    color: "#10b981",
    bg: "rgba(16, 185, 129, 0.14)",
    border: "rgba(16, 185, 129, 0.4)",
    icon: HeartPulse,
    defaultModel: "LightGBM",
    defaultAccuracy: 0.941,
    defaultF1: 0.938,
  },
};

export function getDatasetMeta(datasetName) {
  if (!datasetName) return DATASETS["CIC-IDS2017"];
  const normalized = Object.keys(DATASETS).find(
    (k) =>
      k.toLowerCase() === datasetName.toLowerCase() ||
      datasetName.toLowerCase().includes(k.toLowerCase()),
  );
  return normalized
    ? DATASETS[normalized]
    : {
        id: datasetName,
        displayName: datasetName,
        shortName: datasetName.substring(0, 8),
        domain: "network",
        color: "#64748b",
        bg: "rgba(100, 116, 139, 0.14)",
        border: "rgba(100, 116, 139, 0.4)",
        icon: Database,
        defaultModel: "Multi-Class Tree Ensemble",
        defaultAccuracy: 0.85,
        defaultF1: 0.82,
      };
}

export function getDomainMeta(domainName) {
  const dom = (domainName || "network").toLowerCase();
  return DOMAINS[dom] || DOMAINS.network;
}

export function DatasetBadge({ dataset, showIcon = true, size = "sm" }) {
  const meta = getDatasetMeta(dataset);
  const Icon = meta.icon || Database;
  const isSm = size === "sm";

  return (
    <span
      className="dataset-source-tag"
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: "4px",
        padding: isSm ? "2px 7px" : "4px 9px",
        fontSize: isSm ? "10.5px" : "11.5px",
        fontWeight: 600,
        fontFamily: "var(--font-mono)",
        borderRadius: "3px",
        color: meta.color,
        backgroundColor: meta.bg,
        border: `1px solid ${meta.border}`,
        whiteSpace: "nowrap",
        letterSpacing: "0.02em",
      }}
      title={`Dataset Source: ${meta.displayName} (${meta.domain.toUpperCase()})`}
    >
      {showIcon && <Icon size={isSm ? 11 : 13} style={{ flexShrink: 0 }} />}
      <span>{meta.displayName}</span>
    </span>
  );
}

export function DomainBadge({ domain, size = "sm" }) {
  const meta = getDomainMeta(domain);
  const Icon = meta.icon || Server;
  const isSm = size === "sm";

  return (
    <span
      className="domain-pill"
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: "4px",
        padding: isSm ? "1px 6px" : "3px 8px",
        fontSize: isSm ? "10px" : "11px",
        fontWeight: 600,
        fontFamily: "var(--font-mono)",
        borderRadius: "2px",
        color: meta.color,
        backgroundColor: meta.bg,
        border: `1px solid ${meta.border}`,
        textTransform: "uppercase",
      }}
      title={`Domain: ${meta.label}`}
    >
      <Icon size={isSm ? 10 : 12} />
      <span>{meta.tag}</span>
    </span>
  );
}
