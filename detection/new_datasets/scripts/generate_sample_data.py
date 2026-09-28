"""
Sample Benchmark Data Generator for New IoT / NetFlow Datasets.

Generates realistic sample benchmark CSVs for:
  1. CICIoT2023      – 105-device topology flow schema with 33 attack types
  2. Edge-IIoTset    – Multi-protocol edge/IIoT schema with 14 attack types
  3. NF-ToN-IoT-v3   – 53-feature NetFlow v3 schema with 9 attack types

These samples enable end-to-end pipeline execution, model training,
cross-dataset evaluation, and dashboard visualization immediately,
while allowing seamless drop-in of full raw datasets when downloaded.
"""

import sys
from pathlib import Path

import numpy as np
import pandas as pd

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from detection.new_datasets.config import DATA_RAW, RANDOM_STATE

np.random.seed(RANDOM_STATE)


def generate_ciciot2023_sample(
    n_records: int = 3000, save: bool = True
) -> pd.DataFrame:
    """Generate representative CICIoT2023 flow dataset."""
    attacks = [
        ("BenignTraffic", 0.35),
        ("DDoS-UDP_Flood", 0.08),
        ("DDoS-TCP_Flood", 0.08),
        ("DDoS-SYN_Flood", 0.08),
        ("DoS-UDP_Flood", 0.06),
        ("Mirai-greeth_flood", 0.05),
        ("Mirai-udpplain", 0.05),
        ("Recon-PortScan", 0.06),
        ("Recon-OSScan", 0.04),
        ("DictionaryBruteForce", 0.04),
        ("SqlInjection", 0.03),
        ("XSS", 0.03),
        ("DNS_Spoofing", 0.03),
        ("MITM-ArpSpoofing", 0.02),
        ("Backdoor_Malware", 0.03),
        ("Uploading_Attack", 0.02),
    ]
    labels, probs = zip(*attacks)
    probs = np.array(probs) / sum(probs)
    chosen_labels = np.random.choice(labels, size=n_records, p=probs)

    data = {
        "flow_id": [
            f"192.168.1.{np.random.randint(10, 200)}-10.0.0.{np.random.randint(1, 50)}-{np.random.randint(1024, 65535)}-{np.random.choice([80, 443, 22, 53, 1883])}-6"
            for _ in range(n_records)
        ],
        "src_ip": [f"192.168.1.{np.random.randint(10, 200)}" for _ in range(n_records)],
        "dst_ip": [f"10.0.0.{np.random.randint(1, 50)}" for _ in range(n_records)],
        "src_port": np.random.randint(1024, 65535, size=n_records),
        "dst_port": np.random.choice([80, 443, 22, 53, 1883, 8080], size=n_records),
        "timestamp": pd.date_range(
            "2026-09-01", periods=n_records, freq="100ms"
        ).astype(str),
        "flow_duration": np.random.exponential(1.5, size=n_records),
        "Header_Length": np.random.randint(20, 60, size=n_records),
        "Protocol Type": np.random.choice(
            [6, 17, 1], p=[0.65, 0.30, 0.05], size=n_records
        ),
        "Duration": np.random.exponential(1.5, size=n_records),
        "Rate": np.random.gamma(5, 50, size=n_records),
        "Srate": np.random.gamma(4, 30, size=n_records),
        "Drate": np.random.gamma(2, 20, size=n_records),
        "fin_flag_number": np.random.choice([0, 1], p=[0.8, 0.2], size=n_records),
        "syn_flag_number": np.random.choice([0, 1], p=[0.7, 0.3], size=n_records),
        "rst_flag_number": np.random.choice([0, 1], p=[0.9, 0.1], size=n_records),
        "psh_flag_number": np.random.choice([0, 1], p=[0.75, 0.25], size=n_records),
        "ack_flag_number": np.random.choice([0, 1], p=[0.4, 0.6], size=n_records),
        "ece_flag_number": np.random.choice([0, 1], p=[0.98, 0.02], size=n_records),
        "cwr_flag_number": np.random.choice([0, 1], p=[0.98, 0.02], size=n_records),
        "ack_count": np.random.poisson(12, size=n_records),
        "syn_count": np.random.poisson(3, size=n_records),
        "fin_count": np.random.poisson(1, size=n_records),
        "urg_count": np.random.choice([0, 1], p=[0.99, 0.01], size=n_records),
        "rst_count": np.random.poisson(0.5, size=n_records),
        "Tot sum": np.random.exponential(5000, size=n_records),
        "Min": np.random.uniform(40, 64, size=n_records),
        "Max": np.random.uniform(500, 1500, size=n_records),
        "AVG": np.random.uniform(200, 800, size=n_records),
        "Std": np.random.uniform(50, 400, size=n_records),
        "Tot size": np.random.exponential(8000, size=n_records),
        "IAT": np.random.exponential(0.05, size=n_records),
        "Number": np.random.randint(5, 100, size=n_records),
        "Magnitue": np.random.uniform(10, 50, size=n_records),
        "Radius": np.random.uniform(5, 30, size=n_records),
        "Covariance": np.random.exponential(100, size=n_records),
        "Variance": np.random.exponential(500, size=n_records),
        "Weight": np.random.uniform(1, 20, size=n_records),
        "label": chosen_labels,
    }

    df = pd.DataFrame(data)

    # Adjust values for attacks
    for idx, row in df.iterrows():
        lbl = row["label"]
        if "DDoS" in lbl or "DoS" in lbl:
            df.at[idx, "Rate"] *= 8.0
            df.at[idx, "syn_count"] += 15
            df.at[idx, "syn_flag_number"] = 1
        elif "Mirai" in lbl:
            df.at[idx, "Rate"] *= 5.0
            df.at[idx, "Tot size"] *= 3.0
        elif "Recon" in lbl:
            df.at[idx, "Duration"] = np.random.uniform(0.01, 0.1)
            df.at[idx, "syn_count"] += 5
        elif "Brute" in lbl:
            df.at[idx, "ack_count"] += 20
        elif "Sql" in lbl or "XSS" in lbl:
            df.at[idx, "Tot sum"] += 3000

    if save:
        out_dir = DATA_RAW / "ciciot2023"
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / "ciciot2023_sample.csv"
        df.to_csv(out_path, index=False)
        print(f"✅ Created CICIoT2023 sample: {out_path} ({len(df)} rows)")

    return df


def generate_edge_iiotset_sample(
    n_records: int = 3000, save: bool = True
) -> pd.DataFrame:
    """Generate representative Edge-IIoTset ML dataset."""
    attacks = [
        ("Normal", 0.35),
        ("DDoS_UDP", 0.08),
        ("DDoS_ICMP", 0.08),
        ("DDoS_TCP", 0.07),
        ("DoS_UDP", 0.07),
        ("DoS_TCP", 0.06),
        ("Vulnerability_scanner", 0.05),
        ("Port_Scanning", 0.05),
        ("Password", 0.05),
        ("MITM", 0.04),
        ("ARP_Spoofing", 0.03),
        ("SQL_injection", 0.04),
        ("XSS", 0.03),
        ("Ransomware", 0.03),
        ("Backdoor", 0.02),
    ]
    labels, probs = zip(*attacks)
    probs = np.array(probs) / sum(probs)
    chosen_labels = np.random.choice(labels, size=n_records, p=probs)

    data = {
        "frame.time": pd.date_range(
            "2026-09-01", periods=n_records, freq="50ms"
        ).astype(str),
        "ip.src_host": [
            f"192.168.0.{np.random.randint(2, 100)}" for _ in range(n_records)
        ],
        "ip.dst_host": [
            f"192.168.0.{np.random.randint(101, 250)}" for _ in range(n_records)
        ],
        "arp.dst.proto_ipv4": [0.0] * n_records,
        "arp.opcode": [0.0] * n_records,
        "arp.hw.size": [0.0] * n_records,
        "arp.proto.size": [0.0] * n_records,
        "icmp.checksum": np.random.uniform(0, 65535, size=n_records),
        "icmp.seq_le": np.random.randint(0, 1000, size=n_records),
        "icmp.transmit_timestamp": [0.0] * n_records,
        "http.content_length": np.random.exponential(200, size=n_records),
        "http.response": np.random.choice(
            [0, 200, 404, 500], p=[0.7, 0.25, 0.03, 0.02], size=n_records
        ),
        "http.tls_port": [0.0] * n_records,
        "tcp.flags": np.random.choice([2, 16, 18, 24], size=n_records),
        "tcp.flags.ack": np.random.choice([0, 1], p=[0.4, 0.6], size=n_records),
        "tcp.flags.push": np.random.choice([0, 1], p=[0.8, 0.2], size=n_records),
        "tcp.flags.reset": np.random.choice([0, 1], p=[0.95, 0.05], size=n_records),
        "tcp.flags.syn": np.random.choice([0, 1], p=[0.7, 0.3], size=n_records),
        "tcp.flags.fin": np.random.choice([0, 1], p=[0.85, 0.15], size=n_records),
        "tcp.len": np.random.exponential(400, size=n_records),
        "tcp.ack": np.random.randint(0, 100000, size=n_records),
        "tcp.connection.fin": np.random.choice([0, 1], p=[0.9, 0.1], size=n_records),
        "tcp.connection.rst": np.random.choice([0, 1], p=[0.95, 0.05], size=n_records),
        "tcp.connection.syn": np.random.choice([0, 1], p=[0.75, 0.25], size=n_records),
        "tcp.connection.synack": np.random.choice([0, 1], p=[0.8, 0.2], size=n_records),
        "tcp.dstport": np.random.choice([80, 443, 1883, 502, 8080], size=n_records),
        "tcp.srcport": np.random.randint(1024, 65535, size=n_records),
        "udp.port": [0.0] * n_records,
        "udp.stream": [0.0] * n_records,
        "udp.time_delta": np.random.exponential(0.01, size=n_records),
        "dns.qry.name": [0.0] * n_records,
        "dns.qry.name.len": np.random.exponential(5, size=n_records),
        "dns.qry.qu": [0.0] * n_records,
        "dns.qry.type": [0.0] * n_records,
        "dns.retransmission": [0.0] * n_records,
        "mqtt.conflag.cleansess": np.random.choice(
            [0, 1], p=[0.8, 0.2], size=n_records
        ),
        "mqtt.conflags": [0.0] * n_records,
        "mqtt.hdrflags": [0.0] * n_records,
        "mqtt.len": np.random.exponential(50, size=n_records),
        "mqtt.msg_decoded_as": [0.0] * n_records,
        "mqtt.msgtype": np.random.choice(
            [0, 1, 2, 3], p=[0.7, 0.1, 0.1, 0.1], size=n_records
        ),
        "mqtt.proto_len": [0.0] * n_records,
        "mqtt.topic_num": np.random.randint(0, 10, size=n_records),
        "Attack_type": chosen_labels,
        "Attack_label": [0 if l == "Normal" else 1 for l in chosen_labels],
    }

    df = pd.DataFrame(data)

    # Adjust values for attacks
    for idx, row in df.iterrows():
        lbl = row["Attack_type"]
        if "DDoS" in lbl or "DoS" in lbl:
            df.at[idx, "tcp.flags.syn"] = 1
            df.at[idx, "tcp.len"] = np.random.uniform(10, 60)
        elif "Port_Scanning" in lbl or "Vulnerability" in lbl:
            df.at[idx, "tcp.flags.syn"] = 1
            df.at[idx, "tcp.connection.syn"] = 1
        elif "Password" in lbl:
            df.at[idx, "tcp.flags.ack"] = 1
            df.at[idx, "tcp.len"] = np.random.uniform(50, 150)
        elif "SQL" in lbl or "XSS" in lbl:
            df.at[idx, "http.content_length"] += 800

    if save:
        out_dir = DATA_RAW / "edge_iiotset"
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / "ML-EdgeIIoT-dataset.csv"
        df.to_csv(out_path, index=False)
        print(f"✅ Created Edge-IIoTset sample: {out_path} ({len(df)} rows)")

    return df


def generate_nf_ton_iot_v3_sample(
    n_records: int = 3000, save: bool = True
) -> pd.DataFrame:
    """Generate representative NF-ToN-IoT-v3 NetFlow v3 dataset."""
    attacks = [
        ("Normal", 0.35),
        ("ddos", 0.12),
        ("dos", 0.10),
        ("scanning", 0.10),
        ("password", 0.08),
        ("injection", 0.07),
        ("xss", 0.06),
        ("mitm", 0.05),
        ("backdoor", 0.04),
        ("ransomware", 0.03),
    ]
    labels, probs = zip(*attacks)
    probs = np.array(probs) / sum(probs)
    chosen_attacks = np.random.choice(labels, size=n_records, p=probs)

    data = {
        "IPV4_SRC_ADDR": [
            f"10.0.0.{np.random.randint(1, 200)}" for _ in range(n_records)
        ],
        "IPV4_DST_ADDR": [
            f"192.168.1.{np.random.randint(1, 100)}" for _ in range(n_records)
        ],
        "L4_SRC_PORT": np.random.randint(1024, 65535, size=n_records),
        "L4_DST_PORT": np.random.choice([80, 443, 21, 22, 53, 8080], size=n_records),
        "PROTOCOL": np.random.choice([6, 17, 1], p=[0.75, 0.22, 0.03], size=n_records),
        "L7_PROTO": np.random.choice([0.0, 7.0, 131.0, 188.0], size=n_records),
        "IN_BYTES": np.random.exponential(1500, size=n_records).astype(int),
        "OUT_BYTES": np.random.exponential(3500, size=n_records).astype(int),
        "IN_PKTS": np.random.poisson(8, size=n_records) + 1,
        "OUT_PKTS": np.random.poisson(12, size=n_records) + 1,
        "TCP_FLAGS": np.random.choice([2, 16, 18, 24, 27], size=n_records),
        "CLIENT_TCP_FLAGS": np.random.choice([2, 16, 24], size=n_records),
        "SERVER_TCP_FLAGS": np.random.choice([16, 18, 24], size=n_records),
        "FLOW_DURATION_MILLISECONDS": np.random.exponential(
            2500, size=n_records
        ).astype(int),
        "DURATION_IN": np.random.exponential(1200, size=n_records).astype(int),
        "DURATION_OUT": np.random.exponential(1300, size=n_records).astype(int),
        "MIN_TTL": np.random.choice([64, 128, 255], size=n_records),
        "MAX_TTL": np.random.choice([64, 128, 255], size=n_records),
        "LONGEST_FLOW_PKT": np.random.randint(64, 1500, size=n_records),
        "SHORTEST_FLOW_PKT": np.random.randint(40, 64, size=n_records),
        "MIN_IP_PKT_LEN": np.random.randint(40, 64, size=n_records),
        "MAX_IP_PKT_LEN": np.random.randint(64, 1500, size=n_records),
        "SRC_TO_DST_SECOND_BYTES": np.random.exponential(500, size=n_records),
        "DST_TO_SRC_SECOND_BYTES": np.random.exponential(800, size=n_records),
        "RETRANSMITTED_IN_BYTES": np.random.poisson(10, size=n_records),
        "RETRANSMITTED_OUT_BYTES": np.random.poisson(15, size=n_records),
        "SRC_TO_DST_AVG_THROUGHPUT": np.random.exponential(10000, size=n_records),
        "DST_TO_SRC_AVG_THROUGHPUT": np.random.exponential(20000, size=n_records),
        "NUM_PKTS_UP_TO_128_BYTES": np.random.poisson(4, size=n_records),
        "NUM_PKTS_128_TO_256_BYTES": np.random.poisson(2, size=n_records),
        "NUM_PKTS_256_TO_512_BYTES": np.random.poisson(1, size=n_records),
        "NUM_PKTS_512_TO_1024_BYTES": np.random.poisson(2, size=n_records),
        "NUM_PKTS_1024_TO_1514_BYTES": np.random.poisson(5, size=n_records),
        "TCP_WIN_MAX_IN": np.random.randint(1024, 65535, size=n_records),
        "TCP_WIN_MAX_OUT": np.random.randint(1024, 65535, size=n_records),
        "ICMP_TYPE": [0] * n_records,
        "ICMP_IPV4_TYPE": [0] * n_records,
        "DNS_QUERY_ID": [0] * n_records,
        "DNS_QUERY_TYPE": [0] * n_records,
        "DNS_TTL_ANSWER": [0] * n_records,
        "FTP_COMMAND_RET_CODE": [0] * n_records,
        "Label": [0 if a == "Normal" else 1 for a in chosen_attacks],
        "Attack": chosen_attacks,
    }

    df = pd.DataFrame(data)

    # Adjust values for attacks
    for idx, row in df.iterrows():
        atk = row["Attack"]
        if atk in ("dos", "ddos"):
            df.at[idx, "IN_PKTS"] += 50
            df.at[idx, "SRC_TO_DST_AVG_THROUGHPUT"] *= 10
        elif atk == "scanning":
            df.at[idx, "FLOW_DURATION_MILLISECONDS"] = np.random.randint(5, 50)
            df.at[idx, "IN_PKTS"] = 2
        elif atk == "password":
            df.at[idx, "IN_PKTS"] += 15
            df.at[idx, "L4_DST_PORT"] = np.random.choice([21, 22, 80])
        elif atk in ("injection", "xss"):
            df.at[idx, "IN_BYTES"] += 1200

    if save:
        out_dir = DATA_RAW / "nf_ton_iot_v3"
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / "nf_ton_iot_v3_sample.csv"
        df.to_csv(out_path, index=False)
        print(f"✅ Created NF-ToN-IoT-v3 sample: {out_path} ({len(df)} rows)")

    return df


def generate_all_samples(n_records: int = 3000):
    """Generate sample datasets for all three benchmarks."""
    print("Generating representative benchmark samples for IoT / NetFlow datasets...")
    generate_ciciot2023_sample(n_records)
    generate_edge_iiotset_sample(n_records)
    generate_nf_ton_iot_v3_sample(n_records)
    print("\n✅ All sample datasets created successfully in detection/data/raw/!")


if __name__ == "__main__":
    generate_all_samples()
