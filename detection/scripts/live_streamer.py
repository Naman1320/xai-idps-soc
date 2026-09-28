#!/usr/bin/env python3
"""
Live Telemetry & Attack Streamer Daemon:
Continuously generates and streams realistic network flow telemetry
and periodic attack waves into the XAI-IDPS-SOC platform.
"""

import time
import random
import sys
import os
import requests

API_URL = os.getenv("API_URL", "http://localhost:8000/api/v1")
STREAM_INTERVAL = int(os.getenv("STREAM_INTERVAL", "12"))  # seconds

ATTACK_TYPES = ["DDoS", "DoS Hulk", "PortScan", "SSH-Patator", "Web Attack", "Botnet", "Benign"]


def run_streamer():
    print(f"🚀 XAI-IDPS-SOC Live Telemetry Daemon Started")
    print(f"📡 Target Endpoint: {API_URL}/simulator/attack")
    print(f"⏱️  Stream Interval: {STREAM_INTERVAL}s")

    while True:
        try:
            # 70% chance benign or moderate scan, 30% critical attack
            weights = [0.15, 0.10, 0.20, 0.15, 0.10, 0.10, 0.20]
            chosen_type = random.choices(ATTACK_TYPES, weights=weights, k=1)[0]
            intensity = round(random.uniform(0.9, 1.4), 2)

            res = requests.post(
                f"{API_URL}/simulator/attack",
                json={"attack_type": chosen_type, "intensity": intensity},
                timeout=5
            )
            if res.status_code == 201:
                data = res.json()
                print(f"[{time.strftime('%H:%M:%S')}] ✓ Streamed {data['attack_class']} flow | Src: {data['source_ip']} -> Dst: {data['dest_ip']} | Risk: {int(data['risk_score']*100)}%")
            else:
                print(f"[{time.strftime('%H:%M:%S')}] Ingest HTTP {res.status_code}")
        except Exception as e:
            print(f"[{time.strftime('%H:%M:%S')}] Streamer waiting for backend: {e}")

        time.sleep(STREAM_INTERVAL)


if __name__ == "__main__":
    run_streamer()
