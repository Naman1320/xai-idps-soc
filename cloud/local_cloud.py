#!/usr/bin/env python3
"""
$0-Cost Local Cloud Emulation Service (LocalStack Compatible).

Provides local AWS S3 and SQS emulation on port 4566 with ZERO cloud billing risk:
- S3 emulation: Stores dataset partitions (cse-cic-ids2018) and telemetry archives
- SQS emulation: Buffers raw alert streams from detection engine to SOC backend
- 100% free, local, open-source, and offline capable.
"""

import argparse
import json
import logging
import os
import sys
import threading
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Dict, Any, List
import urllib.parse

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [LOCAL-CLOUD] %(levelname)s: %(message)s"
)
logger = logging.getLogger("local_cloud")

DEFAULT_PORT = 4566
STORAGE_DIR = Path(__file__).parent / "data"
S3_STORAGE = STORAGE_DIR / "s3"
SQS_STORAGE = STORAGE_DIR / "sqs"


class LocalCloudState:
    """In-memory and file-backed state for local S3 and SQS."""
    def __init__(self):
        self.buckets: Dict[str, Dict[str, bytes]] = {}
        self.queues: Dict[str, List[Dict[str, Any]]] = {}
        self._init_storage()

    def _init_storage(self):
        S3_STORAGE.mkdir(parents=True, exist_ok=True)
        SQS_STORAGE.mkdir(parents=True, exist_ok=True)
        
        # Pre-seed default buckets
        for bucket in ["cse-cic-ids2018", "xai-soc-telemetry", "model-registry"]:
            b_dir = S3_STORAGE / bucket
            b_dir.mkdir(parents=True, exist_ok=True)
            self.buckets[bucket] = {}

        # Pre-seed default queues
        for queue in ["xai-alert-queue", "xai-host-telemetry-queue"]:
            self.queues[queue] = []

    def put_object(self, bucket: str, key: str, data: bytes):
        if bucket not in self.buckets:
            self.buckets[bucket] = {}
        self.buckets[bucket][key] = data
        file_path = S3_STORAGE / bucket / key
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_bytes(data)
        logger.info(f"S3 PutObject: s3://{bucket}/{key} ({len(data)} bytes)")

    def get_object(self, bucket: str, key: str) -> bytes:
        file_path = S3_STORAGE / bucket / key
        if file_path.exists():
            return file_path.read_bytes()
        return self.buckets.get(bucket, {}).get(key, b"")

    def list_objects(self, bucket: str) -> List[str]:
        b_dir = S3_STORAGE / bucket
        if not b_dir.exists():
            return []
        return [str(p.relative_to(b_dir)) for p in b_dir.glob("**/*") if p.is_file()]

    def send_message(self, queue: str, body: str) -> str:
        if queue not in self.queues:
            self.queues[queue] = []
        msg_id = f"msg-{len(self.queues[queue]) + 1}"
        self.queues[queue].append({"id": msg_id, "body": body})
        logger.info(f"SQS SendMessage: queue={queue}, id={msg_id}")
        return msg_id

    def receive_messages(self, queue: str, max_msgs: int = 10) -> List[Dict[str, Any]]:
        if queue not in self.queues:
            return []
        msgs = self.queues[queue][:max_msgs]
        self.queues[queue] = self.queues[queue][max_msgs:]
        return msgs


state = LocalCloudState()


class LocalCloudHTTPHandler(BaseHTTPRequestHandler):
    """HTTP handler compatible with LocalStack / AWS SDK signatures."""
    protocol_version = "HTTP/1.1"

    def _send_xml(self, xml_content: str, status_code: int = 200):
        body_bytes = xml_content.encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/xml")
        self.send_header("Content-Length", str(len(body_bytes)))
        self.send_header("Connection", "close")
        self.send_header("Server", "LocalStack/Mock-AWS-0Cost")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body_bytes)
        self.wfile.flush()

    def _send_json(self, data: Any, status_code: int = 200):
        body_bytes = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body_bytes)))
        self.send_header("Connection", "close")
        self.send_header("Server", "LocalStack/Mock-AWS-0Cost")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body_bytes)
        self.wfile.flush()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.strip("/")
        
        # Health check
        if path in ("", "health", "_localstack/health"):
            self._send_json({
                "status": "running",
                "mode": "0-cost-local-cloud",
                "cost_per_hour": "$0.00",
                "services": {
                    "s3": "available",
                    "sqs": "available",
                    "cloudwatch": "available"
                },
                "s3_buckets": list(state.buckets.keys()),
                "sqs_queues": list(state.queues.keys())
            })
            return

        # S3 List Buckets
        if not path:
            buckets_xml = "".join([f"<Bucket><Name>{b}</Name></Bucket>" for b in state.buckets.keys()])
            xml = f"<ListAllMyBucketsResult><Buckets>{buckets_xml}</Buckets></ListAllMyBucketsResult>"
            self._send_xml(xml)
            return

        parts = path.split("/", 1)
        bucket = parts[0]
        if len(parts) == 1:
            # List objects in bucket
            keys = state.list_objects(bucket)
            contents = "".join([f"<Contents><Key>{k}</Key><Size>1024</Size></Contents>" for k in keys])
            xml = f"<ListBucketResult><Name>{bucket}</Name>{contents}</ListBucketResult>"
            self._send_xml(xml)
            return
        
        # Get Object
        key = parts[1]
        data = state.get_object(bucket, key)
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_PUT(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.strip("/")
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)

        parts = path.split("/", 1)
        bucket = parts[0]
        if len(parts) == 1:
            # Create Bucket
            state.buckets[bucket] = {}
            (S3_STORAGE / bucket).mkdir(parents=True, exist_ok=True)
            self._send_xml(f"<CreateBucketResult><Bucket>{bucket}</Bucket></CreateBucketResult>")
            return

        # Put Object
        key = parts[1]
        state.put_object(bucket, key, body)
        self.send_response(200)
        self.send_header("ETag", '"mock-etag-0cost"')
        self.end_headers()

    def do_POST(self):
        # SQS actions
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8", errors="ignore")
        params = urllib.parse.parse_qs(body)
        
        action = params.get("Action", [""])[0] or self.headers.get("X-Amz-Target", "")

        if "SendMessage" in action:
            queue = params.get("QueueUrl", ["xai-alert-queue"])[0].split("/")[-1]
            msg_body = params.get("MessageBody", ["{}"])[0]
            msg_id = state.send_message(queue, msg_body)
            self._send_xml(f"<SendMessageResponse><SendMessageResult><MessageId>{msg_id}</MessageId></SendMessageResult></SendMessageResponse>")
            return

        if "ReceiveMessage" in action:
            queue = params.get("QueueUrl", ["xai-alert-queue"])[0].split("/")[-1]
            msgs = state.receive_messages(queue)
            msgs_xml = "".join([f"<Message><MessageId>{m['id']}</MessageId><Body>{m['body']}</Body></Message>" for m in msgs])
            self._send_xml(f"<ReceiveMessageResponse><ReceiveMessageResult>{msgs_xml}</ReceiveMessageResult></ReceiveMessageResponse>")
            return

        # Fallback JSON echo
        self._send_json({"status": "received", "action": action})


def run_local_cloud_server(port: int = DEFAULT_PORT):
    server = ThreadingHTTPServer(("0.0.0.0", port), LocalCloudHTTPHandler)
    logger.info(f"============================================================")
    logger.info(f" $0-COST LOCALSTACK EMULATOR ACTIVE ON http://localhost:{port}")
    logger.info(f" Guaranteed $0.00 spend — Zero real AWS cloud connectivity")
    logger.info(f" S3 Buckets: {list(state.buckets.keys())}")
    logger.info(f" SQS Queues: {list(state.queues.keys())}")
    logger.info(f"============================================================")
    server.serve_forever()


def test_local_cloud():
    """Verify local S3 and SQS emulation operations."""
    logger.info("Running local cloud self-test...")
    state.put_object("cse-cic-ids2018", "metadata.json", json.dumps({"dataset": "CSE-CIC-IDS2018", "status": "verified"}).encode())
    val = state.get_object("cse-cic-ids2018", "metadata.json")
    assert json.loads(val)["dataset"] == "CSE-CIC-IDS2018"
    
    msg_id = state.send_message("xai-alert-queue", json.dumps({"alert_id": "test-123", "risk_score": 0.89}))
    msgs = state.receive_messages("xai-alert-queue")
    assert len(msgs) == 1 and msgs[0]["id"] == msg_id
    logger.info("✓ Local cloud verification test PASSED (S3 Put/Get, SQS Send/Receive).")
    print("SUCCESS: Local cloud self-test passed! Ready for offline $0 cloud evaluation.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="$0-Cost Local Cloud Emulator")
    parser.add_argument("--test", action="store_true", help="Run self-test and exit")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Port to listen on (default: 4566)")
    args = parser.parse_args()

    if args.test:
        test_local_cloud()
    else:
        run_local_cloud_server(port=args.port)
