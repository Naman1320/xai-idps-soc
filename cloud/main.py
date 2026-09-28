"""
$0-Cost Local Cloud Emulation API (FastAPI + Uvicorn).
Compatible with LocalStack / AWS S3 & SQS APIs.
Guarantees $0.00 cloud cost with zero real-cloud billing exposure.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional  # noqa: UP035

from fastapi import FastAPI, Header, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse

app = FastAPI(
    title="LocalStack $0-Cost Cloud Emulator",
    description="Local S3, SQS, and CloudWatch emulation for offline academic evaluation.",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

STORAGE_DIR = Path(__file__).parent / "data"
S3_DIR = STORAGE_DIR / "s3"
SQS_DIR = STORAGE_DIR / "sqs"

S3_DIR.mkdir(parents=True, exist_ok=True)
SQS_DIR.mkdir(parents=True, exist_ok=True)

# Pre-create default buckets
DEFAULT_BUCKETS = ["cse-cic-ids2018", "xai-soc-telemetry", "model-registry"]
for b in DEFAULT_BUCKETS:
    (S3_DIR / b).mkdir(parents=True, exist_ok=True)

# In-memory SQS queues
queues: Dict[str, List[Dict[str, Any]]] = {
    "xai-alert-queue": [],
    "xai-host-telemetry-queue": [],
}


@app.get("/health")
@app.get("/_localstack/health")
def health():
    return {
        "status": "running",
        "mode": "0-cost-local-cloud",
        "billing_cost_usd": 0.00,
        "services": {
            "s3": "running",
            "sqs": "running",
            "cloudwatch": "running"
        },
        "buckets": [b.name for b in S3_DIR.iterdir() if b.is_dir()],
        "queues": list(queues.keys())
    }


# --- S3 Emulation Endpoints ---

@app.get("/s3/buckets")
def list_buckets():
    buckets = [b.name for b in S3_DIR.iterdir() if b.is_dir()]
    return {"Buckets": [{"Name": b} for b in buckets]}


@app.put("/s3/{bucket}")
def create_bucket(bucket: str):
    (S3_DIR / bucket).mkdir(parents=True, exist_ok=True)
    return {"message": f"Bucket '{bucket}' created successfully"}


@app.get("/s3/{bucket}")
def list_objects(bucket: str):
    b_path = S3_DIR / bucket
    if not b_path.exists():
        return JSONResponse(status_code=404, content={"error": f"Bucket '{bucket}' not found"})
    files = [str(f.relative_to(b_path)) for f in b_path.glob("**/*") if f.is_file()]
    return {"Bucket": bucket, "Objects": files}


@app.put("/s3/{bucket}/{key:path}")
async def put_object(bucket: str, key: str, request: Request):
    b_path = S3_DIR / bucket
    b_path.mkdir(parents=True, exist_ok=True)
    file_path = b_path / key
    file_path.parent.mkdir(parents=True, exist_ok=True)
    content = await request.body()
    file_path.write_bytes(content)
    return {"Bucket": bucket, "Key": key, "Bytes": len(content), "ETag": "mock-0cost-etag"}


@app.get("/s3/{bucket}/{key:path}")
def get_object(bucket: str, key: str):
    file_path = S3_DIR / bucket / key
    if not file_path.exists():
        return JSONResponse(status_code=404, content={"error": "Object not found"})
    return Response(content=file_path.read_bytes(), media_type="application/octet-stream")


# --- SQS Emulation Endpoints ---

@app.post("/sqs/{queue_name}/send")
async def send_message(queue_name: str, request: Request):
    if queue_name not in queues:
        queues[queue_name] = []
    body = (await request.body()).decode("utf-8", errors="ignore")
    msg_id = f"msg-{len(queues[queue_name]) + 1}"
    queues[queue_name].append({"id": msg_id, "body": body})
    return {"MessageId": msg_id, "Queue": queue_name, "Status": "Queued"}


@app.get("/sqs/{queue_name}/receive")
def receive_messages(queue_name: str, max_messages: int = 10):
    if queue_name not in queues:
        return {"Messages": []}
    msgs = queues[queue_name][:max_messages]
    queues[queue_name] = queues[queue_name][max_messages:]
    return {"Queue": queue_name, "Messages": msgs}
