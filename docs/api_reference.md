# REST API Reference — XAI-IDPS-SOC

Base URL: `/api/v1`

---

## 1. Authentication

### `POST /auth/login`
Authenticate analyst or administrator.
- **Request Body**:
  ```json
  { "username": "analyst", "password": "analyst123" }
  ```
- **Response** (`200 OK`):
  ```json
  { "access_token": "eyJhbGciOi...", "token_type": "bearer", "role": "analyst", "username": "analyst" }
  ```

### `GET /auth/me`
Return current authenticated user profile.
- **Headers**: `Authorization: Bearer <token>`
- **Response** (`200 OK`):
  ```json
  { "id": "uuid", "username": "analyst", "role": "analyst" }
  ```

---

## 2. Alerts & Explainability

### `POST /alerts`
Ingest alert(s) from detection pipeline.
- **Headers**: `X-API-Key: xai-soc-pipeline-key-cicids2017`
- **Request Body**: Full Alert Ingest JSON or Array of Alert Ingest JSONs.
- **Response** (`201 Created`):
  ```json
  { "status": "success", "alert_id": "uuid", "ingested_at": "ISO-8601" }
  ```

### `GET /alerts`
List alerts with sorting, filtering, and pagination.
- **Query Parameters**:
  - `status`: `new`, `investigating`, `resolved`, `dismissed`, `closed`
  - `attack_class`: Filter by predicted attack class
  - `severity`: `Critical`, `High`, `Medium`, `Low`
  - `min_risk`: Minimum risk score (e.g. `0.70`)
  - `search`: Full text search on IPs and attack names
  - `sort_by`: `risk_score` (default), `detected_at`, `ml_confidence`
  - `order`: `desc` (default), `asc`
  - `page`: Page number (default `1`)
  - `limit`: Items per page (default `25`)

### `GET /alerts/{id}`
Retrieve full alert details, flow features, and SHAP attributions.

### `GET /alerts/{id}/explanation`
Retrieve SHAP waterfall visualization vectors and plain language narrative.
- **Response** (`200 OK`):
  ```json
  {
    "alert_id": "uuid",
    "attack_class": "DDoS",
    "ml_confidence": 0.965,
    "base_value": 0.10,
    "features": [
      { "id": "uuid", "feature_name": "Flow Packets/s", "shap_value": 0.385, "feature_value": 35714.2, "rank": 1 }
    ],
    "plain_language": {
      "summary": "Alert was classified as DDoS with 96% model confidence...",
      "primary_contributors": ["Flow Packets/s (+0.385)"],
      "mitre_context": "Correlated to MITRE ATT&CK T1498...",
      "recommended_action": "Review ingress bandwidth at perimeter firewall..."
    }
  }
  ```

### `PATCH /alerts/{id}/status`
Update triage status (`new`, `investigating`, `resolved`, `dismissed`, `closed`).

---

## 3. Incident Case Management

### `POST /cases`
Create an incident investigation case.
- **Request Body**:
  ```json
  {
    "title": "Volumetric Ingress Flood Incident",
    "severity": "critical",
    "assigned_to": "analyst",
    "notes": "Correlated DDoS flow telemetry.",
    "alert_ids": ["alert-uuid-1", "alert-uuid-2"]
  }
  ```

### `GET /cases`
List cases. Filter by `status` or `severity`.

### `GET /cases/{id}`
Retrieve case detail with all associated alerts.

### `PATCH /cases/{id}`
Update case status, notes, or final disposition (`true_positive`, `false_positive`, `benign_activity`).

---

## 4. Ground-Truth Feedback

### `POST /alerts/{id}/feedback`
Submit analyst ground-truth disposition.
- **Request Body**:
  ```json
  {
    "disposition": "true_positive",
    "notes": "Verified malicious traffic matching botnet C2 activity."
  }
  ```

---

## 5. Analytics & Metrics

### `GET /analytics/summary`
Retrieve high-level counters, attack distributions, and MITRE frequencies.

### `GET /analytics/timeline?hours=48`
Retrieve time-series threat frequencies grouped in 4-hour temporal windows.

### `GET /analytics/metrics`
Retrieve ML benchmark evaluation metrics (Macro F1, FPR, Ingestion Latency, Precision@10).

---

## 6. Risk Scoring Calibration

### `GET /settings`
Get active scoring weights, thresholds, and asset inventory.

### `POST /settings/weights`
Update weights `w1`, `w2`, `w3` (must sum to 1.0).
