# Setup & Deployment Guide — XAI-IDPS-SOC

## Prerequisites

- **Python 3.10+** (tested on 3.12)
- **Node.js 18+** & npm
- (Optional) **Docker & Docker Compose** for one-command deployment

---

## Option 1: Running Locally (Development Mode)

### Step 1: Start the Backend (FastAPI)
```bash
cd soc-backend
python3 -m pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```
The backend will automatically create SQLite database `soc.db`, initialize tables, and seed demo security alerts and cases.
- Swagger UI Documentation: `http://localhost:8000/docs`
- Health check: `http://localhost:8000/health`

### Step 2: Start the Dashboard (React Vite)
In a separate terminal:
```bash
cd soc-dashboard
npm install
npm run dev
```
Open `http://localhost:5173` in your browser.

Demo Accounts:
- **Analyst**: `analyst` / `analyst123`
- **Administrator**: `admin` / `admin123`

---

## Option 2: One-Command Docker Compose

To spin up the PostgreSQL database, FastAPI backend, and React Nginx dashboard with a single command:

```bash
docker-compose up --build
```

Access:
- Dashboard: `http://localhost:3000`
- Backend API: `http://localhost:8000`

---

## Option 3: Running the ML Detection Pipeline

### 1. Preprocess Dataset
```bash
cd detection
python3 scripts/preprocess_data.py --dataset cicids2017
```

### 2. Train Models (Baseline RF, Tuned RF, XGBoost)
```bash
python3 scripts/train_model.py --model tuned_rf --dataset cicids2017
```

### 3. Run Pipeline Inference & Ingest to SOC
```bash
python3 scripts/run_detection.py --model tuned_rf --dataset cicids2017 --forward
```

### 4. Run Test Suite
```bash
python3 -m pytest tests
```
