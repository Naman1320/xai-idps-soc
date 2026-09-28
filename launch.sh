#!/usr/bin/env bash
# ==============================================================================
#  XAI-IDPS-SOC Master Application Launcher
#  Full Platform: ML-IDPS Engine + Cloud SOC Backend + React Triage Console
# ==============================================================================

set -e

# Terminal Colors
BOLD="\033[1m"
CYAN="\033[0;36m"
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
RED="\033[0;31m"
RESET="\033[0m"

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_ROOT"

CLOUD_PID=""
BACKEND_PID=""
FRONTEND_PID=""
STREAMER_PID=""

cleanup() {
    echo ""
    echo -e "${YELLOW}🛑 Shutting down all XAI-IDPS-SOC services...${RESET}"

    if [ -n "$STREAMER_PID" ] && kill -0 "$STREAMER_PID" 2>/dev/null; then
        echo -e "   Stopping Live Telemetry Streamer (PID: $STREAMER_PID)..."
        kill -15 "$STREAMER_PID" 2>/dev/null || kill -9 "$STREAMER_PID" 2>/dev/null
    fi

    if [ -n "$FRONTEND_PID" ] && kill -0 "$FRONTEND_PID" 2>/dev/null; then
        echo -e "   Stopping React SOC Dashboard (PID: $FRONTEND_PID)..."
        kill -15 "$FRONTEND_PID" 2>/dev/null || kill -9 "$FRONTEND_PID" 2>/dev/null
    fi

    if [ -n "$BACKEND_PID" ] && kill -0 "$BACKEND_PID" 2>/dev/null; then
        echo -e "   Stopping FastAPI SOC Backend (PID: $BACKEND_PID)..."
        kill -15 "$BACKEND_PID" 2>/dev/null || kill -9 "$BACKEND_PID" 2>/dev/null
    fi

    if [ -n "$CLOUD_PID" ] && kill -0 "$CLOUD_PID" 2>/dev/null; then
        echo -e "   Stopping Cloud Emulator (PID: $CLOUD_PID)..."
        kill -15 "$CLOUD_PID" 2>/dev/null || kill -9 "$CLOUD_PID" 2>/dev/null
    fi

    lsof -i :8000 -t 2>/dev/null | xargs kill -9 2>/dev/null || true
    lsof -i :5173 -t 2>/dev/null | xargs kill -9 2>/dev/null || true
    lsof -i :4566 -t 2>/dev/null | xargs kill -9 2>/dev/null || true

    echo -e "${GREEN}✓ All services stopped cleanly. Goodbye!${RESET}"
    exit 0
}

trap cleanup SIGINT SIGTERM EXIT

echo -e "${CYAN}${BOLD}"
echo "=========================================================================="
echo "  🛡️  XAI-IDPS-SOC FULL CLOUD PLATFORM LAUNCHER"
echo "  Explainable AI Intrusion Detection & Context-Enriched Cloud SOC Triage"
echo "  B.Tech Cybersecurity Final-Year Capstone Project"
echo "=========================================================================="
echo -e "${RESET}"

# Release ports 8000, 5173, and 4566 if lingering
lsof -i :8000 -t 2>/dev/null | xargs kill -9 2>/dev/null || true
lsof -i :5173 -t 2>/dev/null | xargs kill -9 2>/dev/null || true
lsof -i :4566 -t 2>/dev/null | xargs kill -9 2>/dev/null || true
sleep 1

# 0. Start Local Cloud Emulator ($0-Cost S3/SQS)
echo -e "${CYAN}▶ Starting Local Cloud Emulator ($0-cost S3/SQS on http://localhost:4566)...${RESET}"
cd "$PROJECT_ROOT"
python3 -m uvicorn cloud.main:app --host 0.0.0.0 --port 4566 > "$PROJECT_ROOT/cloud.log" 2>&1 &
CLOUD_PID=$!
echo -e "  ${GREEN}✓${RESET} Cloud emulator spawned (PID: $CLOUD_PID)"

# 1. Start FastAPI SOC Backend
echo -e "${CYAN}▶ Starting Cloud SOC Backend (FastAPI on http://localhost:8000)...${RESET}"
cd "$PROJECT_ROOT/soc-backend"
python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8000 > "$PROJECT_ROOT/backend.log" 2>&1 &
BACKEND_PID=$!
echo -e "  ${GREEN}✓${RESET} Backend process spawned (PID: $BACKEND_PID)"

# Wait for backend health
echo -n "  Waiting for backend database and API readiness..."
for i in {1..20}; do
    if curl -s http://localhost:8000/health | grep -q "healthy"; then
        echo -e " ${GREEN}READY!${RESET}"
        break
    fi
    sleep 0.5
    echo -n "."
done

# 2. Start React SOC Dashboard
echo -e "${CYAN}▶ Starting React SOC Dashboard (Vite on http://localhost:5173)...${RESET}"
cd "$PROJECT_ROOT/soc-dashboard"
npm run dev -- --host 0.0.0.0 --port 5173 > "$PROJECT_ROOT/frontend.log" 2>&1 &
FRONTEND_PID=$!
echo -e "  ${GREEN}✓${RESET} Dashboard process spawned (PID: $FRONTEND_PID)"

# Wait for frontend readiness
echo -n "  Waiting for dashboard dev server..."
for i in {1..20}; do
    if curl -s -I http://localhost:5173 | grep -q "200 OK"; then
        echo -e " ${GREEN}READY!${RESET}"
        break
    fi
    sleep 0.5
    echo -n "."
done

# 3. Start Live Telemetry & Attack Streamer Daemon
echo -e "${CYAN}▶ Starting Live Telemetry Daemon (periodic flow injections)...${RESET}"
cd "$PROJECT_ROOT"
python3 detection/scripts/live_streamer.py > "$PROJECT_ROOT/streamer.log" 2>&1 &
STREAMER_PID=$!
echo -e "  ${GREEN}✓${RESET} Streamer daemon active (PID: $STREAMER_PID)"

echo ""
echo -e "${GREEN}${BOLD}=========================================================================="
echo "  🎉 XAI-IDPS-SOC APPLICATION IS LIVE AND READY!"
echo "=========================================================================="
echo -e "  🖥️  SOC Analyst Dashboard:  ${CYAN}http://localhost:5173${RESET}"
echo -e "  📚 Swagger API Docs:        ${CYAN}http://localhost:8000/docs${RESET}"
echo -e "  ☁️  Cloud S3/SQS Emulator:  ${CYAN}http://localhost:4566/health${RESET}"
echo -e "  👤 Demo Analyst Account:    ${BOLD}analyst / analyst123${RESET}"
echo -e "  👑 Demo Admin Account:      ${BOLD}admin / admin123${RESET}"
echo -e "${GREEN}==========================================================================${RESET}"
echo ""
echo -e "${YELLOW}Press [Ctrl+C] anytime to stop all services.${RESET}"

# Open in browser on macOS
if command -v open &>/dev/null; then
    open "http://localhost:5173" || true
fi

# Keep script running
wait
