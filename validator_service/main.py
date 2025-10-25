import os
import logging
from datetime import datetime
from collections import defaultdict
from typing import List, Dict, Any
import httpx

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from incident_logger import (
    database,
    setup_database,
    log_incident,
    log_request,
    log_suricata_alert,
    get_incidents,
    get_api_usage,
    suricata_table,
)
from owasp_rules import OWASP_RULES
from regex_rules import check_regex_rules

# ==============================================================
# 🌍 APP CONFIGURATION
# ==============================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

app = FastAPI(title="MedSecureX Backend", version="2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # You can restrict this to your frontend domain later
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

ADMIN_KEY = os.getenv("ADMIN_KEY", "supersecretadminkey")
RAG_SERVICE_URL = os.getenv("RAG_SERVICE_URL", "http://rag-service:8000/analyze-payload")
# ==============================================================
# 🚀 STARTUP & SHUTDOWN
# ==============================================================

@app.on_event("startup")
async def startup():
    try:
        await database.connect()
        await setup_database()
        logging.info("✅ Database connected and verified successfully.")
        if not RAG_SERVICE_URL:
            logging.warning("⚠️ RAG_SERVICE_URL is not set. RAG validation will be skipped.")
    except Exception as e:
        logging.error(f"❌ Failed to initialize database: {e}", exc_info=True)
        raise

@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()
    logging.info("🛑 Database disconnected successfully.")


# ==============================================================
# 🔐 ADMIN AUTH
# ==============================================================

def admin_auth(key: str):
    if key != ADMIN_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized access.")


# ==============================================================
# 🧱 PAYLOAD INSPECTION MIDDLEWARE
# ==============================================================

@app.middleware("http")
async def payload_inspection_middleware(request: Request, call_next):
    """Inspect incoming payloads for malicious patterns (OWASP + regex)."""
    path = request.url.path
    method = request.method

    if path.startswith(("/api/", "/admin", "/health")):
        # Skip internal endpoints
        return await call_next(request)

    client_ip = request.client.host if request.client else "unknown"
    try:
        body_bytes = await request.body()
        payload_text = body_bytes.decode("utf-8", errors="ignore")
    except Exception:
        payload_text = ""

    payload = payload_text + (request.url.query or "")

    # --- OWASP RULE DETECTION ---
    for rule_name, rule_fn in OWASP_RULES.items():
        try:
            if callable(rule_fn) and rule_fn(payload):
                logging.warning(f"🚨 OWASP rule triggered: {rule_name} from {client_ip}")
                await log_incident(client_ip, payload, rule_name)
                return JSONResponse(
                    status_code=403,
                    content={"detail": f"Blocked by OWASP rule: {rule_name}"},
                )
        except Exception as e:
            logging.error(f"Error evaluating rule {rule_name}: {e}", exc_info=True)

    # --- REGEX RULE DETECTION ---
    triggered = check_regex_rules(payload)
    if triggered:
        logging.warning(f"🚨 Regex rule(s) triggered: {triggered}")
        for r in triggered:
            await log_incident(client_ip, payload, r)
        return JSONResponse(
            status_code=403,
            content={"detail": f"Blocked by Regex rule(s): {', '.join(triggered)}"},
        )
    # ==============================================================
    # 🧠 NEW: RAG SERVICE VALIDATION
    # ==============================================================
    if RAG_SERVICE_URL:
        logging.info(f"🤔 Payload is unknown. Forwarding to RAG service for analysis.")
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(RAG_SERVICE_URL, json={"payload": payload})
                response.raise_for_status()
                rag_data = response.json()

            if rag_data.get("verdict") == "malicious":
                rule_name = f"RAG: {rag_data.get('detected_pattern', 'Unknown Pattern')}"
                logging.warning(f"🚨 RAG service identified payload as malicious from {client_ip}")
                await log_incident(client_ip, payload, rule_name)
                # NOTE: The feedback loop to update OWASP/Regex rules would go here.
                return JSONResponse(
                    status_code=403,
                    content={"detail": f"Blocked by RAG analysis: {rule_name}"},
                )

        except httpx.RequestError as e:
            logging.error(f"❌ Could not connect to RAG service: {e}")
            # Failsafe: If RAG is down, you might choose to block or allow.
            # Here, we'll block to be safe.
            return JSONResponse(
                status_code=503,
                content={"detail": "Service Unavailable: Analysis service is down."},
            )
    # ==============================================================
    # --- Safe request ---
    await log_request(status="success", client_ip=client_ip)
    response = await call_next(request)
    return response


# ==============================================================
# 📊 API ENDPOINTS
# ==============================================================

@app.get("/api/blocked-requests", response_model=List[Dict[str, Any]])
async def blocked_requests():
    """Return number of blocked requests grouped by 5-minute intervals."""
    incidents = await get_incidents()
    buckets = defaultdict(int)
    for inc in incidents:
        try:
            dt = datetime.fromisoformat(inc["timestamp"])
            minute = (dt.minute // 5) * 5
            time_key = f"{dt.hour:02d}:{minute:02d}"
            buckets[time_key] += 1
        except Exception:
            continue
    return [{"time": t, "blocked": c} for t, c in sorted(buckets.items())]


@app.get("/api/api-usage")
async def api_usage():
    """Return API usage statistics over time."""
    return await get_api_usage()


@app.get("/admin/incidents")
async def admin_list_incidents(key: str):
    """Admin view for all incidents."""
    admin_auth(key)
    return await get_incidents()


@app.get("/health")
def health():
    """Health check endpoint."""
    return {"status": "ok", "service": "MedSecureX Backend"}


# ==============================================================
# 🧠 MITRE TTP AGGREGATION (CACHED)
# ==============================================================

MITRE_MAP = {
    "SQL Injection": {"id": "T1190", "tactic": "Execution"},
    "XSS": {"id": "T1059.007", "tactic": "Execution"},
    "Path Traversal": {"id": "T1083", "tactic": "Discovery"},
    "Brute Force": {"id": "T1110", "tactic": "Credential Access"},
}

@app.get("/api/ttps")
async def get_ttp_data(limit: int = 100):
    """Aggregate incidents by rule and return MITRE-mapped objects."""
    try:
        query = """
            SELECT
                rule_triggered,
                COUNT(*) AS count,
                MAX(timestamp) AS last_seen,
                (array_agg(payload ORDER BY timestamp DESC))[1] AS sample_payload,
                (array_agg(ip ORDER BY timestamp DESC))[1] AS sample_ip
            FROM incidents
            WHERE rule_triggered IS NOT NULL
            GROUP BY rule_triggered
            ORDER BY count DESC
            LIMIT :limit;
        """
        results = await database.fetch_all(query, values={"limit": limit})

        ttps = []
        for row in results:
            data = dict(row._mapping)
            rule = data["rule_triggered"]
            mapping = MITRE_MAP.get(rule, {"id": "Unknown", "tactic": "Unmapped"})

            snippet = data.get("sample_payload")
            if snippet and len(snippet) > 250:
                snippet = snippet[:250] + "..."

            ttps.append({
                "id": mapping["id"],
                "name": rule,
                "tactic": mapping["tactic"],
                "count": data["count"],
                "lastSeen": (
                    data["last_seen"].isoformat()
                    if isinstance(data["last_seen"], datetime)
                    else data["last_seen"]
                ),
                "description": f"Latest detection of {rule} from {data.get('sample_ip', 'N/A')}",
                "example": snippet or "N/A",
            })
        return ttps
    except Exception as e:
        logging.error(f"❌ Could not fetch TTP data: {e}", exc_info=True)
        return JSONResponse(content={"error": str(e)}, status_code=500)


# ==============================================================
# 🧩 SURICATA LOGS FETCH ENDPOINT
# ==============================================================

@app.get("/api/api-gateway")
async def get_suricata_logs(limit: int = 100):
    """Return latest Suricata alerts."""
    try:
        query = suricata_table.select().order_by(suricata_table.c.timestamp.desc()).limit(limit)
        results = await database.fetch_all(query)
        logs = [dict(row._mapping) for row in results]
        for log in logs:
            if isinstance(log.get("timestamp"), datetime):
                log["timestamp"] = log["timestamp"].isoformat()
        return {"alerts": logs}
    except Exception as e:
        logging.error(f"❌ Failed to fetch Suricata logs: {e}", exc_info=True)
        return {"alerts": []}


# ==============================================================
# 🆕 INCIDENT ENDPOINT (For Suricata Watcher)
# ==============================================================

@app.post("/api/incidents")
async def add_incident(request: Request, key: str):
    """
    Endpoint to receive incidents from Suricata watcher or other sources.
    Requires ?key=<ADMIN_KEY> for authorization.
    """
    try:
        admin_auth(key)
        data = await request.json()
        ip = data.get("ip", "unknown")
        payload = data.get("payload", "")
        rule = data.get("rule", "Unknown")

        await log_incident(ip=ip, payload=payload, rule=rule)

        if rule.startswith("SURICATA"):
            await log_suricata_alert(
                timestamp=datetime.utcnow(),
                source=ip,
                signature=rule,
                category="Suricata Alert",
                severity=2
            )

        return JSONResponse(
            status_code=200,
            content={"status": "success", "message": "Incident logged successfully"},
        )

    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"❌ Failed to log incident: {e}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"status": "error", "message": str(e)},
        )


# ==============================================================
# 🧩 FALLBACK ROUTE
# ==============================================================

@app.api_route("/{path_name:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def catch_all(request: Request, path_name: str):
    """Handles non-API routes safely."""
    return {"message": "Request processed successfully.", "path": f"/{path_name}"}
