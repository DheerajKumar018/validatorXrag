import os
import logging
from datetime import datetime, timezone
from databases import Database
from sqlalchemy import text, MetaData, Table, Column, Integer, String, DateTime, Text
from tenacity import retry, stop_after_attempt, wait_fixed

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# ------------------------------------------------------------
# 🌐 Database Setup
# ------------------------------------------------------------
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("❌ DATABASE_URL environment variable not set!")

database = Database(DATABASE_URL)
metadata = MetaData()

# ------------------------------------------------------------
# 🧱 Table Definitions
# ------------------------------------------------------------
incidents_table = Table(
    "incidents",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("timestamp", DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)),
    Column("ip", String(45)),
    Column("payload", Text),
    Column("rule_triggered", String(255)),
    Column("status", String(50), default="open"),
)

requests_table = Table(
    "requests",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("timestamp", DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)),
    Column("status", String(50)),
    Column("client_ip", String(45)),
)

ttps_table = Table(
    "ttps",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("timestamp", DateTime(timezone=True), default=lambda: datetime.now(timezone.utc)),
    Column("incident_id", Integer),
    Column("technique_id", String(100)),
    Column("technique_name", String(255)),
    Column("description", Text),
)

suricata_table = Table(
    "suricata_logs",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("timestamp", DateTime(timezone=True)),
    Column("source", String(45)),
    Column("signature", Text),
    Column("category", String(255)),
    Column("severity", Integer),
)

# ------------------------------------------------------------
# 🛠 Database Setup Function
# ------------------------------------------------------------
@retry(stop=stop_after_attempt(5), wait=wait_fixed(2))
async def setup_database():
    logging.info("[DB Setup] Initializing tables...")
    try:
        await database.execute(text("""
            CREATE TABLE IF NOT EXISTS incidents (
                id SERIAL PRIMARY KEY,
                timestamp TIMESTAMPTZ NOT NULL,
                ip VARCHAR(45),
                payload TEXT,
                rule_triggered VARCHAR(255),
                status VARCHAR(50)
            );
        """))
        await database.execute(text("""
            CREATE TABLE IF NOT EXISTS requests (
                id SERIAL PRIMARY KEY,
                timestamp TIMESTAMPTZ NOT NULL,
                status VARCHAR(50),
                client_ip VARCHAR(45)
            );
        """))
        await database.execute(text("""
            CREATE TABLE IF NOT EXISTS ttps (
                id SERIAL PRIMARY KEY,
                timestamp TIMESTAMPTZ NOT NULL,
                incident_id INTEGER,
                technique_id VARCHAR(100),
                technique_name VARCHAR(255),
                description TEXT
            );
        """))
        await database.execute(text("""
            CREATE TABLE IF NOT EXISTS suricata_logs (
                id SERIAL PRIMARY KEY,
                timestamp TIMESTAMPTZ NOT NULL,
                source VARCHAR(45),
                signature TEXT,
                category VARCHAR(255),
                severity INTEGER
            );
        """))
        logging.info("✅ Database tables confirmed / created successfully.")
    except Exception as e:
        logging.error(f"❌ Database setup failed: {e}", exc_info=True)
        raise

# ------------------------------------------------------------
# 🧾 Logging Functions
# ------------------------------------------------------------
async def log_request(status: str, client_ip: str):
    try:
        query = requests_table.insert().values(
            status=status,
            client_ip=client_ip,
            timestamp=datetime.now(timezone.utc),
        )
        await database.execute(query)
        logging.info(f"✅ Request logged: {status} from {client_ip}")
    except Exception as e:
        logging.error(f"❌ Failed to log request: {e}", exc_info=True)

async def log_ttp(incident_id: int, technique_id: str, technique_name: str, description: str):
    try:
        query = ttps_table.insert().values(
            incident_id=incident_id,
            technique_id=technique_id,
            technique_name=technique_name,
            description=description,
            timestamp=datetime.now(timezone.utc),
        )
        await database.execute(query)
        logging.info(f"🧠 Logged TTP: {technique_id} - {technique_name}")
    except Exception as e:
        logging.error(f"❌ Failed to log TTP: {e}", exc_info=True)

async def log_incident(ip: str, payload: str, rule: str):
    try:
        insert_query = incidents_table.insert().values(
            ip=ip,
            payload=payload,
            rule_triggered=rule,
            timestamp=datetime.now(timezone.utc),
        ).returning(incidents_table.c.id)
        incident_id = await database.execute(insert_query)
        logging.warning(f"🚨 Incident logged (ID={incident_id}) - Rule: {rule} from {ip}")

        # --- Auto MITRE mapping ---
        if "SQL" in rule.upper():
            await log_ttp(incident_id, "T1190", "Exploit Public-Facing Application", "SQL Injection attempt detected.")
        elif "XSS" in rule.upper():
            await log_ttp(incident_id, "T1059.007", "Cross-Site Scripting (XSS)", "Potential XSS attack detected.")

        await log_request(status="error", client_ip=ip)
    except Exception as e:
        logging.error(f"❌ Failed to log incident: {e}", exc_info=True)

async def log_suricata_alert(timestamp, source, signature, category, severity):
    try:
        query = suricata_table.insert().values(
            timestamp=timestamp,
            source=source,
            signature=signature,
            category=category,
            severity=severity,
        )
        await database.execute(query)
        logging.info(f"🛡️ Suricata alert logged: {signature} ({category})")
    except Exception as e:
        logging.error(f"❌ Failed to log Suricata alert: {e}", exc_info=True)

# ------------------------------------------------------------
# 📊 Query Functions
# ------------------------------------------------------------
async def get_api_usage():
    try:
        query = text("""
            SELECT
                to_char(date_trunc('hour', timestamp) + floor(extract(minute from timestamp) / 5) * interval '5 minutes', 'HH24:MI') AS time,
                COUNT(CASE WHEN status = 'success' THEN 1 END) AS success,
                COUNT(CASE WHEN status = 'error' THEN 1 END) AS errors
            FROM requests
            WHERE timestamp > NOW() - INTERVAL '1 hour'
            GROUP BY time
            ORDER BY time;
        """)
        results = await database.fetch_all(query)
        usage = []
        for row in results:
            row_dict = dict(row._mapping)
            total = int(row_dict.get("success", 0)) + int(row_dict.get("errors", 0))
            usage.append({
                "time": row_dict["time"],
                "rps": total,
                "success": int(row_dict.get("success", 0)),
                "errors": int(row_dict.get("errors", 0)),
            })
        return usage
    except Exception as e:
        logging.error(f"❌ Failed to fetch API usage: {e}", exc_info=True)
        return []

async def get_incidents():
    try:
        query = incidents_table.select().order_by(incidents_table.c.timestamp.desc()).limit(500)
        results = await database.fetch_all(query)
        incidents = [dict(row._mapping) for row in results]
        for inc in incidents:
            if isinstance(inc.get("timestamp"), datetime):
                inc["timestamp"] = inc["timestamp"].isoformat()
        return incidents
    except Exception as e:
        logging.error(f"❌ Failed to fetch incidents: {e}", exc_info=True)
        return []

async def get_ttps():
    try:
        query = ttps_table.select().order_by(ttps_table.c.timestamp.desc()).limit(500)
        results = await database.fetch_all(query)
        ttps = [dict(row._mapping) for row in results]
        for ttp in ttps:
            if isinstance(ttp.get("timestamp"), datetime):
                ttp["timestamp"] = ttp["timestamp"].isoformat()
        return ttps
    except Exception as e:
        logging.error(f"❌ Failed to fetch TTPs: {e}", exc_info=True)
        return []

async def mark_incident_handled(incident_id: int):
    try:
        query = text("UPDATE incidents SET status = 'handled' WHERE id = :id")
        await database.execute(query, values={"id": incident_id})
        logging.info(f"✅ Incident {incident_id} marked as handled.")
        return True
    except Exception as e:
        logging.error(f"❌ Failed to mark incident handled: {e}", exc_info=True)
        return False

