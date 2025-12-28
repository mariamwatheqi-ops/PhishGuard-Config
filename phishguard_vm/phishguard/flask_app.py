# flask_app.py
# PhishGuard unified Flask application (GitHub-safe version)
#


from flask import Flask, render_template, jsonify, request, redirect, url_for, session, abort
from functools import wraps
from datetime import datetime, timezone
import imaplib
import email
from email.header import decode_header, make_header
import joblib
import requests
import time
import pytz
import base64
import json
import os
import psycopg2
from psycopg2.extras import RealDictCursor
import boto3
from requests.auth import HTTPBasicAuth
import traceback
import uuid
from werkzeug.security import generate_password_hash, check_password_hash

# ------------------------------------------------------------
# CONFIG (GitHub-safe placeholders)
# ------------------------------------------------------------
# AWS S3
S3_BUCKET = "YOUR_S3_BUCKET_NAME"
S3_REGION = "us-east-1"  # example: us-east-1

# AWS RDS PostgreSQL
RDS_HOST = "YOUR_RDS_ENDPOINT"
RDS_PORT = 5432
RDS_DB = "phishguard"
RDS_USER = "YOUR_DB_USER"
RDS_PASS = "YOUR_DB_PASSWORD"

# ------------------------------------------------------------
# Wazuh configuration
# ------------------------------------------------------------
WAZUH_API_URL = "https://YOUR_WAZUH_MANAGER_PRIVATE_IP:55000"
WAZUH_USER = "YOUR_WAZUH_USER"
WAZUH_PASSWORD = "YOUR_WAZUH_PASSWORD"
WAZUH_VERIFY_SSL = False  # True if you use valid TLS certs
LOCAL_WAZUH_LOG = "/var/ossec/logs/custom/phishguard.log"
WAZUH_AGENT_ID = "001"

# This is your embedded/dashboard link. Keep it as a placeholder here.
WAZUH_DASHBOARD_URL = "/wazuh/app/threat-hunting#/overview/?tab=general"

# ------------------------------------------------------------
# Gmail IMAP settings (inbox ingestion)
# ------------------------------------------------------------
EMAIL = "YOUR_GMAIL_ADDRESS"
EMAIL_PASSWORD = "YOUR_GMAIL_APP_PASSWORD"   # Gmail App Password (not your normal password)
IMAP_SERVER = "imap.gmail.com"

# ------------------------------------------------------------
# VirusTotal API Key
# ------------------------------------------------------------
VT_API_KEY = "YOUR_VT_API_KEY"

# ------------------------------------------------------------
# MISP Threat Intel
# ------------------------------------------------------------
MISP_URL = "https://YOUR_MISP_PUBLIC_OR_PRIVATE_IP"
MISP_API_KEY = "YOUR_MISP_API_KEY"
MISP_VERIFY_SSL = False  # True if valid TLS

# ------------------------------------------------------------
# Shuffle configuration
# ------------------------------------------------------------
SHUFFLE_BASE_URL = "https://YOUR_SHUFFLE_IP_OR_DOMAIN:3443"
SHUFFLE_API_KEY = "YOUR_SHUFFLE_API_KEY"
SHUFFLE_WORKFLOW_ID = "YOUR_SHUFFLE_WORKFLOW_ID"

# ------------------------------------------------------------
# ML Model
# ------------------------------------------------------------
MODEL_PATH = "app/model/model.pkl"

# ------------------------------------------------------------
# Flask app
# ------------------------------------------------------------
app = Flask(__name__, template_folder="templates", static_folder="static")

# For GitHub-safe code, keep a placeholder.
# On EC2, replace with a real stable secret key.
app.secret_key = "YOUR_FLASK_SECRET_KEY"

# ------------------------------------------------------------
# AWS clients
# ------------------------------------------------------------
s3_client = boto3.client("s3", region_name=S3_REGION)

# ------------------------------------------------------------
# In-memory dashboard storage
# ------------------------------------------------------------
LAST_INBOX_FETCH = 0
INBOX_FETCH_INTERVAL = 10
email_log_inbox = []
email_log_uploads = []

# ------------------------------------------------------------
# Load ML model
# ------------------------------------------------------------
try:
    model = joblib.load(MODEL_PATH)
    print(f"[ML] Model loaded: {MODEL_PATH}")
except Exception as e:
    model = None
    print("[ML ERROR] Failed to load model:", e)

# ============================================================
# AUTH HELPERS
# ============================================================
def login_required(f):
    """
    I used session-based login.
    If a user is not logged in, I redirect them to the login page.
    """
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return wrapper


def admin_required(f):
    """
    Admin-only routes (not used much in demo, but useful for future).
    """
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login", next=request.path))
        if session.get("role") != "admin":
            return abort(403)
        return f(*args, **kwargs)
    return wrapper


def remember_session_case(detection_id: int):
    """
    I store detection IDs created in THIS login session only.
    This is used to show the upload page results without exposing all history.
    """
    try:
        ids = session.get("session_case_ids", [])
        if not isinstance(ids, list):
            ids = []
        did = int(detection_id)
        if did not in ids:
            ids.append(did)
        session["session_case_ids"] = ids
        session.modified = True
    except Exception:
        pass

# ============================================================
# DB HELPERS
# ============================================================
def get_db_conn():
    """
    Connect to PostgreSQL (RDS).
    Secrets are placeholders in this GitHub-safe file.
    """
    return psycopg2.connect(
        host=RDS_HOST,
        port=RDS_PORT,
        dbname=RDS_DB,
        user=RDS_USER,
        password=RDS_PASS
    )


def _safe_exec(cur, sql):
    """
    Helper: runs CREATE/ALTER safely so the app doesn't crash if it already exists.
    """
    try:
        cur.execute(sql)
    except Exception as e:
        print("[DB MIGRATE WARN]", str(e)[:200])


def init_db():
    """
    I create the database tables if they don't exist.
    This lets the app be plug-and-play for demos.
    """
    try:
        conn = get_db_conn()
        cur = conn.cursor()

        _safe_exec(cur, """
        CREATE TABLE IF NOT EXISTS users (
            user_id SERIAL PRIMARY KEY,
            username VARCHAR(50) UNIQUE NOT NULL,
            email VARCHAR(255) UNIQUE,
            password_hash TEXT NOT NULL,
            role VARCHAR(20) DEFAULT 'user',
            created_at TIMESTAMPTZ DEFAULT NOW(),
            last_login TIMESTAMPTZ
        );
        """)

        _safe_exec(cur, """
        CREATE TABLE IF NOT EXISTS emails (
            email_id SERIAL PRIMARY KEY,
            user_id INTEGER,
            sender_address VARCHAR(255),
            subject TEXT,
            body_text TEXT,
            body_html TEXT,
            timestamp_received TIMESTAMPTZ NOT NULL,
            raw_eml_path VARCHAR(500) NOT NULL,
            internet_message_id TEXT,
            ingested_at TIMESTAMPTZ DEFAULT NOW()
        );
        """)

        _safe_exec(cur, "CREATE UNIQUE INDEX IF NOT EXISTS emails_msgid_uq ON emails(internet_message_id);")
        _safe_exec(cur, "CREATE INDEX IF NOT EXISTS emails_user_id_idx ON emails(user_id);")

        _safe_exec(cur, """
        CREATE TABLE IF NOT EXISTS detections (
            detection_id SERIAL PRIMARY KEY,
            email_id INTEGER NOT NULL UNIQUE REFERENCES emails(email_id) ON DELETE CASCADE,
            ml_verdict VARCHAR(50),
            ml_confidence NUMERIC(5,4),
            features_used JSONB,
            detected_at TIMESTAMPTZ DEFAULT NOW()
        );
        """)

        _safe_exec(cur, """
        CREATE TABLE IF NOT EXISTS threat_intel (
            threat_id SERIAL PRIMARY KEY,
            detection_id INTEGER UNIQUE REFERENCES detections(detection_id) ON DELETE CASCADE,
            url_verdict VARCHAR(50) NOT NULL,
            attachment_verdict VARCHAR(50),
            vt_report_id VARCHAR(255),
            misp_event_id INTEGER,
            enriched_at TIMESTAMPTZ DEFAULT NOW(),
            vt_score INTEGER,
            misp_hits INTEGER
        );
        """)

        _safe_exec(cur, """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM information_schema.table_constraints
                WHERE constraint_name = 'emails_user_id_fk'
            ) THEN
                ALTER TABLE emails
                    ADD CONSTRAINT emails_user_id_fk
                    FOREIGN KEY (user_id) REFERENCES users(user_id)
                    ON DELETE SET NULL;
            END IF;
        END$$;
        """)

        conn.commit()
        cur.close()
        conn.close()
        print("[DB] init/migrate done")
    except Exception as e:
        print("[DB INIT ERROR]", e)


def ensure_default_admin():
    """
    Creates a demo admin if missing.
    NOTE: Replace this for real deployments.
    """
    default_user = "admin"
    default_pass = "ChangeMe123!"
    try:
        conn = get_db_conn()
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM users WHERE username=%s", (default_user,))
        exists = cur.fetchone() is not None
        if not exists:
            pw_hash = generate_password_hash(default_pass)
            cur.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (%s,%s,%s)",
                (default_user, pw_hash, "admin")
            )
            conn.commit()
            print("[AUTH] Default admin created: admin / ChangeMe123!")
        cur.close()
        conn.close()
    except Exception as e:
        print("[AUTH] ensure_default_admin error:", e)


init_db()
ensure_default_admin()


def email_already_processed(message_id: str) -> bool:
    """
    Inbox safety: prevents re-processing the same email by Message-ID.
    """
    if not message_id:
        return False
    try:
        conn = get_db_conn()
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM emails WHERE internet_message_id = %s LIMIT 1", (message_id,))
        exists = cur.fetchone() is not None
        cur.close()
        conn.close()
        return exists
    except Exception as e:
        print("[DB CHECK ERROR]", e)
        return False

# ============================================================
# INTEGRATIONS
# ============================================================
def send_to_shuffle(payload):
    """
    I send the detection/enrichment payload to Shuffle to trigger SOAR automation.
    """
    try:
        url = f"{SHUFFLE_BASE_URL}/api/v1/workflows/{SHUFFLE_WORKFLOW_ID}/execute"
        headers = {
            "Authorization": f"Bearer {SHUFFLE_API_KEY}",
            "Content-Type": "application/json"
        }
        r = requests.post(url, headers=headers, json=payload, timeout=15, verify=False)
        print("[SHUFFLE] status:", r.status_code)
        return r.status_code in (200, 201)
    except Exception as e:
        print("[SHUFFLE ERROR]", e)
        return False


def should_skip_inbox_email(subject: str, sender: str) -> bool:
    """
    I skip my own alert emails to avoid loops.
    """
    s = (subject or "").lower()
    f = (sender or "").lower()
    if "phishguard alert" in s:
        return True
    if "shuffle" in f or "no-reply" in f:
        return True
    return False


def get_wazuh_token():
    """
    Authenticate to Wazuh API and return token.
    """
    url = f"{WAZUH_API_URL}/security/user/authenticate"
    try:
        r = requests.post(
            url,
            auth=HTTPBasicAuth(WAZUH_USER, WAZUH_PASSWORD),
            timeout=10,
            verify=WAZUH_VERIFY_SSL
        )
        data = r.json()
        return data.get("data", {}).get("token") or data.get("token")
    except Exception:
        return None


def write_local_wazuh_log(agent_id, message, extra=None):
    """
    Fallback method: if API fails, I still write JSON logs locally for Wazuh to ingest.
    """
    event = {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "agent": agent_id,
        "app": "phishguard",
        "message": message,
        "extra": extra or {}
    }
    try:
        os.makedirs(os.path.dirname(LOCAL_WAZUH_LOG), exist_ok=True)
        with open(LOCAL_WAZUH_LOG, "a") as f:
            f.write(json.dumps(event) + "\n")
        return True
    except Exception:
        return False


def send_phishguard_event(agent_id, message, extra=None):
    """
    Tries to send to Wazuh API. If it fails, writes to local log.
    """
    token = get_wazuh_token()
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    url = f"{WAZUH_API_URL}/api/v1/agents/{agent_id}/events"
    payload = {"event": {"app": "phishguard", "message": message, "extra": extra or {}}}

    try:
        if token:
            r = requests.post(url, headers=headers, json=payload, timeout=10, verify=WAZUH_VERIFY_SSL)
            if r.status_code in (200, 201):
                return True
    except Exception:
        pass

    return write_local_wazuh_log(agent_id, message, extra)

# ============================================================
# THREAT ENRICHMENT
# ============================================================
def extract_urls(text):
    """
    Simple URL extraction: in my demo I detect tokens starting with 'http'.
    """
    return [u for u in (text or "").split() if u.startswith("http")]


def enrich_with_virustotal(text):
    """
    Checks extracted URLs with VirusTotal (placeholder key in this file).
    """
    headers = {"x-apikey": VT_API_KEY}
    urls = extract_urls(text)
    results = []
    for url in urls:
        try:
            enc = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            r = requests.get(
                f"https://www.virustotal.com/api/v3/urls/{enc}",
                headers=headers,
                timeout=10
            )
            stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = int(stats.get("malicious", 0) or 0)
            results.append({"url": url, "score": malicious, "malicious": malicious > 0})
        except Exception as e:
            results.append({"url": url, "error": str(e)})
    return results


def summarize_vt_score(vt_results):
    scores = [r.get("score", 0) for r in (vt_results or []) if isinstance(r, dict) and "score" in r]
    return max(scores) if scores else 0


def query_misp_indicator(indicator):
    """
    Checks an indicator (URL) in MISP using the REST search API.
    """
    headers = {
        "Authorization": MISP_API_KEY,
        "Accept": "application/json",
        "Content-Type": "application/json"
    }
    payload = {"value": indicator, "returnFormat": "json"}

    try:
        r = requests.post(
            f"{MISP_URL}/attributes/restSearch",
            headers=headers,
            json=payload,
            timeout=10,
            verify=MISP_VERIFY_SSL
        )
        data = r.json()

        attrs = []
        if isinstance(data, dict) and "Attribute" in data:
            attrs = data.get("Attribute", [])
        elif isinstance(data, dict) and "response" in data:
            resp_obj = data.get("response")
            if isinstance(resp_obj, dict):
                attrs = resp_obj.get("Attribute", [])
            elif isinstance(resp_obj, list):
                for ev in resp_obj:
                    if isinstance(ev, dict):
                        attrs.extend(ev.get("Attribute", []) or [])

        return {"indicator": indicator, "found": len(attrs) > 0, "count": len(attrs)}
    except Exception as e:
        return {"indicator": indicator, "found": False, "error": str(e)}


def enrich_with_misp(text):
    urls = extract_urls(text)
    return [query_misp_indicator(u) for u in urls]


def summarize_misp_hits(misp_results):
    return sum(1 for r in (misp_results or []) if isinstance(r, dict) and r.get("found") is True)

# ============================================================
# S3 + DB STORAGE
# ============================================================
def presign_s3_key(s3_key: str, expires: int = 3600):
    """
    I generate a pre-signed URL so the dashboard can download raw emails safely.
    """
    if not s3_key:
        return None
    try:
        return s3_client.generate_presigned_url(
            "get_object",
            Params={"Bucket": S3_BUCKET, "Key": s3_key},
            ExpiresIn=expires
        )
    except Exception as e:
        print("[S3 PRESIGN ERROR]", e)
        return None


def store_eml_and_create_records(
    file_bytes,
    subject,
    sender,
    body,
    vt_results,
    misp_results,
    label,
    vt_score,
    misp_hits,
    internet_message_id=None,
    user_id=None
):
    """
    Core pipeline storage:
    - Save raw EML into S3 (for uploads)
    - Insert/update DB tables (emails, detections, threat_intel)
    """
    timestamp_key = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    rand = uuid.uuid4().hex[:8]
    subject_str = str(subject) if subject else "email"
    safe_name = subject_str.replace(" ", "_")[:50]
    s3_key = f"uploads/{timestamp_key}-{rand}-{safe_name}.eml"

    presigned = None

    try:
        if file_bytes and len(file_bytes) > 0:
            s3_client.put_object(Bucket=S3_BUCKET, Key=s3_key, Body=file_bytes)
        else:
            # Inbox emails have no raw bytes in my demo, so I save a placeholder path.
            s3_key = f"inbox/no-raw/{timestamp_key}-{rand}-{safe_name}.eml"

        if file_bytes and len(file_bytes) > 0:
            presigned = presign_s3_key(s3_key, expires=86400)
    except Exception as e:
        print("[S3 ERROR]", e)

    email_id = None
    detection_id = None

    try:
        conn = get_db_conn()
        cur = conn.cursor()
        received = datetime.now(timezone.utc)

        if internet_message_id:
            cur.execute("""
                INSERT INTO emails (
                    user_id, sender_address, subject, body_text, body_html,
                    timestamp_received, raw_eml_path, internet_message_id
                )
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (internet_message_id) DO UPDATE
                SET
                    user_id = COALESCE(EXCLUDED.user_id, emails.user_id),
                    sender_address = EXCLUDED.sender_address,
                    subject = EXCLUDED.subject,
                    body_text = EXCLUDED.body_text,
                    body_html = EXCLUDED.body_html,
                    timestamp_received = EXCLUDED.timestamp_received,
                    raw_eml_path = EXCLUDED.raw_eml_path,
                    ingested_at = NOW()
                RETURNING email_id;
            """, (user_id, sender, subject, body, None, received, s3_key, internet_message_id))
        else:
            cur.execute("""
                INSERT INTO emails (
                    user_id, sender_address, subject, body_text, body_html,
                    timestamp_received, raw_eml_path, internet_message_id
                )
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                RETURNING email_id;
            """, (user_id, sender, subject, body, None, received, s3_key, None))

        email_id = cur.fetchone()[0]

        verdict = "phishing" if int(label) == 1 else "benign"
        features = {
            "urls": extract_urls(body),
            "vt_results": vt_results,
            "misp_results": misp_results,
            "source": "gmail_inbox" if (not file_bytes or len(file_bytes) == 0) else "manual_upload",
        }

        cur.execute("""
            INSERT INTO detections (email_id, ml_verdict, ml_confidence, features_used)
            VALUES (%s,%s,%s,%s)
            ON CONFLICT (email_id) DO UPDATE
            SET
                ml_verdict = EXCLUDED.ml_verdict,
                ml_confidence = EXCLUDED.ml_confidence,
                features_used = EXCLUDED.features_used,
                detected_at = NOW()
            RETURNING detection_id;
        """, (email_id, verdict, 1.0, json.dumps(features)))
        detection_id = cur.fetchone()[0]

        url_verdict = "malicious" if int(vt_score) > 0 else "clean"

        cur.execute("""
            INSERT INTO threat_intel (detection_id, url_verdict, vt_score, misp_hits)
            VALUES (%s,%s,%s,%s)
            ON CONFLICT (detection_id) DO UPDATE
            SET
                url_verdict = EXCLUDED.url_verdict,
                vt_score = EXCLUDED.vt_score,
                misp_hits = EXCLUDED.misp_hits,
                enriched_at = NOW();
        """, (detection_id, url_verdict, int(vt_score), int(misp_hits)))

        conn.commit()
        cur.close()
        conn.close()

    except Exception as e:
        print("[DB ERROR]", e)
        traceback.print_exc()

    return {
        "email_id": email_id,
        "detection_id": detection_id,
        "s3_key": s3_key,
        "s3_presigned": presigned
    }


def build_shuffle_payload(source, subject, sender, body, label, vt_results, vt_score, misp_results, rec=None):
    """
    This payload is what I send to Shuffle and also to Wazuh events.
    """
    rec = rec or {}
    return {
        "source": source,
        "ml_label_raw": int(label),
        "ml_verdict": "phishing" if int(label) == 1 else "benign",
        "subject": subject,
        "sender": sender,
        "body": body,
        "vt_results": vt_results,
        "vt_score": int(vt_score),
        "url_verdict": "malicious" if int(vt_score) > 0 else "clean",
        "misp_results": misp_results,
        "email_id": rec.get("email_id"),
        "detection_id": rec.get("detection_id"),
        "s3_key": rec.get("s3_key"),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

# ============================================================
# INBOX INGESTION
# ============================================================
def fetch_unread_emails():
    """
    Reads UNSEEN emails from Gmail INBOX and Spam, then runs the same pipeline.
    """
    try:
        mail = imaplib.IMAP4_SSL(IMAP_SERVER)
        mail.login(EMAIL, EMAIL_PASSWORD)
        print("[INBOX] Logged in OK")

        for folder in ["INBOX", "[Gmail]/Spam"]:
            try:
                status, _ = mail.select(folder)
                if status != "OK":
                    continue
            except Exception:
                continue

            typ, data = mail.search(None, "UNSEEN")
            ids = data[0].split() if typ == "OK" and data and data[0] else []

            for eid in ids:
                try:
                    _, msg_data = mail.fetch(eid, "(BODY.PEEK[])")
                    msg = email.message_from_bytes(msg_data[0][1])

                    subject = str(make_header(decode_header(msg.get("subject", "")))) or "(no subject)"
                    sender = msg.get("from") or "(unknown)"

                    if should_skip_inbox_email(subject, sender):
                        continue

                    message_id = (msg.get("message-id") or "").strip()
                    if message_id and email_already_processed(message_id):
                        continue

                    body = ""
                    if msg.is_multipart():
                        for part in msg.walk():
                            if part.get_content_type() == "text/plain":
                                body = part.get_payload(decode=True).decode(errors="ignore")
                                break
                    else:
                        body = msg.get_payload(decode=True).decode(errors="ignore")

                    if model is None:
                        label = 0
                    else:
                        label = model.predict([body])[0]

                    vt = enrich_with_virustotal(body)
                    vt_score = summarize_vt_score(vt)

                    try:
                        misp = enrich_with_misp(body)
                    except Exception:
                        misp = []
                    misp_hits = summarize_misp_hits(misp)

                    rec = store_eml_and_create_records(
                        file_bytes=b"",
                        subject=subject,
                        sender=sender,
                        body=body,
                        vt_results=vt,
                        misp_results=misp,
                        label=label,
                        vt_score=vt_score,
                        misp_hits=misp_hits,
                        internet_message_id=message_id if message_id else None,
                        user_id=None
                    )

                    email_log_inbox.append({
                        "subject": subject,
                        "label": int(label),
                        "virustotal": vt,
                        "misp": misp,
                        "timestamp": datetime.now(pytz.timezone("Asia/Bahrain")).strftime("%Y-%m-%d %H:%M:%S"),
                        "detection_id": rec.get("detection_id")
                    })

                    shuffle_payload = build_shuffle_payload(
                        "gmail_inbox", subject, sender, body, label, vt, vt_score, misp, rec=rec
                    )
                    send_to_shuffle(shuffle_payload)

                    verdict_text = "PHISHING" if int(label) == 1 else "BENIGN"
                    send_phishguard_event(
                        WAZUH_AGENT_ID,
                        f"PhishGuard detected {verdict_text} (Inbox): {subject}",
                        shuffle_payload
                    )

                except Exception as e:
                    print("[INBOX ERROR]", e)
                    traceback.print_exc()

        mail.logout()

    except Exception as e:
        print("[INBOX IMAP ERROR]", e)
        traceback.print_exc()

# ============================================================
# HISTORY / CASE QUERIES
# ============================================================
def db_get_user_cases(user_id: int, limit: int = 200):
    conn = get_db_conn()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("""
        SELECT
            d.detection_id,
            e.email_id,
            e.subject,
            e.sender_address,
            d.ml_verdict,
            t.vt_score,
            t.misp_hits,
            e.raw_eml_path,
            d.detected_at
        FROM detections d
        JOIN emails e ON e.email_id = d.email_id
        LEFT JOIN threat_intel t ON t.detection_id = d.detection_id
        WHERE e.user_id = %s
        ORDER BY d.detected_at DESC
        LIMIT %s;
    """, (user_id, limit))
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return rows


def db_get_cases_by_detection_ids(detection_ids):
    if not detection_ids:
        return []
    conn = get_db_conn()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("""
        SELECT
            d.detection_id,
            e.email_id,
            e.subject,
            e.sender_address,
            d.ml_verdict,
            t.vt_score,
            t.misp_hits,
            e.raw_eml_path,
            d.detected_at
        FROM detections d
        JOIN emails e ON e.email_id = d.email_id
        LEFT JOIN threat_intel t ON t.detection_id = d.detection_id
        WHERE d.detection_id = ANY(%s::int[])
        ORDER BY d.detected_at DESC;
    """, (detection_ids,))
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return rows


def db_get_case_details(detection_id: int):
    conn = get_db_conn()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("""
        SELECT
            d.detection_id,
            d.ml_verdict,
            d.ml_confidence,
            d.features_used,
            d.detected_at,

            e.email_id,
            e.user_id,
            e.sender_address,
            e.subject,
            e.body_text,
            e.raw_eml_path,
            e.timestamp_received,

            t.url_verdict,
            t.vt_score,
            t.misp_hits,
            t.enriched_at
        FROM detections d
        JOIN emails e ON e.email_id = d.email_id
        LEFT JOIN threat_intel t ON t.detection_id = d.detection_id
        WHERE d.detection_id = %s
        LIMIT 1;
    """, (detection_id,))
    row = cur.fetchone()
    cur.close()
    conn.close()
    return row

# ============================================================
# ROUTES
# ============================================================
@app.route("/")
def landing():
    return render_template("landing.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    username = (request.form.get("username") or "").strip()
    email_addr = (request.form.get("email") or "").strip().lower()
    password = request.form.get("password") or ""
    confirm = request.form.get("confirm") or ""

    if not username or not email_addr or not password:
        return render_template("register.html", error="All fields are required.")
    if password != confirm:
        return render_template("register.html", error="Passwords do not match.")
    if len(password) < 8:
        return render_template("register.html", error="Password must be at least 8 characters.")

    pw_hash = generate_password_hash(password)

    try:
        conn = get_db_conn()
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM users WHERE username=%s OR email=%s", (username, email_addr))
        if cur.fetchone():
            cur.close()
            conn.close()
            return render_template("register.html", error="Username or email already exists.")

        cur.execute(
            "INSERT INTO users (username, email, password_hash, role) VALUES (%s,%s,%s,%s)",
            (username, email_addr, pw_hash, "user")
        )
        conn.commit()
        cur.close()
        conn.close()
        return redirect(url_for("login"))
    except Exception as e:
        print("[REGISTER ERROR]", e)
        return render_template("register.html", error="Server error. Check logs.")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""

    try:
        conn = get_db_conn()
        cur = conn.cursor()
        cur.execute("""
            SELECT user_id, username, password_hash, role
            FROM users
            WHERE username=%s OR email=%s
        """, (username, username))
        row = cur.fetchone()
        cur.close()
        conn.close()

        if not row:
            return render_template("login.html", error="Invalid username/email or password.")

        user_id, db_user, pw_hash, role = row
        if not check_password_hash(pw_hash, password):
            return render_template("login.html", error="Invalid username/email or password.")

        session.clear()
        session["user_id"] = int(user_id)
        session["user"] = db_user
        session["role"] = role
        session["session_case_ids"] = []
        session.modified = True

        try:
            conn = get_db_conn()
            cur = conn.cursor()
            cur.execute("UPDATE users SET last_login = NOW() WHERE user_id=%s", (user_id,))
            conn.commit()
            cur.close()
            conn.close()
        except Exception:
            pass

        nxt = request.args.get("next")
        return redirect(nxt or url_for("upload_dashboard"))

    except Exception as e:
        print("[LOGIN ERROR]", e)
        return render_template("login.html", error="Server error. Check logs.")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("landing"))


@app.route("/upload")
@login_required
def upload_dashboard():
    return render_template(
        "dashboard.html",
        page_title="PhishGuard – Manual Upload",
        show_upload_form=True,
        data_endpoint=url_for("upload_data"),
        wazuh_endpoint=url_for("wazuh_alerts_data"),
        wazuh_iframe_url=WAZUH_DASHBOARD_URL
    )


@app.route("/inbox")
@login_required
def inbox_dashboard():
    return render_template(
        "dashboard.html",
        page_title="PhishGuard – Gmail Inbox Monitor",
        show_upload_form=False,
        data_endpoint=url_for("inbox_data"),
        wazuh_endpoint=url_for("wazuh_alerts_data"),
        wazuh_iframe_url=WAZUH_DASHBOARD_URL
    )


@app.route("/history")
@login_required
def history():
    rows = db_get_user_cases(session["user_id"], limit=200)
    return render_template("history.html", rows=rows)


@app.route("/case/<int:detection_id>")
@login_required
def case_details(detection_id):
    row = db_get_case_details(detection_id)
    if not row:
        return abort(404)

    if session.get("role") != "admin":
        owner_id = row.get("user_id")
        is_owner = (owner_id == session.get("user_id"))

        is_inbox_case = False
        try:
            features = row.get("features_used") or {}
            if isinstance(features, str):
                features = json.loads(features)
            if isinstance(features, dict):
                src = features.get("source")
                if src in ("gmail_inbox", "inbox"):
                    is_inbox_case = True
        except Exception:
            is_inbox_case = False

        if not (is_owner or is_inbox_case):
            return abort(403)

    download_url = presign_s3_key(row.get("raw_eml_path"), expires=3600)

    urls = []
    try:
        features = row.get("features_used") or {}
        if isinstance(features, str):
            features = json.loads(features)
        urls = (features.get("urls") or []) if isinstance(features, dict) else []
    except Exception:
        urls = extract_urls(row.get("body_text") or "")

    return render_template("case_details.html", row=row, download_url=download_url, urls=urls)


# ------------------------------------------------------------
# Manual Upload Endpoint
# ------------------------------------------------------------
@app.route("/upload_eml", methods=["POST"])
@login_required
def upload_eml():
    file = request.files.get("eml_file")
    if not file:
        return "No file uploaded", 400

    file_bytes = file.read()
    msg = email.message_from_bytes(file_bytes)

    subject = str(make_header(decode_header(msg.get("subject", "")))) or "(no subject)"
    sender = msg.get("from") or "(unknown)"

    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                body = part.get_payload(decode=True).decode(errors="ignore")
                break
    else:
        body = msg.get_payload(decode=True).decode(errors="ignore")

    if model is None:
        label = 0
    else:
        label = model.predict([body])[0]

    vt = enrich_with_virustotal(body)
    vt_score = summarize_vt_score(vt)

    try:
        misp = enrich_with_misp(body)
    except Exception as e:
        print("[MISP ERROR]", e)
        misp = []
    misp_hits = summarize_misp_hits(misp)

    message_id = (msg.get("message-id") or "").strip() or None

    rec = store_eml_and_create_records(
        file_bytes=file_bytes,
        subject=subject,
        sender=sender,
        body=body,
        vt_results=vt,
        misp_results=misp,
        label=label,
        vt_score=vt_score,
        misp_hits=misp_hits,
        internet_message_id=message_id,
        user_id=session.get("user_id")
    )

    if rec.get("detection_id"):
        remember_session_case(rec["detection_id"])

    try:
        shuffle_payload = build_shuffle_payload(
            "manual_upload", subject, sender, body, label, vt, vt_score, misp, rec=rec
        )
        send_to_shuffle(shuffle_payload)

        verdict_text = "PHISHING" if int(label) == 1 else "BENIGN"
        send_phishguard_event(
            WAZUH_AGENT_ID,
            f"PhishGuard detected {verdict_text} (Upload): {subject}",
            shuffle_payload
        )
    except Exception as e:
        print("[AUTOMATION ERROR]", e)

    email_log_uploads.append({
        "subject": subject,
        "label": int(label),
        "virustotal": vt,
        "misp": misp,
        "s3_path": rec.get("s3_presigned"),
        "filename": file.filename,
        "timestamp": datetime.now(pytz.timezone("Asia/Bahrain")).strftime("%Y-%m-%d %H:%M:%S"),
        "detection_id": rec.get("detection_id")
    })

    return redirect(url_for("upload_dashboard"))


@app.route("/upload_data")
@login_required
def upload_data():
    """
    Returns JSON for the upload dashboard table.
    I show ONLY the detections created in the current login session.
    """
    try:
        session_ids = session.get("session_case_ids", [])
        rows = db_get_cases_by_detection_ids(session_ids)

        emails = []
        tz_bh = pytz.timezone("Asia/Bahrain")

        for r in rows:
            detection_id = int(r.get("detection_id"))
            vt_score = int(r.get("vt_score") or 0)
            misp_hits = int(r.get("misp_hits") or 0)

            urls = []
            try:
                case_row = db_get_case_details(detection_id)
                features = case_row.get("features_used") if case_row else None
                if isinstance(features, str):
                    features = json.loads(features)
                if isinstance(features, dict):
                    urls = features.get("urls") or []
            except Exception:
                urls = []

            if urls:
                vt_list = [{"url": u, "score": vt_score, "malicious": (vt_score > 0)} for u in urls]
                misp_list = [{"indicator": u, "found": (misp_hits > 0), "count": misp_hits} for u in urls]
            else:
                vt_list = [{"url": "", "score": vt_score, "malicious": (vt_score > 0)}]
                misp_list = [{"indicator": "", "found": (misp_hits > 0), "count": misp_hits}]

            ts = r.get("detected_at")
            ts_str = ts.astimezone(tz_bh).strftime("%Y-%m-%d %H:%M:%S") if ts else None

            emails.append({
                "subject": r.get("subject"),
                "label": 1 if (r.get("ml_verdict") == "phishing") else 0,
                "virustotal": vt_list,
                "misp": misp_list,
                "s3_path": presign_s3_key(r.get("raw_eml_path"), expires=3600),
                "timestamp": ts_str,
                "detection_id": detection_id
            })

        return jsonify({"emails": emails, "last_updated": emails[0]["timestamp"] if emails else None})

    except Exception as e:
        print("[UPLOAD_DATA ERROR]", e)
        return jsonify({"emails": [], "last_updated": None})


@app.route("/inbox_data")
@login_required
def inbox_data():
    """
    Fetches inbox emails on a small timer to avoid hammering Gmail.
    """
    global LAST_INBOX_FETCH
    now = time.time()

    if now - LAST_INBOX_FETCH > INBOX_FETCH_INTERVAL:
        fetch_unread_emails()
        LAST_INBOX_FETCH = now

    return jsonify({
        "emails": email_log_inbox,
        "last_updated": email_log_inbox[-1]["timestamp"] if email_log_inbox else None
    })


@app.route("/wazuh_alerts_data")
def wazuh_alerts_data():
    """
    In this demo UI, Wazuh iframe is embedded, so I return a placeholder endpoint.
    """
    return jsonify({"status": "ok", "alerts": []})


@app.route("/about")
def about():
    return render_template("about.html", page_title="PhishGuard – About Us")


if __name__ == "__main__":
    # Local dev mode. In production I run it using gunicorn + systemd.
    app.run(debug=True, host="0.0.0.0", port=5001)
