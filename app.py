"""
MediSphere - Production-grade Flask backend
Run: python app.py  |  gunicorn app:app
"""
from __future__ import annotations

import io
import os
import re
import json
import time
import logging
import secrets
import datetime as dt
from collections import defaultdict
from functools import wraps
from typing import Any, Optional

import bcrypt
import jwt
import qrcode
from flask import Flask, request, jsonify, send_file, send_from_directory, g
from flask_cors import CORS
from supabase import create_client, Client
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.lib.utils import ImageReader
from dotenv import load_dotenv

load_dotenv()

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
log = logging.getLogger("medisphere")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "")
JWT_SECRET = os.getenv("JWT_SECRET", secrets.token_urlsafe(64))
JWT_ALG = "HS256"
JWT_EXP_HRS = 24
PORT = int(os.getenv("PORT", "5000"))

CORS_ALLOWED_ORIGINS = [
    o.strip() for o in os.getenv("CORS_ALLOWED_ORIGINS", "*").split(",") if o.strip()
]

AUTH_RATE_LIMIT = int(os.getenv("AUTH_RATE_LIMIT", "10"))
RESET_RATE_LIMIT = int(os.getenv("RESET_RATE_LIMIT", "5"))
CHECK_RATE_LIMIT = int(os.getenv("CHECK_RATE_LIMIT", "20"))

# Resolve frontend dir
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
_CANDIDATE_FRONTEND_DIRS = [
    os.path.join(BASE_DIR, "..", "frontend"),
    os.path.join(BASE_DIR, "frontend"),
    os.path.join(BASE_DIR, "..", "..", "frontend"),
    os.path.join(BASE_DIR, "static"),
    BASE_DIR,
]
FRONTEND_DIR = next(
    (os.path.abspath(p) for p in _CANDIDATE_FRONTEND_DIRS
     if os.path.isdir(p) and os.path.isfile(os.path.join(p, "index.html"))),
    None,
)
log.info(f"FRONTEND_DIR: {FRONTEND_DIR}")

supabase: Optional[Client] = create_client(SUPABASE_URL, SUPABASE_KEY) if SUPABASE_URL else None

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
app = Flask(
    __name__,
    static_folder=FRONTEND_DIR if FRONTEND_DIR else None,
    static_url_path="",
)
CORS(app, origins=CORS_ALLOWED_ORIGINS or ["*"], supports_credentials=False)

# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------
_rate_buckets: dict[str, list[float]] = defaultdict(list)


def _client_ip() -> str:
    return (
        request.headers.get("x-forwarded-for", "").split(",")[0].strip()
        or request.remote_addr
        or "anon"
    )


def rate_limit(bucket_prefix: str, limit: int, window: int = 60):
    def deco(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            key = f"{bucket_prefix}:{_client_ip()}"
            now = time.time()
            window_start = now - window
            bucket = _rate_buckets[key]
            bucket[:] = [t for t in bucket if t > window_start]
            if len(bucket) >= limit:
                retry = int(bucket[0] + window - now) + 1
                resp = jsonify({"success": False, "error": "Too many attempts. Try again soon."})
                resp.status_code = 429
                resp.headers["Retry-After"] = str(max(1, retry))
                return resp
            bucket.append(now)
            return fn(*args, **kwargs)
        return wrapper
    return deco


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
PHONE_RE = re.compile(r"^\+?\d{10,15}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
CODE_RE = re.compile(r"^(PAT|DOC|ADM)\d{6}$")


def _ok(data: Any = None, **extra) -> Any:
    payload = {"success": True}
    if data is not None:
        payload["data"] = data
    payload.update(extra)
    return jsonify(payload)


def _err(message: str, status: int = 400) -> Any:
    resp = jsonify({"success": False, "error": message})
    resp.status_code = status
    return resp


def _normalize_phone(phone: str) -> str:
    p = re.sub(r"[\s\-()]", "", phone or "")
    if not p.startswith("+") and len(p) == 10:
        p = "+91" + p
    return p


def hash_password(pw: str) -> str:
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt(rounds=12)).decode()


def verify_password(pw: str, pw_hash: str) -> bool:
    try:
        return bcrypt.checkpw(pw.encode(), pw_hash.encode())
    except Exception:
        return False


def make_token(user: dict) -> str:
    now = dt.datetime.now(dt.timezone.utc)
    payload = {
        "uid": user["id"],
        "code": user["user_code"],
        "role": user["role"],
        "iat": int(now.timestamp()),
        "exp": int((now + dt.timedelta(hours=JWT_EXP_HRS)).timestamp()),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


def auth_required(roles: Optional[list[str]] = None):
    def deco(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            auth_header = request.headers.get("Authorization", "")
            if not auth_header.lower().startswith("bearer "):
                return _err("Authentication required.", 401)
            token = auth_header.split(" ", 1)[1].strip()
            try:
                data = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
            except jwt.ExpiredSignatureError:
                return _err("Session expired.", 401)
            except jwt.InvalidTokenError:
                return _err("Invalid session.", 401)
            if roles and data.get("role") not in roles:
                return _err("Forbidden.", 403)
            g.user = data
            return fn(*args, **kwargs)
        return wrapper
    return deco


def next_user_code(role: str) -> str:
    prefix = {"patient": "PAT", "doctor": "DOC", "admin": "ADM"}[role]
    res = supabase.table("users").select("user_code").eq("role", role).execute()
    nums = [
        int(r["user_code"][3:])
        for r in (res.data or [])
        if r["user_code"].startswith(prefix) and r["user_code"][3:].isdigit()
    ]
    nxt = max(nums) + 1 if nums else 100001
    return f"{prefix}{nxt}"


def log_audit(user_id: str, action: str, details: str = "") -> None:
    try:
        supabase.table("audit_logs").insert({
            "user_id": user_id, "action": action, "details": details
        }).execute()
    except Exception:
        pass


def _find_user(identifier: str, role: Optional[str] = None) -> Optional[dict]:
    """Look up a user by user_code, email, or phone."""
    identifier = identifier.strip()
    q = supabase.table("users").select("*")
    if CODE_RE.match(identifier.upper()):
        q = q.eq("user_code", identifier.upper())
    elif EMAIL_RE.match(identifier):
        q = q.eq("email", identifier.lower())
    elif PHONE_RE.match(_normalize_phone(identifier)):
        q = q.eq("phone", _normalize_phone(identifier))
    else:
        # fallback OR query
        q = q.or_(f"user_code.eq.{identifier},email.eq.{identifier},phone.eq.{identifier}")
    if role:
        q = q.eq("role", role)
    res = q.execute()
    return res.data[0] if res.data else None


# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------
@app.errorhandler(404)
def not_found(_):
    if request.path.startswith("/api/"):
        return _err("Not found.", 404)
    if FRONTEND_DIR and os.path.isfile(os.path.join(FRONTEND_DIR, "index.html")):
        return send_from_directory(FRONTEND_DIR, "index.html")
    return _err("Not found.", 404)


@app.errorhandler(Exception)
def unhandled(e):
    log.exception("Unhandled: %s", e)
    return _err("Internal server error.", 500)


# ---------------------------------------------------------------------------
# Static frontend
# ---------------------------------------------------------------------------
@app.route("/")
def root():
    if FRONTEND_DIR and os.path.isfile(os.path.join(FRONTEND_DIR, "index.html")):
        return send_from_directory(FRONTEND_DIR, "index.html")
    return jsonify({
        "service": "MediSphere API",
        "status": "running",
        "frontend_dir": FRONTEND_DIR,
        "time": dt.datetime.now(dt.timezone.utc).isoformat(),
    })


@app.route("/<path:path>")
def static_proxy(path):
    if path.startswith("api/"):
        return _err("Not found.", 404)
    if FRONTEND_DIR:
        full = os.path.join(FRONTEND_DIR, path)
        if os.path.isfile(full):
            return send_from_directory(FRONTEND_DIR, path)
        index_path = os.path.join(FRONTEND_DIR, "index.html")
        if os.path.isfile(index_path):
            return send_from_directory(FRONTEND_DIR, "index.html")
    return _err("Not found.", 404)


@app.get("/health")
@app.get("/api/health")
def health():
    return _ok({
        "status": "ok",
        "frontend_loaded": FRONTEND_DIR is not None,
        "supabase_configured": supabase is not None,
        "time": dt.datetime.now(dt.timezone.utc).isoformat(),
    })


# ---------------------------------------------------------------------------
# AUTH
# ---------------------------------------------------------------------------
@app.post("/api/auth/check-availability")
@rate_limit("check", CHECK_RATE_LIMIT)
def check_availability():
    """Tell the client whether email/phone/code is taken."""
    d = request.get_json(silent=True) or {}
    out = {}

    email = (d.get("email") or "").strip().lower()
    phone = _normalize_phone(d.get("phone") or "")
    code = (d.get("user_code") or "").strip().upper()
    role = d.get("role")

    if email:
        if not EMAIL_RE.match(email):
            return _err("Invalid email.", 400)
        r = supabase.table("users").select("id").eq("email", email).execute()
        out["email"] = "taken" if r.data else "available"

    if phone:
        if not PHONE_RE.match(phone):
            return _err("Invalid phone number.", 400)
        r = supabase.table("users").select("id").eq("phone", phone).execute()
        out["phone"] = "taken" if r.data else "available"

    if code:
        q = supabase.table("users").select("id,role").eq("user_code", code)
        if role:
            q = q.eq("role", role)
        r = q.execute()
        out["user_code"] = "taken" if r.data else "available"

    return _ok(out)


@app.post("/api/auth/check-identifier")
@rate_limit("check", CHECK_RATE_LIMIT)
def check_identifier():
    """Live check: does an account exist for this identifier (+ role)?"""
    d = request.get_json(silent=True) or {}
    identifier = (d.get("identifier") or "").strip()
    role = d.get("role")
    if not identifier:
        return _err("Identifier required.", 400)
    user = _find_user(identifier, role)
    return _ok({"exists": bool(user)})


@app.post("/api/auth/register")
@rate_limit("auth", AUTH_RATE_LIMIT)
def register():
    d = request.get_json(silent=True) or {}
    required = ["full_name", "email", "phone", "password", "role"]
    for k in required:
        if not d.get(k):
            return _err(f"{k.replace('_', ' ').title()} is required.", 400)

    role = d["role"].lower()
    if role not in ("patient", "doctor", "admin"):
        return _err("Invalid role.", 400)

    email = d["email"].strip().lower()
    if not EMAIL_RE.match(email):
        return _err("Invalid email.", 400)

    phone = _normalize_phone(d["phone"])
    if not PHONE_RE.match(phone):
        return _err("Invalid phone number.", 400)

    password = d["password"]
    if len(password) < 6:
        return _err("Password must be at least 6 characters.", 400)

    full_name = d["full_name"].strip()
    if not full_name:
        return _err("Name required.", 400)

    # uniqueness check
    exists = supabase.table("users").select("id,email,phone").or_(
        f"email.eq.{email},phone.eq.{phone}"
    ).execute()
    if exists.data:
        conflict = exists.data[0]
        if conflict.get("email") == email:
            return _err("An account with this email already exists.", 409)
        return _err("An account with this phone already exists.", 409)

    code = next_user_code(role)
    user_row = {
        "user_code": code,
        "role": role,
        "full_name": full_name,
        "email": email,
        "phone": phone,
        "password_hash": hash_password(password),
        "gender": d.get("gender"),
        "dob": d.get("dob"),
    }
    inserted = supabase.table("users").insert(user_row).execute()
    if not inserted.data:
        return _err("Could not create account.", 500)
    user = inserted.data[0]

    # role-specific profile row
    try:
        if role == "patient":
            supabase.table("patients").insert({"user_id": user["id"]}).execute()
        elif role == "doctor":
            supabase.table("doctors").insert({
                "user_id": user["id"],
                "specialization": d.get("specialization", "General"),
                "license_number": d.get("license_number", f"LIC-{code}"),
                "hospital_name": d.get("hospital_name", "MediSphere Hospital"),
            }).execute()
        elif role == "admin":
            supabase.table("admins").insert({"user_id": user["id"]}).execute()
    except Exception as e:
        log.warning("Profile row failed for %s: %s", code, e)

    log_audit(user["id"], "register", f"{role} registered")
    safe_user = {k: v for k, v in user.items() if k != "password_hash"}
    return _ok({"token": make_token(user), "user": safe_user})


@app.post("/api/auth/login")
@rate_limit("auth", AUTH_RATE_LIMIT)
def login():
    d = request.get_json(silent=True) or {}
    identifier = (d.get("identifier") or "").strip()
    password = d.get("password") or ""
    role = d.get("role")

    if not identifier or not password:
        return _err("Identifier and password required.", 400)

    user = _find_user(identifier, role)
    if not user:
        return _err("No account found. Please sign up first.", 404)

    if not verify_password(password, user["password_hash"]):
        return _err("Incorrect password.", 401)

    if role and user["role"] != role:
        return _err(f"This account is not a {role} account.", 403)

    try:
        supabase.table("users").update({
            "last_login_at": dt.datetime.now(dt.timezone.utc).isoformat()
        }).eq("id", user["id"]).execute()
    except Exception:
        pass

    log_audit(user["id"], "login")
    safe_user = {k: v for k, v in user.items() if k != "password_hash"}
    return _ok({"token": make_token(user), "user": safe_user})


@app.get("/api/auth/me")
@auth_required()
def me():
    res = supabase.table("users").select("*").eq("id", g.user["uid"]).execute()
    if not res.data:
        return _err("User not found.", 404)
    user = res.data[0]
    user.pop("password_hash", None)

    profile = {}
    if user["role"] == "patient":
        p = supabase.table("patients").select("*").eq("user_id", user["id"]).execute()
        profile = p.data[0] if p.data else {}
    elif user["role"] == "doctor":
        p = supabase.table("doctors").select("*").eq("user_id", user["id"]).execute()
        profile = p.data[0] if p.data else {}
    elif user["role"] == "admin":
        p = supabase.table("admins").select("*").eq("user_id", user["id"]).execute()
        profile = p.data[0] if p.data else {}

    return _ok({"user": user, "profile": profile})


@app.post("/api/auth/reset-password")
@rate_limit("reset", RESET_RATE_LIMIT)
def reset_password():
    """
    No-verification password reset.
    Requires user_code + phone match (acts as light verification),
    then sets new password directly.
    """
    d = request.get_json(silent=True) or {}
    user_code = (d.get("user_code") or "").strip().upper()
    phone = _normalize_phone(d.get("phone") or "")
    new_password = d.get("new_password") or ""
    confirm = d.get("confirm_password") or ""

    if not user_code or not phone:
        return _err("User ID and phone required.", 400)
    if not CODE_RE.match(user_code):
        return _err("Invalid user ID format.", 400)
    if not PHONE_RE.match(phone):
        return _err("Invalid phone number.", 400)
    if len(new_password) < 6:
        return _err("Password must be at least 6 characters.", 400)
    if new_password != confirm:
        return _err("Passwords do not match.", 400)

    res = supabase.table("users").select("id,user_code,phone").eq(
        "user_code", user_code
    ).eq("phone", phone).execute()
    if not res.data:
        return _err("No matching account found.", 404)

    user_id = res.data[0]["id"]
    supabase.table("users").update({
        "password_hash": hash_password(new_password)
    }).eq("id", user_id).execute()
    log_audit(user_id, "password_reset")
    return _ok({"reset": True})


@app.post("/api/auth/logout")
@auth_required()
def logout():
    log_audit(g.user["uid"], "logout")
    return _ok({"ok": True})


# ---------------------------------------------------------------------------
# PATIENTS / DOCTORS
# ---------------------------------------------------------------------------
@app.get("/api/patients")
@auth_required(roles=["doctor", "admin"])
def list_patients():
    users = supabase.table("users").select("*").eq("role", "patient").execute().data or []
    out = []
    for u in users:
        u.pop("password_hash", None)
        p = supabase.table("patients").select("*").eq("user_id", u["id"]).execute().data
        u["profile"] = p[0] if p else {}
        out.append(u)
    return _ok(out)


@app.get("/api/doctors")
@auth_required()
def list_doctors():
    users = supabase.table("users").select("*").eq("role", "doctor").execute().data or []
    out = []
    for u in users:
        u.pop("password_hash", None)
        p = supabase.table("doctors").select("*").eq("user_id", u["id"]).execute().data
        u["profile"] = p[0] if p else {}
        out.append(u)
    return _ok(out)


@app.put("/api/profile")
@auth_required()
def update_profile():
    d = request.get_json(silent=True) or {}
    uid = g.user["uid"]
    role = g.user["role"]
    user_fields = {k: d[k] for k in ("full_name", "phone", "gender", "dob", "photo_url") if k in d}
    if "phone" in user_fields:
        user_fields["phone"] = _normalize_phone(user_fields["phone"])
        if not PHONE_RE.match(user_fields["phone"]):
            return _err("Invalid phone.", 400)
    if user_fields:
        supabase.table("users").update(user_fields).eq("id", uid).execute()

    profile_fields = d.get("profile") or {}
    if profile_fields and role in ("patient", "doctor"):
        table = "patients" if role == "patient" else "doctors"
        supabase.table(table).update(profile_fields).eq("user_id", uid).execute()
    return _ok({"ok": True})


# ---------------------------------------------------------------------------
# APPOINTMENTS
# ---------------------------------------------------------------------------
@app.post("/api/appointments")
@auth_required(roles=["patient"])
def create_appointment():
    d = request.get_json(silent=True) or {}
    if not all(d.get(k) for k in ("doctor_id", "appointment_date", "appointment_time")):
        return _err("doctor_id, date, and time required.", 400)
    row = {
        "patient_id": g.user["uid"],
        "doctor_id": d["doctor_id"],
        "appointment_date": d["appointment_date"],
        "appointment_time": d["appointment_time"],
        "reason": d.get("reason"),
    }
    r = supabase.table("appointments").insert(row).execute()
    supabase.table("notifications").insert({
        "user_id": d["doctor_id"],
        "title": "New Appointment",
        "message": f"Appointment booked on {d['appointment_date']} at {d['appointment_time']}",
        "type": "appointment",
    }).execute()
    return _ok(r.data[0] if r.data else {})


@app.get("/api/appointments")
@auth_required()
def list_appointments():
    uid = g.user["uid"]
    role = g.user["role"]
    if role == "patient":
        r = supabase.table("appointments").select("*").eq("patient_id", uid).order("appointment_date", desc=True).execute()
    elif role == "doctor":
        r = supabase.table("appointments").select("*").eq("doctor_id", uid).order("appointment_date", desc=True).execute()
    else:
        r = supabase.table("appointments").select("*").order("appointment_date", desc=True).execute()
    rows = r.data or []
    for row in rows:
        for key in ("patient_id", "doctor_id"):
            u = supabase.table("users").select("user_code,full_name").eq("id", row[key]).execute().data
            if u:
                row[key.replace("_id", "_name")] = u[0]["full_name"]
                row[key.replace("_id", "_code")] = u[0]["user_code"]
    return _ok(rows)


@app.put("/api/appointments/<aid>")
@auth_required()
def update_appointment(aid):
    d = request.get_json(silent=True) or {}
    allowed = {k: d[k] for k in ("appointment_date", "appointment_time", "status", "notes") if k in d}
    supabase.table("appointments").update(allowed).eq("id", aid).execute()
    return _ok({"ok": True})


@app.delete("/api/appointments/<aid>")
@auth_required()
def cancel_appointment(aid):
    supabase.table("appointments").update({"status": "cancelled"}).eq("id", aid).execute()
    return _ok({"ok": True})


# ---------------------------------------------------------------------------
# CONSULTATIONS
# ---------------------------------------------------------------------------
@app.post("/api/consultations")
@auth_required(roles=["doctor"])
def create_consultation():
    d = request.get_json(silent=True) or {}
    row = {
        "appointment_id": d.get("appointment_id"),
        "patient_id": d.get("patient_id"),
        "doctor_id": g.user["uid"],
        "diagnosis": d.get("diagnosis"),
        "treatment": d.get("treatment"),
        "notes": d.get("notes"),
    }
    r = supabase.table("consultations").insert(row).execute()
    return _ok(r.data[0] if r.data else {})


@app.get("/api/consultations")
@auth_required()
def list_consultations():
    uid = g.user["uid"]
    role = g.user["role"]
    field = "patient_id" if role == "patient" else "doctor_id" if role == "doctor" else None
    q = supabase.table("consultations").select("*")
    if field:
        q = q.eq(field, uid)
    return _ok(q.order("created_at", desc=True).execute().data or [])


# ---------------------------------------------------------------------------
# PRESCRIPTIONS
# ---------------------------------------------------------------------------
@app.post("/api/prescriptions")
@auth_required(roles=["doctor"])
def create_prescription():
    d = request.get_json(silent=True) or {}
    row = {
        "consultation_id": d.get("consultation_id"),
        "patient_id": d.get("patient_id"),
        "doctor_id": g.user["uid"],
        "medicines": d.get("medicines", []),
        "instructions": d.get("instructions"),
    }
    r = supabase.table("prescriptions").insert(row).execute()
    if d.get("patient_id"):
        supabase.table("notifications").insert({
            "user_id": d["patient_id"],
            "title": "New Prescription",
            "message": "Your doctor has issued a new prescription",
            "type": "prescription",
        }).execute()
    return _ok(r.data[0] if r.data else {})


@app.get("/api/prescriptions")
@auth_required()
def list_prescriptions():
    uid = g.user["uid"]
    role = g.user["role"]
    q = supabase.table("prescriptions").select("*")
    if role == "patient":
        q = q.eq("patient_id", uid)
    elif role == "doctor":
        q = q.eq("doctor_id", uid)
    rows = q.order("issued_at", desc=True).execute().data or []
    for row in rows:
        for key in ("patient_id", "doctor_id"):
            u = supabase.table("users").select("user_code,full_name").eq("id", row[key]).execute().data
            if u:
                row[key.replace("_id", "_name")] = u[0]["full_name"]
    return _ok(rows)


@app.get("/api/prescriptions/<pid>/pdf")
@auth_required()
def prescription_pdf(pid):
    r = supabase.table("prescriptions").select("*").eq("id", pid).execute().data
    if not r:
        return _err("Not found.", 404)
    pres = r[0]
    pat = supabase.table("users").select("full_name,user_code").eq("id", pres["patient_id"]).execute().data[0]
    doc = supabase.table("users").select("full_name,user_code").eq("id", pres["doctor_id"]).execute().data[0]

    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    c.setFillColorRGB(0.145, 0.388, 0.922)
    c.rect(0, 780, 600, 60, fill=1, stroke=0)
    c.setFillColorRGB(1, 1, 1)
    c.setFont("Helvetica-Bold", 22)
    c.drawString(40, 800, "MediSphere — Prescription")
    c.setFillColorRGB(0, 0, 0)
    c.setFont("Helvetica", 11)
    c.drawString(40, 750, f"Patient: {pat['full_name']} ({pat['user_code']})")
    c.drawString(40, 735, f"Doctor:  {doc['full_name']} ({doc['user_code']})")
    c.drawString(40, 720, f"Date:    {str(pres.get('issued_at',''))[:10]}")
    c.line(40, 710, 555, 710)
    c.setFont("Helvetica-Bold", 13)
    c.drawString(40, 690, "Medicines")
    y = 670
    c.setFont("Helvetica", 11)
    meds = pres.get("medicines") or []
    if isinstance(meds, str):
        try:
            meds = json.loads(meds)
        except Exception:
            meds = []
    for m in meds:
        line = f"• {m.get('name','')} — {m.get('dose','')} — {m.get('frequency','')} — {m.get('duration','')}"
        c.drawString(50, y, line)
        y -= 18
    if pres.get("instructions"):
        y -= 10
        c.setFont("Helvetica-Bold", 12)
        c.drawString(40, y, "Instructions:")
        y -= 16
        c.setFont("Helvetica", 11)
        c.drawString(50, y, pres["instructions"])
    c.save()
    buf.seek(0)
    return send_file(buf, mimetype="application/pdf",
                     download_name=f"prescription-{pid}.pdf", as_attachment=True)


# ---------------------------------------------------------------------------
# RECORDS / REPORTS
# ---------------------------------------------------------------------------
@app.post("/api/records")
@auth_required()
def create_record():
    d = request.get_json(silent=True) or {}
    row = {
        "patient_id": d.get("patient_id") or g.user["uid"],
        "uploaded_by": g.user["uid"],
        "title": d.get("title"),
        "record_type": d.get("record_type", "note"),
        "description": d.get("description"),
        "file_url": d.get("file_url"),
    }
    r = supabase.table("medical_records").insert(row).execute()
    return _ok(r.data[0] if r.data else {})


@app.get("/api/records")
@auth_required()
def list_records():
    uid = g.user["uid"]
    role = g.user["role"]
    if role == "patient":
        r = supabase.table("medical_records").select("*").eq("patient_id", uid).execute()
    else:
        pid = request.args.get("patient_id")
        q = supabase.table("medical_records").select("*")
        if pid:
            q = q.eq("patient_id", pid)
        r = q.execute()
    return _ok(r.data or [])


@app.post("/api/reports")
@auth_required()
def create_report():
    d = request.get_json(silent=True) or {}
    row = {
        "patient_id": d.get("patient_id") or g.user["uid"],
        "uploaded_by": g.user["uid"],
        "report_name": d.get("report_name"),
        "report_type": d.get("report_type"),
        "file_url": d.get("file_url"),
        "notes": d.get("notes"),
        "report_date": d.get("report_date") or str(dt.date.today()),
    }
    r = supabase.table("lab_reports").insert(row).execute()
    return _ok(r.data[0] if r.data else {})


@app.get("/api/reports")
@auth_required()
def list_reports():
    uid = g.user["uid"]
    role = g.user["role"]
    q = supabase.table("lab_reports").select("*")
    if role == "patient":
        q = q.eq("patient_id", uid)
    elif request.args.get("patient_id"):
        q = q.eq("patient_id", request.args["patient_id"])
    return _ok(q.order("report_date", desc=True).execute().data or [])


# ---------------------------------------------------------------------------
# REMINDERS + ADHERENCE
# ---------------------------------------------------------------------------
@app.post("/api/reminders")
@auth_required(roles=["patient"])
def create_reminder():
    d = request.get_json(silent=True) or {}
    row = {
        "patient_id": g.user["uid"],
        "medicine_name": d.get("medicine_name"),
        "dosage": d.get("dosage"),
        "frequency": d.get("frequency"),
        "alarm_time": d.get("alarm_time"),
        "start_date": d.get("start_date"),
        "end_date": d.get("end_date"),
        "instructions": d.get("instructions"),
    }
    r = supabase.table("medication_reminders").insert(row).execute()
    return _ok(r.data[0] if r.data else {})


@app.get("/api/reminders")
@auth_required(roles=["patient"])
def list_reminders():
    r = supabase.table("medication_reminders").select("*").eq("patient_id", g.user["uid"]).execute()
    return _ok(r.data or [])


@app.put("/api/reminders/<rid>")
@auth_required(roles=["patient"])
def update_reminder(rid):
    d = request.get_json(silent=True) or {}
    supabase.table("medication_reminders").update(d).eq("id", rid).execute()
    return _ok({"ok": True})


@app.delete("/api/reminders/<rid>")
@auth_required(roles=["patient"])
def delete_reminder(rid):
    supabase.table("medication_reminders").delete().eq("id", rid).execute()
    return _ok({"ok": True})


@app.post("/api/reminders/<rid>/log")
@auth_required(roles=["patient"])
def log_reminder(rid):
    d = request.get_json(silent=True) or {}
    supabase.table("medication_logs").insert({
        "reminder_id": rid,
        "patient_id": g.user["uid"],
        "status": d.get("status", "taken"),
    }).execute()
    return _ok({"ok": True})


@app.get("/api/adherence")
@auth_required(roles=["patient"])
def adherence():
    uid = g.user["uid"]
    logs = supabase.table("medication_logs").select("*").eq("patient_id", uid).execute().data or []
    today = str(dt.date.today())
    week_start = str(dt.date.today() - dt.timedelta(days=7))
    month_start = str(dt.date.today() - dt.timedelta(days=30))

    def pct(rows):
        if not rows: return 0
        taken = sum(1 for r in rows if r["status"] == "taken")
        return round(taken / len(rows) * 100)

    return _ok({
        "daily":   pct([l for l in logs if l.get("log_date") == today]),
        "weekly":  pct([l for l in logs if l.get("log_date", "") >= week_start]),
        "monthly": pct([l for l in logs if l.get("log_date", "") >= month_start]),
        "total_taken":  sum(1 for l in logs if l["status"] == "taken"),
        "total_missed": sum(1 for l in logs if l["status"] == "missed"),
    })


# ---------------------------------------------------------------------------
# HEALTH METRICS
# ---------------------------------------------------------------------------
@app.post("/api/health-metrics")
@auth_required(roles=["patient"])
def add_metric():
    d = request.get_json(silent=True) or {}
    row = {
        "patient_id": g.user["uid"],
        "metric_type": d.get("metric_type"),
        "value": d.get("value"),
        "unit": d.get("unit"),
    }
    r = supabase.table("health_metrics").insert(row).execute()
    return _ok(r.data[0] if r.data else {})


@app.get("/api/health-metrics")
@auth_required()
def list_metrics():
    pid = request.args.get("patient_id") or g.user["uid"]
    r = supabase.table("health_metrics").select("*").eq("patient_id", pid).order("recorded_at", desc=True).execute()
    return _ok(r.data or [])


# ---------------------------------------------------------------------------
# NOTIFICATIONS
# ---------------------------------------------------------------------------
@app.get("/api/notifications")
@auth_required()
def list_notifications():
    r = supabase.table("notifications").select("*").eq("user_id", g.user["uid"]).order("created_at", desc=True).execute()
    return _ok(r.data or [])


@app.put("/api/notifications/<nid>/read")
@auth_required()
def mark_read(nid):
    supabase.table("notifications").update({"is_read": True}).eq("id", nid).execute()
    return _ok({"ok": True})


# ---------------------------------------------------------------------------
# QR + DIGITAL CARDS
# ---------------------------------------------------------------------------
@app.get("/api/qr/<code>")
def qr_for(code):
    img = qrcode.make(f"MEDISPHERE:{code}")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return send_file(buf, mimetype="image/png")


@app.get("/api/card/<user_code>")
@auth_required()
def digital_card(user_code):
    u = supabase.table("users").select("*").eq("user_code", user_code).execute().data
    if not u:
        return _err("Not found.", 404)
    user = u[0]; user.pop("password_hash", None)
    extra = {}
    if user["role"] == "patient":
        p = supabase.table("patients").select("*").eq("user_id", user["id"]).execute().data
        extra = p[0] if p else {}
    elif user["role"] == "doctor":
        p = supabase.table("doctors").select("*").eq("user_id", user["id"]).execute().data
        extra = p[0] if p else {}
    return _ok({"user": user, "details": extra})


@app.get("/api/card/<user_code>/pdf")
@auth_required()
def card_pdf(user_code):
    u = supabase.table("users").select("*").eq("user_code", user_code).execute().data
    if not u:
        return _err("Not found.", 404)
    user = u[0]
    extra = {}
    if user["role"] == "patient":
        p = supabase.table("patients").select("*").eq("user_id", user["id"]).execute().data
        extra = p[0] if p else {}
    else:
        p = supabase.table("doctors").select("*").eq("user_id", user["id"]).execute().data
        extra = p[0] if p else {}

    qr_img = qrcode.make(f"MEDISPHERE:{user_code}")
    qr_buf = io.BytesIO(); qr_img.save(qr_buf, format="PNG"); qr_buf.seek(0)

    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    c.setFillColorRGB(0.145, 0.388, 0.922)
    c.roundRect(60, 500, 480, 280, 20, fill=1, stroke=0)
    c.setFillColorRGB(1, 1, 1)
    c.setFont("Helvetica-Bold", 22)
    c.drawString(80, 740, "MediSphere Digital Card")
    c.setFont("Helvetica", 12)
    c.drawString(80, 715, user["role"].upper())
    c.setFont("Helvetica-Bold", 18)
    c.drawString(80, 680, user["full_name"])
    c.setFont("Helvetica", 12)
    c.drawString(80, 660, f"ID: {user['user_code']}")
    c.drawString(80, 640, f"Phone: {user['phone']}")
    if user["role"] == "patient":
        c.drawString(80, 620, f"Blood Group: {extra.get('blood_group','-')}")
        c.drawString(80, 600, f"DOB: {user.get('dob','-')}")
        c.drawString(80, 580, f"Emergency: {extra.get('emergency_contact','-')}")
    else:
        c.drawString(80, 620, f"Specialization: {extra.get('specialization','-')}")
        c.drawString(80, 600, f"License: {extra.get('license_number','-')}")
        c.drawString(80, 580, f"Hospital: {extra.get('hospital_name','-')}")

    c.drawImage(ImageReader(qr_buf), 420, 540, width=100, height=100)
    c.save()
    buf.seek(0)
    return send_file(buf, mimetype="application/pdf",
                     download_name=f"card-{user_code}.pdf", as_attachment=True)


# ---------------------------------------------------------------------------
# ADMIN
# ---------------------------------------------------------------------------
@app.get("/api/admin/stats")
@auth_required(roles=["admin"])
def admin_stats():
    def count(table, **filters):
        q = supabase.table(table).select("id", count="exact")
        for k, v in filters.items():
            q = q.eq(k, v)
        return q.execute().count or 0
    return _ok({
        "total_patients": count("users", role="patient"),
        "total_doctors": count("users", role="doctor"),
        "total_appointments": count("appointments"),
        "total_records": count("medical_records"),
        "total_reports": count("lab_reports"),
        "total_prescriptions": count("prescriptions"),
    })


@app.get("/api/admin/audit-logs")
@auth_required(roles=["admin"])
def audit_logs():
    r = supabase.table("audit_logs").select("*").order("created_at", desc=True).limit(200).execute()
    return _ok(r.data or [])


# ---------------------------------------------------------------------------
# DEV: re-seed passwords
# ---------------------------------------------------------------------------
@app.post("/api/dev/seed-passwords")
def seed_passwords():
    secret = request.headers.get("X-Seed-Secret")
    if secret != JWT_SECRET:
        return _err("Forbidden.", 403)
    new_hash = hash_password("password123")
    for code in ("ADM100001", "DOC100001", "PAT100001"):
        supabase.table("users").update({"password_hash": new_hash}).eq("user_code", code).execute()
    return _ok({"default_password": "password123"})


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT, debug=True)
