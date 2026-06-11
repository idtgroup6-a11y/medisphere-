"""
MediSphere - Full Flask Backend (single file)
Run: python app.py
"""
import os
import io
import jwt
import bcrypt
import qrcode
import datetime as dt
from functools import wraps
from flask import Flask, request, jsonify, send_file, send_from_directory
from flask_cors import CORS
from supabase import create_client, Client
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from dotenv import load_dotenv

load_dotenv()

# ------------------------------------------------------------------
# CONFIG
# ------------------------------------------------------------------
SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "")
JWT_SECRET   = os.getenv("JWT_SECRET", "medisphere-secret-college-project")
JWT_ALG      = "HS256"
JWT_EXP_HRS  = 24
FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "..", "frontend")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY) if SUPABASE_URL else None

app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path="")
CORS(app, supports_credentials=True)

# ------------------------------------------------------------------
# HELPERS
# ------------------------------------------------------------------
def hash_password(pw: str) -> str:
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()

def verify_password(pw: str, pw_hash: str) -> bool:
    try:
        return bcrypt.checkpw(pw.encode(), pw_hash.encode())
    except Exception:
        return False

def make_token(user):
    payload = {
        "uid": user["id"],
        "code": user["user_code"],
        "role": user["role"],
        "exp": dt.datetime.utcnow() + dt.timedelta(hours=JWT_EXP_HRS),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

def auth_required(roles=None):
    def deco(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            token = request.headers.get("Authorization", "").replace("Bearer ", "")
            if not token:
                return jsonify({"error": "Missing token"}), 401
            try:
                data = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
            except Exception as e:
                return jsonify({"error": f"Invalid token: {e}"}), 401
            if roles and data["role"] not in roles:
                return jsonify({"error": "Forbidden"}), 403
            request.user = data
            return fn(*args, **kwargs)
        return wrapper
    return deco

def next_user_code(role: str) -> str:
    prefix = {"patient": "PAT", "doctor": "DOC", "admin": "ADM"}[role]
    res = supabase.table("users").select("user_code").eq("role", role).execute()
    nums = [int(r["user_code"][3:]) for r in (res.data or []) if r["user_code"].startswith(prefix)]
    nxt = max(nums) + 1 if nums else 100001
    return f"{prefix}{nxt}"

def log_audit(user_id, action, details=""):
    try:
        supabase.table("audit_logs").insert({
            "user_id": user_id, "action": action, "details": details
        }).execute()
    except Exception:
        pass

# ------------------------------------------------------------------
# STATIC FRONTEND
# ------------------------------------------------------------------
@app.route("/")
def root():
    return send_from_directory(FRONTEND_DIR, "index.html")

@app.route("/<path:path>")
def static_proxy(path):
    full = os.path.join(FRONTEND_DIR, path)
    if os.path.isfile(full):
        return send_from_directory(FRONTEND_DIR, path)
    return send_from_directory(FRONTEND_DIR, "index.html")

# ------------------------------------------------------------------
# AUTH
# ------------------------------------------------------------------
@app.post("/api/auth/check-availability")
def check_availability():
    d = request.json or {}
    out = {}
    if d.get("email"):
        r = supabase.table("users").select("id").eq("email", d["email"]).execute()
        out["email"] = "taken" if r.data else "available"
    if d.get("phone"):
        r = supabase.table("users").select("id").eq("phone", d["phone"]).execute()
        out["phone"] = "taken" if r.data else "available"
    return jsonify(out)

@app.post("/api/auth/register")
def register():
    d = request.json or {}
    required = ["full_name", "email", "phone", "password", "role"]
    for k in required:
        if not d.get(k):
            return jsonify({"error": f"{k} is required"}), 400
    role = d["role"].lower()
    if role not in ("patient", "doctor", "admin"):
        return jsonify({"error": "Invalid role"}), 400

    # uniqueness
    exists = supabase.table("users").select("id").or_(
        f"email.eq.{d['email']},phone.eq.{d['phone']}"
    ).execute()
    if exists.data:
        return jsonify({"error": "Email or phone already exists"}), 409

    code = next_user_code(role)
    user_row = {
        "user_code": code,
        "role": role,
        "full_name": d["full_name"],
        "email": d["email"],
        "phone": d["phone"],
        "password_hash": hash_password(d["password"]),
        "gender": d.get("gender"),
        "dob": d.get("dob"),
    }
    inserted = supabase.table("users").insert(user_row).execute()
    user = inserted.data[0]

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

    log_audit(user["id"], "register", f"{role} registered")
    return jsonify({"token": make_token(user), "user": user})

@app.post("/api/auth/login")
def login():
    d = request.json or {}
    identifier = d.get("identifier")  # user_code / email / phone
    password = d.get("password")
    role = d.get("role")
    if not identifier or not password:
        return jsonify({"error": "Identifier and password required"}), 400

    q = supabase.table("users").select("*").or_(
        f"user_code.eq.{identifier},email.eq.{identifier},phone.eq.{identifier}"
    )
    if role:
        q = q.eq("role", role)
    res = q.execute()
    if not res.data:
        return jsonify({"error": "Account not found"}), 404
    user = res.data[0]
    if not verify_password(password, user["password_hash"]):
        return jsonify({"error": "Invalid password"}), 401

    log_audit(user["id"], "login")
    return jsonify({"token": make_token(user), "user": {
        k: v for k, v in user.items() if k != "password_hash"
    }})

@app.get("/api/auth/me")
@auth_required()
def me():
    res = supabase.table("users").select("*").eq("id", request.user["uid"]).execute()
    if not res.data:
        return jsonify({"error": "Not found"}), 404
    user = res.data[0]
    user.pop("password_hash", None)

    profile = {}
    if user["role"] == "patient":
        p = supabase.table("patients").select("*").eq("user_id", user["id"]).execute()
        profile = p.data[0] if p.data else {}
    elif user["role"] == "doctor":
        p = supabase.table("doctors").select("*").eq("user_id", user["id"]).execute()
        profile = p.data[0] if p.data else {}
    return jsonify({"user": user, "profile": profile})

@app.post("/api/auth/forgot-password")
def forgot_password():
    d = request.json or {}
    code = d.get("user_code")
    phone = d.get("phone")
    if not code or not phone:
        return jsonify({"error": "user_code and phone required"}), 400
    res = supabase.table("users").select("id").eq("user_code", code).eq("phone", phone).execute()
    if not res.data:
        return jsonify({"error": "No matching account"}), 404
    return jsonify({"ok": True, "user_id": res.data[0]["id"]})

@app.post("/api/auth/reset-password")
def reset_password():
    d = request.json or {}
    user_id = d.get("user_id")
    new_password = d.get("new_password")
    confirm = d.get("confirm_password")
    if not all([user_id, new_password, confirm]):
        return jsonify({"error": "All fields required"}), 400
    if new_password != confirm:
        return jsonify({"error": "Passwords do not match"}), 400
    supabase.table("users").update({"password_hash": hash_password(new_password)}).eq("id", user_id).execute()
    log_audit(user_id, "password_reset")
    return jsonify({"ok": True})

@app.post("/api/auth/logout")
@auth_required()
def logout():
    log_audit(request.user["uid"], "logout")
    return jsonify({"ok": True})

# ------------------------------------------------------------------
# PATIENTS / DOCTORS LISTS
# ------------------------------------------------------------------
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
    return jsonify(out)

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
    return jsonify(out)

@app.put("/api/profile")
@auth_required()
def update_profile():
    d = request.json or {}
    uid = request.user["uid"]
    role = request.user["role"]
    user_fields = {k: d[k] for k in ("full_name", "phone", "gender", "dob", "photo_url") if k in d}
    if user_fields:
        supabase.table("users").update(user_fields).eq("id", uid).execute()
    profile_fields = d.get("profile") or {}
    if profile_fields and role in ("patient", "doctor"):
        table = "patients" if role == "patient" else "doctors"
        supabase.table(table).update(profile_fields).eq("user_id", uid).execute()
    return jsonify({"ok": True})

# ------------------------------------------------------------------
# APPOINTMENTS
# ------------------------------------------------------------------
@app.post("/api/appointments")
@auth_required(roles=["patient"])
def create_appointment():
    d = request.json or {}
    row = {
        "patient_id": request.user["uid"],
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
    return jsonify(r.data[0])

@app.get("/api/appointments")
@auth_required()
def list_appointments():
    uid = request.user["uid"]
    role = request.user["role"]
    if role == "patient":
        r = supabase.table("appointments").select("*").eq("patient_id", uid).order("appointment_date", desc=True).execute()
    elif role == "doctor":
        r = supabase.table("appointments").select("*").eq("doctor_id", uid).order("appointment_date", desc=True).execute()
    else:
        r = supabase.table("appointments").select("*").order("appointment_date", desc=True).execute()
    rows = r.data or []
    # enrich with names
    for row in rows:
        for key in ("patient_id", "doctor_id"):
            u = supabase.table("users").select("user_code,full_name").eq("id", row[key]).execute().data
            if u:
                row[key.replace("_id", "_name")] = u[0]["full_name"]
                row[key.replace("_id", "_code")] = u[0]["user_code"]
    return jsonify(rows)

@app.put("/api/appointments/<aid>")
@auth_required()
def update_appointment(aid):
    d = request.json or {}
    allowed = {k: d[k] for k in ("appointment_date", "appointment_time", "status", "notes") if k in d}
    supabase.table("appointments").update(allowed).eq("id", aid).execute()
    return jsonify({"ok": True})

@app.delete("/api/appointments/<aid>")
@auth_required()
def cancel_appointment(aid):
    supabase.table("appointments").update({"status": "cancelled"}).eq("id", aid).execute()
    return jsonify({"ok": True})

# ------------------------------------------------------------------
# CONSULTATIONS
# ------------------------------------------------------------------
@app.post("/api/consultations")
@auth_required(roles=["doctor"])
def create_consultation():
    d = request.json or {}
    row = {
        "appointment_id": d.get("appointment_id"),
        "patient_id": d["patient_id"],
        "doctor_id": request.user["uid"],
        "diagnosis": d.get("diagnosis"),
        "treatment": d.get("treatment"),
        "notes": d.get("notes"),
    }
    r = supabase.table("consultations").insert(row).execute()
    return jsonify(r.data[0])

@app.get("/api/consultations")
@auth_required()
def list_consultations():
    uid = request.user["uid"]
    role = request.user["role"]
    field = "patient_id" if role == "patient" else "doctor_id" if role == "doctor" else None
    q = supabase.table("consultations").select("*")
    if field:
        q = q.eq(field, uid)
    return jsonify(q.order("created_at", desc=True).execute().data or [])

# ------------------------------------------------------------------
# PRESCRIPTIONS
# ------------------------------------------------------------------
@app.post("/api/prescriptions")
@auth_required(roles=["doctor"])
def create_prescription():
    d = request.json or {}
    row = {
        "consultation_id": d.get("consultation_id"),
        "patient_id": d["patient_id"],
        "doctor_id": request.user["uid"],
        "medicines": d.get("medicines", []),
        "instructions": d.get("instructions"),
    }
    r = supabase.table("prescriptions").insert(row).execute()
    supabase.table("notifications").insert({
        "user_id": d["patient_id"],
        "title": "New Prescription",
        "message": "Your doctor has issued a new prescription",
        "type": "prescription",
    }).execute()
    return jsonify(r.data[0])

@app.get("/api/prescriptions")
@auth_required()
def list_prescriptions():
    uid = request.user["uid"]
    role = request.user["role"]
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
    return jsonify(rows)

@app.get("/api/prescriptions/<pid>/pdf")
@auth_required()
def prescription_pdf(pid):
    r = supabase.table("prescriptions").select("*").eq("id", pid).execute().data
    if not r:
        return jsonify({"error": "Not found"}), 404
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
    c.drawString(40, 720, f"Date:    {pres.get('issued_at','')[:10]}")
    c.line(40, 710, 555, 710)
    c.setFont("Helvetica-Bold", 13)
    c.drawString(40, 690, "Medicines")
    y = 670
    c.setFont("Helvetica", 11)
    for m in pres.get("medicines", []) or []:
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

# ------------------------------------------------------------------
# MEDICAL RECORDS & LAB REPORTS
# ------------------------------------------------------------------
@app.post("/api/records")
@auth_required()
def create_record():
    d = request.json or {}
    row = {
        "patient_id": d.get("patient_id") or request.user["uid"],
        "uploaded_by": request.user["uid"],
        "title": d.get("title"),
        "record_type": d.get("record_type", "note"),
        "description": d.get("description"),
        "file_url": d.get("file_url"),
    }
    r = supabase.table("medical_records").insert(row).execute()
    return jsonify(r.data[0])

@app.get("/api/records")
@auth_required()
def list_records():
    uid = request.user["uid"]
    role = request.user["role"]
    if role == "patient":
        r = supabase.table("medical_records").select("*").eq("patient_id", uid).execute()
    else:
        pid = request.args.get("patient_id")
        q = supabase.table("medical_records").select("*")
        if pid: q = q.eq("patient_id", pid)
        r = q.execute()
    return jsonify(r.data or [])

@app.post("/api/reports")
@auth_required()
def create_report():
    d = request.json or {}
    row = {
        "patient_id": d.get("patient_id") or request.user["uid"],
        "uploaded_by": request.user["uid"],
        "report_name": d.get("report_name"),
        "report_type": d.get("report_type"),
        "file_url": d.get("file_url"),
        "notes": d.get("notes"),
        "report_date": d.get("report_date") or str(dt.date.today()),
    }
    r = supabase.table("lab_reports").insert(row).execute()
    return jsonify(r.data[0])

@app.get("/api/reports")
@auth_required()
def list_reports():
    uid = request.user["uid"]
    role = request.user["role"]
    q = supabase.table("lab_reports").select("*")
    if role == "patient":
        q = q.eq("patient_id", uid)
    elif request.args.get("patient_id"):
        q = q.eq("patient_id", request.args["patient_id"])
    return jsonify(q.order("report_date", desc=True).execute().data or [])

# ------------------------------------------------------------------
# REMINDERS + ADHERENCE
# ------------------------------------------------------------------
@app.post("/api/reminders")
@auth_required(roles=["patient"])
def create_reminder():
    d = request.json or {}
    row = {
        "patient_id": request.user["uid"],
        "medicine_name": d["medicine_name"],
        "dosage": d.get("dosage"),
        "frequency": d.get("frequency"),
        "alarm_time": d.get("alarm_time"),
        "start_date": d.get("start_date"),
        "end_date": d.get("end_date"),
        "instructions": d.get("instructions"),
    }
    r = supabase.table("medication_reminders").insert(row).execute()
    return jsonify(r.data[0])

@app.get("/api/reminders")
@auth_required(roles=["patient"])
def list_reminders():
    r = supabase.table("medication_reminders").select("*").eq("patient_id", request.user["uid"]).execute()
    return jsonify(r.data or [])

@app.put("/api/reminders/<rid>")
@auth_required(roles=["patient"])
def update_reminder(rid):
    d = request.json or {}
    supabase.table("medication_reminders").update(d).eq("id", rid).execute()
    return jsonify({"ok": True})

@app.delete("/api/reminders/<rid>")
@auth_required(roles=["patient"])
def delete_reminder(rid):
    supabase.table("medication_reminders").delete().eq("id", rid).execute()
    return jsonify({"ok": True})

@app.post("/api/reminders/<rid>/log")
@auth_required(roles=["patient"])
def log_reminder(rid):
    d = request.json or {}
    supabase.table("medication_logs").insert({
        "reminder_id": rid,
        "patient_id": request.user["uid"],
        "status": d.get("status", "taken"),
    }).execute()
    return jsonify({"ok": True})

@app.get("/api/adherence")
@auth_required(roles=["patient"])
def adherence():
    uid = request.user["uid"]
    logs = supabase.table("medication_logs").select("*").eq("patient_id", uid).execute().data or []
    today = str(dt.date.today())
    week_start = str(dt.date.today() - dt.timedelta(days=7))
    month_start = str(dt.date.today() - dt.timedelta(days=30))

    def pct(rows):
        if not rows: return 0
        taken = sum(1 for r in rows if r["status"] == "taken")
        return round(taken / len(rows) * 100)

    return jsonify({
        "daily":   pct([l for l in logs if l["log_date"] == today]),
        "weekly":  pct([l for l in logs if l["log_date"] >= week_start]),
        "monthly": pct([l for l in logs if l["log_date"] >= month_start]),
        "total_taken":  sum(1 for l in logs if l["status"] == "taken"),
        "total_missed": sum(1 for l in logs if l["status"] == "missed"),
    })

# ------------------------------------------------------------------
# HEALTH METRICS
# ------------------------------------------------------------------
@app.post("/api/health-metrics")
@auth_required(roles=["patient"])
def add_metric():
    d = request.json or {}
    row = {
        "patient_id": request.user["uid"],
        "metric_type": d["metric_type"],
        "value": d["value"],
        "unit": d.get("unit"),
    }
    r = supabase.table("health_metrics").insert(row).execute()
    return jsonify(r.data[0])

@app.get("/api/health-metrics")
@auth_required()
def list_metrics():
    pid = request.args.get("patient_id") or request.user["uid"]
    r = supabase.table("health_metrics").select("*").eq("patient_id", pid).order("recorded_at", desc=True).execute()
    return jsonify(r.data or [])

# ------------------------------------------------------------------
# NOTIFICATIONS
# ------------------------------------------------------------------
@app.get("/api/notifications")
@auth_required()
def list_notifications():
    r = supabase.table("notifications").select("*").eq("user_id", request.user["uid"]).order("created_at", desc=True).execute()
    return jsonify(r.data or [])

@app.put("/api/notifications/<nid>/read")
@auth_required()
def mark_read(nid):
    supabase.table("notifications").update({"is_read": True}).eq("id", nid).execute()
    return jsonify({"ok": True})

# ------------------------------------------------------------------
# QR + DIGITAL CARDS
# ------------------------------------------------------------------
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
        return jsonify({"error": "Not found"}), 404
    user = u[0]; user.pop("password_hash", None)
    extra = {}
    if user["role"] == "patient":
        p = supabase.table("patients").select("*").eq("user_id", user["id"]).execute().data
        extra = p[0] if p else {}
    elif user["role"] == "doctor":
        p = supabase.table("doctors").select("*").eq("user_id", user["id"]).execute().data
        extra = p[0] if p else {}
    return jsonify({"user": user, "details": extra})

@app.get("/api/card/<user_code>/pdf")
@auth_required()
def card_pdf(user_code):
    u = supabase.table("users").select("*").eq("user_code", user_code).execute().data
    if not u: return jsonify({"error": "Not found"}), 404
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

    from reportlab.lib.utils import ImageReader
    c.drawImage(ImageReader(qr_buf), 420, 540, width=100, height=100)
    c.save()
    buf.seek(0)
    return send_file(buf, mimetype="application/pdf",
                     download_name=f"card-{user_code}.pdf", as_attachment=True)

# ------------------------------------------------------------------
# ADMIN ANALYTICS
# ------------------------------------------------------------------
@app.get("/api/admin/stats")
@auth_required(roles=["admin"])
def admin_stats():
    def count(table, **filters):
        q = supabase.table(table).select("id", count="exact")
        for k, v in filters.items(): q = q.eq(k, v)
        return q.execute().count or 0
    return jsonify({
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
    return jsonify(r.data or [])

# ------------------------------------------------------------------
# DEV: re-seed passwords (so seed accounts work with current bcrypt)
# ------------------------------------------------------------------
@app.post("/api/dev/seed-passwords")
def seed_passwords():
    secret = request.headers.get("X-Seed-Secret")
    if secret != JWT_SECRET:
        return jsonify({"error": "Forbidden"}), 403
    new_hash = hash_password("password123")
    for code in ("ADM100001", "DOC100001", "PAT100001"):
        supabase.table("users").update({"password_hash": new_hash}).eq("user_code", code).execute()
    return jsonify({"ok": True, "default_password": "password123"})

# ------------------------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
