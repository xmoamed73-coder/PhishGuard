from flask import Flask, render_template, request, redirect, url_for, session
import re
import sqlite3
import os
import uuid
from datetime import datetime, timedelta
from contextlib import closing
from urllib.parse import urlparse

import cv2
import numpy as np

app = Flask(__name__)

SITE_NAME = os.environ.get("SITE_NAME", "PhishGuard")
CONTACT_EMAIL = os.environ.get("CONTACT_EMAIL", "xmoamed73@gmail.com")

app.secret_key = os.environ.get("SECRET_KEY", "dev-only-change-me")
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=bool(os.environ.get("PRODUCTION")),
    PERMANENT_SESSION_LIFETIME=timedelta(days=90),
)
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # أقصى حجم للصورة 5MB

DB_PATH = os.environ.get("DB_PATH", os.path.join(os.path.dirname(os.path.abspath(__file__)), "history.db"))
HISTORY_LIMIT = 20

TRUSTED_DOMAINS = [
    "microsoft.com",
    "office.com",
    "outlook.com",
    "live.com"
]

SUSPICIOUS_WORDS = [
    "urgent", "verify", "password",
    "login", "click", "suspended",
    "security", "confirm", "update",
    "account"
]


# ================= DATABASE (HISTORY) =================
def uid():
    """معرّف مجهول لكل زائر (كوكي) عشان كل واحد يشوف سجله هو بس."""
    if "uid" not in session:
        session["uid"] = uuid.uuid4().hex
        session.permanent = True
    return session["uid"]


def init_db():
    with closing(sqlite3.connect(DB_PATH)) as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS analyses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                source TEXT NOT NULL,
                snippet TEXT NOT NULL,
                status TEXT NOT NULL,
                safety INTEGER NOT NULL,
                risk INTEGER NOT NULL,
                color TEXT NOT NULL
            )
        """)
        db.execute("CREATE INDEX IF NOT EXISTS idx_user ON analyses(user_id)")
        db.commit()


def save_history(user_id, source, text, status, safety, risk, color):
    snippet = " ".join(text.split())[:90]
    with closing(sqlite3.connect(DB_PATH)) as db:
        db.execute(
            "INSERT INTO analyses (user_id, created_at, source, snippet, status, safety, risk, color) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (user_id, datetime.now().strftime("%Y-%m-%d %H:%M"), source,
             snippet, status, safety, risk, color),
        )
        # نحتفظ بآخر 100 تحليل لكل زائر بس
        db.execute(
            "DELETE FROM analyses WHERE user_id = ? AND id NOT IN "
            "(SELECT id FROM analyses WHERE user_id = ? ORDER BY id DESC LIMIT 100)",
            (user_id, user_id),
        )
        db.commit()


def get_history(user_id):
    with closing(sqlite3.connect(DB_PATH)) as db:
        db.row_factory = sqlite3.Row
        rows = db.execute(
            "SELECT * FROM analyses WHERE user_id = ? ORDER BY id DESC LIMIT ?",
            (user_id, HISTORY_LIMIT),
        ).fetchall()
    return [dict(r) for r in rows]


# ================= QR DECODING =================
def decode_qr(file_bytes):
    """بيرجع النص اللي جوه الـ QR أو None لو ملقاش."""
    arr = np.frombuffer(file_bytes, np.uint8)
    img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
    if img is None:
        return None

    detector = cv2.QRCodeDetector()

    # محاولات متعددة لزيادة فرصة القراءة
    attempts = [img]
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    attempts.append(gray)
    attempts.append(cv2.resize(img, None, fx=2, fy=2, interpolation=cv2.INTER_CUBIC))
    attempts.append(cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)[1])

    for candidate in attempts:
        data, _, _ = detector.detectAndDecode(candidate)
        if data:
            return data
    return None


# ================= ANALYSIS =================
def analyze_email(text):

    text_low = text.lower()

    # ================= CONTENT =================
    content_score = 100
    hits = sum(1 for w in SUSPICIOUS_WORDS if w in text_low)
    content_score -= hits * 10

    # ================= LINKS =================
    urls = re.findall(r'https?://\S+', text)

    link_score = 100
    for url in urls:
        if "http://" in url:
            link_score -= 10

        if any(w in url.lower() for w in ["login", "verify", "secure", "update"]):
            link_score -= 15

        if not any(d in url for d in TRUSTED_DOMAINS):
            link_score -= 40

    # ================= DOMAIN =================
    domain_score = 100
    for url in urls:
        domain = urlparse(url).netloc.lower()
        if not any(d in domain for d in TRUSTED_DOMAINS):
            domain_score -= 30

    # ================= FINAL SCORE =================
    safety = (content_score + link_score + domain_score) / 3
    safety = max(0, min(100, int(safety)))

    risk = 100 - safety

    # ================= CLASSIFICATION =================
    if safety >= 30:
        status = "SAFE 🟢"
        color = "#22c55e"

    elif safety >= 10:
        status = "DANGEROUS 🟠"
        color = "#f59e0b"

    else:
        status = "VERY DANGEROUS 🔴"
        color = "#ef4444"

    return status, safety, risk, content_score, link_score, domain_score, len(urls), hits, color


@app.route("/", methods=["GET", "POST"])
def home():

    data = {
        "status": None,
        "safety": 100,
        "risk": 0,
        "content": 100,
        "links": 100,
        "domain": 100,
        "urls": 0,
        "hits": 0,
        "color": "#22c55e",
        "source": "text",
        "scanned_text": None,
        "error": None,
    }

    if request.method == "POST":
        text = (request.form.get("email_content") or "").strip()
        qr_file = request.files.get("qr_image")
        source = "text"

        # لو المستخدم رفع صورة QR
        if qr_file and qr_file.filename:
            decoded = decode_qr(qr_file.read())
            if decoded:
                text = decoded
                source = "qr-image"
                data["scanned_text"] = decoded
            else:
                data["error"] = "مقدرتش أقرأ QR code من الصورة دي. جرّب صورة أوضح."
                text = ""
        # لو جاي من مسح الكاميرا (الـ JS بيبعت الفلاج ده)
        elif request.form.get("from_camera") == "1" and text:
            source = "qr-camera"
            data["scanned_text"] = text

        if text:
            (status, safety, risk,
             content, links, domain,
             urls, hits, color) = analyze_email(text)

            data.update({
                "status": status,
                "safety": safety,
                "risk": risk,
                "content": content,
                "links": links,
                "domain": domain,
                "urls": urls,
                "hits": hits,
                "color": color,
                "source": source,
            })

            save_history(uid(), source, text, status, safety, risk, color)
        elif not data["error"]:
            data["error"] = "اكتب نص الإيميل أو ارفع صورة QR."

    return render_template("index.html", history=get_history(uid()), **data)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/clear_history", methods=["POST"])
def clear_history():
    with closing(sqlite3.connect(DB_PATH)) as db:
        db.execute("DELETE FROM analyses WHERE user_id = ?", (uid(),))
        db.commit()
    return redirect(url_for("home"))


@app.route("/delete/<int:item_id>", methods=["POST"])
def delete_item(item_id):
    with closing(sqlite3.connect(DB_PATH)) as db:
        db.execute("DELETE FROM analyses WHERE id = ? AND user_id = ?", (item_id, uid()))
        db.commit()
    return redirect(url_for("home"))


@app.context_processor
def inject_site():
    return {"site_name": SITE_NAME, "contact_email": CONTACT_EMAIL,
            "year": datetime.now().year}


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    resp.headers["Permissions-Policy"] = "camera=(self), microphone=(), geolocation=()"
    return resp


@app.errorhandler(413)
def too_large(_):
    return render_template("index.html", history=get_history(uid()), status=None,
                           safety=100, risk=0, content=100, links=100, domain=100,
                           urls=0, hits=0, color="#22c55e", source="text",
                           scanned_text=None,
                           error="الصورة كبيرة قوي (الحد الأقصى 5MB)."), 413


init_db()

if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
