#!/usr/bin/env python3
"""
Cleaned, full app.py for CashinGo-style payment links app.
Features:
- Flask + SQLAlchemy (single instance)
- PostgreSQL support via DATABASE_URL (auto-fix postgres:// -> postgresql://)
- Auto-create tables on startup
- Optional superadmin seeding via env variables
- Uploads persisted under uploads/ (use Render Disk for persistence)
- All routes preserved from your original app
"""

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, send_from_directory, flash, abort, jsonify
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from pathlib import Path
import os
import time
import threading
import requests
import secrets
import string

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, or_
from functools import wraps

# ---------------- Config & FS ----------------
BASE_DIR = Path(__file__).parent.resolve()
UPLOAD_FOLDER = BASE_DIR / "uploads"
STATIC_FOLDER = BASE_DIR / "static"
TEMPLATES_FOLDER = BASE_DIR / "templates"

# ensure folders exist
UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)
STATIC_FOLDER.mkdir(parents=True, exist_ok=True)
TEMPLATES_FOLDER.mkdir(parents=True, exist_ok=True)  # templates should be in your repo

# Flask app
app = Flask(__name__, template_folder=str(TEMPLATES_FOLDER), static_folder=str(STATIC_FOLDER), static_url_path="/static")

# secret key
app.secret_key = os.environ.get("CASHINGO_SECRET", "change_me_in_prod")

# DB config: prefer env DATABASE_URL, fallback to sqlite for local dev
DATABASE_URL = os.environ.get("DATABASE_URL", f"sqlite:///{BASE_DIR / 'local.db'}")
# Render sometimes provides postgres:// — SQLAlchemy expects postgresql://
if isinstance(DATABASE_URL, str) and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# upload folder config for send_from_directory
app.config['UPLOAD_FOLDER'] = str(UPLOAD_FOLDER)
app.config['MAX_CONTENT_LENGTH'] = 25 * 1024 * 1024  # 25 MB

# ---------------- DB init (single instance) ----------------
db = SQLAlchemy(app)  # only created once

# ---------------- Models ----------------
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    username = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    slug = db.Column(db.String(120), unique=True, nullable=False)
    role = db.Column(db.String(20), default="user")  # user | admin | superadmin
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    settings = db.relationship('Setting', backref='user', uselist=False, cascade="all, delete-orphan")
    payments = db.relationship('Payment', backref='user', cascade="all, delete-orphan")
    paylinks = db.relationship('PayLink', backref='user', cascade="all, delete-orphan")

class Setting(db.Model):
    __tablename__ = 'settings'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    upi_id = db.Column(db.String(255), default="")
    receiver_name = db.Column(db.String(255), default="")
    loan_number = db.Column(db.String(255), default="")
    default_amount = db.Column(db.Float, default=0.0)

class Payment(db.Model):
    __tablename__ = 'payments'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    name = db.Column(db.String(255))
    mobile = db.Column(db.String(32))
    amount = db.Column(db.Float, default=0.0)
    screenshot = db.Column(db.String(512))
    status = db.Column(db.String(32), default='Pending')  # Pending | Approved
    created_at = db.Column(db.Integer, default=lambda: int(time.time()))

class PayLink(db.Model):
    __tablename__ = 'paylinks'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    code = db.Column(db.String(12), unique=True, nullable=False, index=True)  # short code
    name = db.Column(db.String(255))
    mobile = db.Column(db.String(32))
    amount = db.Column(db.Float, default=0.0)
    expires_at = db.Column(db.DateTime, nullable=True)  # null = never expires
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# ---------------- Helpers / Utilities ----------------
def slugify_username(username: str) -> str:
    base = ''.join(ch for ch in username.lower().strip().replace(' ', '-') if ch.isalnum() or ch == '-')
    if not base:
        base = "user"
    slug = base
    n = 1
    while User.query.filter_by(slug=slug).first() is not None:
        n += 1
        slug = f"{base}-{n}"
    return slug

def make_code(k=7):
    alphabet = string.ascii_letters + string.digits
    while True:
        code = ''.join(secrets.choice(alphabet) for _ in range(k))
        if not PayLink.query.filter_by(code=code).first():
            return code

def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if 'uid' not in session:
            return redirect(url_for('login', next=request.path))
        return view(*args, **kwargs)
    return wrapper

def role_required(*roles):
    def deco(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            uid = session.get('uid')
            if not uid:
                return redirect(url_for('login', next=request.path))
            u = db.session.get(User, uid)
            if not u or u.role not in roles:
                abort(403)
            return view(*args, **kwargs)
        return wrapper
    return deco

@app.template_filter('ts_to_string')
def ts_to_string(ts):
    try:
        return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(int(ts)))
    except Exception:
        return "-"

# ---------------- Create DB tables & optional seeding ----------------
# Run once at import / startup so tables exist for the first requests (works with Gunicorn)
with app.app_context():
    db.create_all()

    # Optional: create superadmin from env variables (first run)
    seed_email = os.environ.get("SEED_SUPERADMIN_EMAIL")
    seed_user = os.environ.get("SEED_SUPERADMIN_USER")
    seed_pass = os.environ.get("SEED_SUPERADMIN_PASS")
    if seed_email and seed_user and seed_pass:
        existing = User.query.filter_by(email=seed_email).first()
        if not existing:
            su = User(
                email=seed_email,
                username=seed_user,
                password_hash=generate_password_hash(seed_pass),
                slug=slugify_username(seed_user),
                role='superadmin'
            )
            db.session.add(su)
            db.session.commit()  # commit so su.id exists
            # create default settings row for superadmin
            s = Setting(user_id=su.id, upi_id='', receiver_name=seed_user, loan_number='', default_amount=0.0)
            db.session.add(s)
            db.session.commit()

# ---------------- Routes ----------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email','').strip().lower()
        username = request.form.get('username','').strip()
        password = request.form.get('password','')

        if not email or not username or not password:
            flash('All fields are required.', 'danger')
            return render_template('register.html')

        conflict = User.query.filter(or_(User.email == email, User.username == username)).first()
        if conflict:
            flash('Email or username already exists.', 'danger')
            return render_template('register.html')

        u = User(
            email=email,
            username=username,
            password_hash=generate_password_hash(password),
            slug=slugify_username(username),
            role='user'
        )
        db.session.add(u)
        db.session.commit()

        s = Setting(user_id=u.id, upi_id='', receiver_name=username, loan_number='', default_amount=0.0)
        db.session.add(s)
        db.session.commit()

        session['uid'] = u.id
        flash('Account created and logged in.', 'success')
        return redirect(url_for('dashboard'))
    return render_template('register.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        identifier = request.form.get('email_or_username','').strip()
        password = request.form.get('password','')

        if not identifier or not password:
            flash('Please fill both fields.', 'danger')
            return render_template('login.html')

        # case-insensitive email or username match
        user = User.query.filter(
            or_(func.lower(User.email) == identifier.lower(), func.lower(User.username) == identifier.lower())
        ).first()

        if not user or not check_password_hash(user.password_hash, password):
            flash('Invalid credentials.', 'danger')
            return render_template('login.html')

        session['uid'] = user.id
        flash('Logged in successfully.', 'success')
        return redirect(request.args.get('next') or url_for('dashboard'))
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    session.pop('uid', None)
    flash('Logged out.', 'info')
    return redirect(url_for('login'))

# ---------------- User Dashboard & settings ----------------
@app.route('/dashboard', methods=['GET','POST'])
@login_required
def dashboard():
    user = db.session.get(User, session['uid'])
    settings = user.settings
    if request.method == 'POST':
        settings.upi_id = request.form.get('upi_id','').strip()
        settings.receiver_name = request.form.get('receiver_name','').strip()
        settings.loan_number = request.form.get('loan_number','').strip()
        try:
            settings.default_amount = float(request.form.get('default_amount') or 0)
        except Exception:
            settings.default_amount = 0.0
        db.session.commit()
        flash('Settings updated!', 'success')
        return redirect(url_for('dashboard'))

    public_link = url_for('public_page', slug=user.slug, _external=True)
    pending = Payment.query.filter_by(user_id=user.id, status='Pending').count()
    short_count = PayLink.query.filter_by(user_id=user.id).count()
    return render_template('dashboard.html',
                           user=user, settings=settings,
                           public_link=public_link,
                           pending=pending, short_count=short_count)

# ---------------- Payments list & actions ----------------
@app.route('/payments')
@login_required
def my_payments():
    user = db.session.get(User, session['uid'])
    items = Payment.query.filter_by(user_id=user.id).order_by(Payment.id.desc()).all()
    return render_template('payments.html', items=items)

@app.route('/approve/<int:pid>')
@login_required
def approve(pid):
    user = db.session.get(User, session['uid'])
    p = Payment.query.filter_by(id=pid, user_id=user.id).first_or_404()
    p.status = 'Approved'
    db.session.commit()
    flash('Payment approved.', 'success')
    return redirect(url_for('my_payments'))

@app.route('/delete/<int:pid>')
@login_required
def delete_payment(pid):
    user = db.session.get(User, session['uid'])
    p = Payment.query.filter_by(id=pid, user_id=user.id).first_or_404()
    if p.screenshot:
        file_path = UPLOAD_FOLDER / p.screenshot
        try:
            if file_path.exists():
                file_path.unlink()
        except Exception:
            pass
    db.session.delete(p)
    db.session.commit()
    flash('Payment deleted.', 'info')
    return redirect(url_for('my_payments'))

# ---------------- Short Payment Links (per user) ----------------
@app.route('/links', methods=['GET','POST'])
@login_required
def links():
    user = db.session.get(User, session['uid'])
    if request.method == 'POST':
        name   = request.form.get('name','').strip()
        mobile = request.form.get('mobile','').strip()
        try:
            amount = float(request.form.get('amount') or 0)
        except Exception:
            amount = 0.0
        expiry_hours = request.form.get('expiry_hours')  # optional
        expires_at = None
        if expiry_hours:
            try:
                hours = int(expiry_hours)
                expires_at = datetime.utcnow() + timedelta(hours=hours)
            except Exception:
                expires_at = None

        code = make_code()
        pl = PayLink(user_id=user.id, code=code, name=name, mobile=mobile, amount=amount, expires_at=expires_at)
        db.session.add(pl)
        db.session.commit()
        flash('Short link created!', 'success')
        return redirect(url_for('links'))

    items = PayLink.query.filter_by(user_id=user.id).order_by(PayLink.id.desc()).all()
    return render_template('links.html', items=items)

# ---------------- Pay by short code ----------------
@app.route('/pay/<code>', methods=['GET','POST'])
def pay_code(code):
    pl = PayLink.query.filter_by(code=code).first_or_404()
    if pl.expires_at and datetime.utcnow() > pl.expires_at:
        return render_template('expired.html'), 410

    user = db.session.get(User, pl.user_id)
    settings = user.settings
    success = ''
    if request.method == 'POST':
        # allow overriding prefilled if customer types different
        try:
            amount = float(request.form.get('amount') or pl.amount or 0)
        except Exception:
            amount = pl.amount or 0.0
        name = request.form.get('name', pl.name or '').strip()
        mobile = request.form.get('mobile', pl.mobile or '').strip()
        screenshot = request.files.get('screenshot')

        if amount <= 0:
            success = '❌ Invalid amount.'
        elif not screenshot:
            success = '❌ Please upload screenshot.'
        else:
            filename = secure_filename(f"{int(time.time())}_{screenshot.filename}")
            filepath = UPLOAD_FOLDER / filename
            # save uploaded file
            screenshot.save(str(filepath))
            pay = Payment(user_id=user.id, name=name, mobile=mobile, amount=amount,
                          screenshot=filename, status='Pending')
            db.session.add(pay)
            db.session.commit()
            success = f"✅ ₹{amount:.2f} payment submitted successfully. Awaiting approval."

    return render_template('public_page.html',
                           settings=settings, user=user, success=success,
                           preset={'name': pl.name, 'mobile': pl.mobile, 'amount': pl.amount},
                           short_code=pl.code)

# ---------------- Public page for each user ----------------
@app.route('/u/<slug>', methods=['GET','POST'])
def public_page(slug):
    user = User.query.filter_by(slug=slug).first_or_404()
    settings = user.settings
    success = ''
    if request.method == 'POST':
        try:
            amount = float(request.form.get('amount') or 0)
        except Exception:
            amount = 0.0
        name = request.form.get('name','').strip()
        mobile = request.form.get('mobile','').strip()
        screenshot = request.files.get('screenshot')

        if amount <= 0:
            success = '❌ Invalid amount.'
        elif not screenshot:
            success = '❌ Please upload screenshot.'
        else:
            filename = secure_filename(f"{int(time.time())}_{screenshot.filename}")
            filepath = UPLOAD_FOLDER / filename
            screenshot.save(str(filepath))
            pay = Payment(user_id=user.id, name=name, mobile=mobile, amount=amount,
                          screenshot=filename, status='Pending')
            db.session.add(pay)
            db.session.commit()
            success = f"✅ ₹{amount:.2f} payment submitted successfully. Awaiting approval."

    return render_template('public_page.html', settings=settings, user=user, success=success, preset=None, short_code=None)

# ---------------- Super Admin ----------------
@app.route('/superadmin')
@role_required('superadmin')
def superadmin():
    users = User.query.order_by(User.id.desc()).all()
    payments = Payment.query.order_by(Payment.id.desc()).all()
    return render_template('superadmin.html', users=users, payments=payments)

# ---------------- Serve uploaded files ----------------
@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# ---------------- Root ----------------
@app.route('/')
def home():
    if 'uid' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

# ---------------- Keep-alive (optional) ----------------
def keep_alive():
    url = os.environ.get("RENDER_URL")
    if not url:
        return
    while True:
        try:
            requests.get(url, timeout=10)
        except Exception as e:
            print("Keep-alive failed:", e)
        time.sleep(49)

# Start keep-alive thread if explicitly requested via env var
if os.environ.get("START_KEEP_ALIVE", "0") == "1":
    threading.Thread(target=keep_alive, daemon=True).start()

# ---------------- Run ----------------
if __name__ == '__main__':
    # when running locally directly, start keep-alive (if requested) and run flask dev server
    if os.environ.get("START_KEEP_ALIVE", "0") == "1":
        threading.Thread(target=keep_alive, daemon=True).start()

    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=os.environ.get("FLASK_DEBUG", "0") == "1")
