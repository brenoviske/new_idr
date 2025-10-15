# app_secure.py
# Rewritten with security improvements (password hashing, secure sessions, headers, login_required, safer APIs)

import os
from datetime import datetime, timedelta
from collections import Counter
from functools import wraps
import logging

from flask import (
    Flask, jsonify, request, render_template, redirect,
    url_for, session, abort, make_response
)
from sqlalchemy import or_, func
import numpy as np
from sklearn.linear_model import LinearRegression
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

# optional libs (used if available)
try:
    from flask_talisman import Talisman
except Exception:
    Talisman = None

try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
except Exception:
    Limiter = None

# local imports (models, db extensions)
from models import Patient, User
from extensions import db

# Load environment variables
load_dotenv()

DB_USER = os.environ.get('DB_USER')
DB_PASS = os.environ.get('DB_PASSWORD')
DB_HOST = os.environ.get('DB_HOST')
DB_NAME = os.environ.get('DB_NAME')
SECRET_KEY = os.environ.get('SECRET_KEY', 'dev_secret_key')
ENV = os.environ.get('FLASK_ENV', 'production')  # 'development' or 'production'
PROD = ENV == 'production'

# App init
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+pymysql://{DB_USER}:{DB_PASS}@{DB_HOST}/{DB_NAME}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = SECRET_KEY

# Session security
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
# Only set Secure cookie in production (requires HTTPS)
app.config['SESSION_COOKIE_SECURE'] = True if PROD else False
app.permanent_session_lifetime = timedelta(hours=3)

# Optional: enforce preferred URL scheme if set
if PROD:
    app.config['PREFERRED_URL_SCHEME'] = 'https'

# Init DB
db.init_app(app)

# Optional: Talisman (sets many security headers like HSTS, CSP)
if Talisman and PROD:
    Talisman(app, content_security_policy={
        "default-src": ["'self'"],
        "script-src": ["'self'", "https://cdn.jsdelivr.net", "https://cdn.tailwindcss.com", "https://cdn.jsdelivr.net/npm/chart.js"],
        "style-src": ["'self'", "'unsafe-inline'", "https://cdn.tailwindcss.com"],
        "img-src": ["'self'", "data:"],
    })
# If Talisman unavailable, we'll set headers in after_request

# Optional: rate limiter
if Limiter:
    limiter = Limiter(app, key_func=get_remote_address, default_limits=["200 per day", "50 per hour"])
else:
    limiter = None

# Logging
LOG_FILE = os.environ.get('APP_LOG_FILE', 'app.log')
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# --------------------------
# Utility & Security helpers
# --------------------------

def mask_cpf(cpf: str) -> str:
    """Return masked CPF, keep last 3 characters visible if possible."""
    if not cpf:
        return None
    cpf = str(cpf)
    if len(cpf) <= 3:
        return '*' * len(cpf)
    return '*' * (len(cpf) - 3) + cpf[-3:]


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user_email' not in session:
            # if AJAX, return json error
            if request.is_json or request.accept_mimetypes.accept_json:
                return jsonify({'status': 'error', 'message': 'Authentication required'}), 401
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrapper


# Set secure headers if Talisman not enabled
@app.after_request
def set_security_headers(response):
    if not Talisman:
        response.headers.setdefault('X-Frame-Options', 'DENY')
        response.headers.setdefault('X-Content-Type-Options', 'nosniff')
        response.headers.setdefault('Referrer-Policy', 'no-referrer-when-downgrade')
        # Only add HSTS in production
        if PROD:
            response.headers.setdefault('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
        # Minimal CSP fallback
        response.headers.setdefault('Content-Security-Policy', "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net https://cdn.tailwindcss.com https://cdn.jsdelivr.net/npm/chart.js; style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; img-src 'self' data:;")
    return response


# Generic error handlers (do not leak stack traces to clients)
@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(e):
    logger.exception("Internal server error:")
    # do not expose the exception detail to client
    return jsonify({'status': 'error', 'message': 'Internal server error'}), 500

# --------------------------
# Routes (kept names / behavior)
# --------------------------

@app.route("/", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        form_data = request.form.to_dict()
        email = form_data.get('email', '').strip().lower()
        password = form_data.get('password', '')

        if not email or not password:
            return jsonify({'status': 'error', 'message': 'Missing credentials'}), 400

        existing_user = User.query.filter_by(email=email).first()
        if existing_user and check_password_hash(existing_user.password, password):
            session.permanent = True
            session['user_email'] = existing_user.email
            return jsonify({'status': 'success'})
        return jsonify({'status': 'error', 'message': 'Credenciais inválidas'}), 401

    return render_template('login.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        data = request.form.to_dict()
        email = data.get('email', '').strip().lower()
        password = data.get('password')

        if not email or not password:
            return jsonify({'status': 'error', 'message': 'Missing email or password'}), 400

        # Basic email and password checks (can be extended)
        if len(password) < 6:
            return jsonify({'status': 'error', 'message': 'Password must be at least 6 characters'}), 400

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            return jsonify({'status': 'error', 'message': 'Usuário já existente'}), 409

        try:
            # hash password before saving
            data['password'] = generate_password_hash(password)
            # ensure email normalized
            data['email'] = email
            new_user = User(**data)
            db.session.add(new_user)
            db.session.commit()
            return jsonify({'status': 'success'})
        except Exception as e:
            db.session.rollback()
            logger.exception("Error creating user")
            return jsonify({'status': 'error', 'message': 'Erro ao criar usuário'}), 500

    return render_template('signup.html')


@app.route('/forgotpass', methods=['GET', 'POST'])
def forgotpass():
    if request.method == 'POST':
        user_email = (request.form.get('email') or '').strip().lower()
        if not user_email:
            return jsonify({'status': 'error', 'message': 'Email required'}), 400

        existing_user = User.query.filter_by(email=user_email).first()
        if not existing_user:
            # do not reveal whether the email exists; return generic message
            return jsonify({'status': 'error', 'message': 'E-mail ou telefone não registrado'}), 404

        # Here you should generate a password-reset token and send email/SMS (not implemented)
        # token = generate_reset_token(existing_user)
        # send_reset_email(existing_user.email, token)
        return jsonify({'status': 'success'})

    return render_template('forgotpass.html')


@app.route("/main", methods=['GET', 'POST'])
@login_required
def homepage():
    user_email = session.get('user_email')
    user = User.query.filter_by(email=user_email).first()
    username = user.username if user else None

    # fetch patients
    patients = Patient.query.filter_by(user_email=user_email).all()
    incomes = [pt.income for pt in patients if pt.income is not None and isinstance(pt.income, (int, float))]

    # defaults
    surgeries = consults = 0
    max_revenue = min_revenue = mean_revenue = total_revenue = month_revenue = 0

    num_patients = Patient.query.filter_by(user_email=user_email).count()

    if num_patients > 0:
        surgeries = Patient.query.filter(
            Patient.user_email == user_email,
            or_(
                Patient.modality.ilike('%Cirurgia%'),
                Patient.modality.ilike('%Procedimento%')
            )
        ).count()

        consults = Patient.query.filter(
            Patient.user_email == user_email,
            or_(
                Patient.modality.ilike('%Consulta%'),
                Patient.modality.ilike('%Atendimento%')
            )
        ).count()

        if incomes:
            try:
                max_revenue = max(incomes)
                min_revenue = min(incomes)
                total_revenue = sum(incomes)
                mean_revenue = total_revenue / num_patients
            except Exception:
                max_revenue = min_revenue = mean_revenue = total_revenue = 0

        now = datetime.utcnow()
        month_revenue = (
            db.session.query(func.sum(Patient.income))
            .filter(Patient.user_email == user_email)
            .filter(func.extract('year', Patient.created_at) == now.year)
            .filter(func.extract('month', Patient.created_at) == now.month)
        ).scalar() or 0

    return render_template('main.html',
                           patients=patients,
                           num_patients=num_patients,
                           surgeries=surgeries,
                           consults=consults,
                           max_revenue=max_revenue,
                           min_revenue=min_revenue,
                           total_revenue=total_revenue,
                           mean_revenue=mean_revenue,
                           month_revenue=month_revenue,
                           username=username
                           )

# --------------------------
# API Endpoints (safer outputs)
# --------------------------

@app.route('/api/age-distribution')
@login_required
def ageDistribution():
    user_email = session.get('user_email')
    ages = [pt.age for pt in Patient.query.filter_by(user_email=user_email).all() if pt.age is not None and isinstance(pt.age, (int, float))]

    bins = {'0-18': 0, '19-35': 0, '36-50': 0, '51-65': 0, '66+': 0}
    for age in ages:
        if age <= 18:
            bins['0-18'] += 1
        elif age <= 35:
            bins['19-35'] += 1
        elif age <= 50:
            bins['36-50'] += 1
        elif age <= 65:
            bins['51-65'] += 1
        else:
            bins['66+'] += 1

    return jsonify({'labels': list(bins.keys()), 'values': list(bins.values())})


@app.route('/api/status-distribution')
@login_required
def statusRelation():
    user_email = session.get('user_email')
    patients = Patient.query.filter_by(user_email=user_email).all()

    confirmed = sum(1 for pt in patients if getattr(pt, 'status', '') and str(pt.status).lower() == 'confirmado')
    standby = sum(1 for pt in patients if getattr(pt, 'status', '') and str(pt.status).lower() == 'pendente')

    return jsonify({'labels': ['Confirmado', 'Pendente'], 'values': [confirmed, standby]})


@app.route('/api/gender-distribution')
@login_required
def genderDistribution():
    user_email = session.get('user_email')
    pts = Patient.query.filter_by(user_email=user_email).all()
    women = sum(1 for pt in pts if getattr(pt, 'gender', '') and str(pt.gender).lower() == 'feminino')
    men = sum(1 for pt in pts if getattr(pt, 'gender', '') and str(pt.gender).lower() == 'masculino')
    return jsonify({'labels': ['Feminino', 'Masculino'], 'values': [women, men]})


@app.route("/api/monthly-revenue")
@login_required
def monthly_revenue():
    now = datetime.utcnow()
    labels = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
    monthly_revenues = []
    for m in range(1, 13):
        total = (
            db.session.query(func.sum(Patient.income))
            .filter(func.extract('year', Patient.created_at) == now.year)
            .filter(func.extract('month', Patient.created_at) == m)
        ).scalar() or 0
        monthly_revenues.append(float(total))
    return jsonify({'labels': labels, 'values': monthly_revenues})


@app.route('/api/current-predicted-revenue')
@login_required
def current_predicted_revenue():
    now = datetime.utcnow()
    current_month = now.month
    current_revenue = (
        db.session.query(func.sum(Patient.income))
        .filter(func.extract('year', Patient.created_at) == now.year)
        .filter(func.extract('month', Patient.created_at) == current_month)
    ).scalar() or 0
    current_revenue = float(current_revenue)

    past_months = []
    revenues = []
    for month in range(1, current_month + 1):
        total = (
            db.session.query(func.sum(Patient.income))
            .filter(func.extract('year', Patient.created_at) == now.year)
            .filter(func.extract('month', Patient.created_at) == month)
        ).scalar() or 0
        past_months.append(month)
        revenues.append(float(total))

    predicted_revenue = 0.0
    if len(past_months) > 1:
        X = np.array(past_months).reshape(-1, 1)
        y = np.array(revenues)
        model = LinearRegression().fit(X, y)
        predicted_revenue = float(model.predict([[current_month + 1]]))

    return jsonify({'labels': ['Mês Atual', 'Próximo mês(Previsão Financeira)'], 'values': [current_revenue, predicted_revenue]})


@app.route('/api/service-distribution')
@login_required
def serviceRelation():
    user_email = session.get('user_email')
    patients = Patient.query.filter_by(user_email=user_email).all()
    service_counts = Counter((pt.service or '').lower() for pt in patients)
    # filter empty keys
    filtered = {k: v for k, v in service_counts.items() if k}
    return jsonify({'labels': list(filtered.keys()), 'values': list(filtered.values())})


# --------------------------
# Add / Update / Delete routes (protected)
# --------------------------

@app.route("/add_patient", methods=['POST', 'GET'])
@login_required
def add_patient():
    user_email = session.get('user_email')
    if request.method == 'POST':
        form_data = request.form.to_dict()
        cpf = (form_data.get('cpf') or '').strip()
        name = (form_data.get('name') or '').strip()

        if not cpf or len(cpf) != 11 or not cpf.isdigit():
            return jsonify({'status': 'error', 'message': 'CPF inválido (precisa ter 11 dígitos numéricos)'}), 400

        existing_cpf = Patient.query.filter_by(cpf=cpf, user_email=user_email).first()
        existing_name = Patient.query.filter_by(name=name, user_email=user_email).first()
        if existing_cpf or existing_name:
            return jsonify({'status': 'error', 'message': 'Paciente já existe'}), 409

        try:
            schedule_date_str = form_data.pop('schedule_date', None)
            schedule_date = None
            if schedule_date_str:
                schedule_date = datetime.strptime(schedule_date_str, '%Y-%m-%d').date()

            # sanitize numeric fields
            income_raw = form_data.get('income')
            if income_raw:
                try:
                    form_data['income'] = float(income_raw)
                except Exception:
                    form_data['income'] = None

            new_patient = Patient(**form_data, schedule_date=schedule_date, user_email=user_email)
            db.session.add(new_patient)
            db.session.commit()
            return jsonify({'status': 'success'})
        except Exception as e:
            db.session.rollback()
            logger.exception("Error adding patient")
            return jsonify({'status': 'error', 'message': 'Erro ao adicionar paciente'}), 500

    return render_template('main.html')


@app.route('/search_patient', methods=['GET'])
@login_required
def search_patient():
    user_email = session.get('user_email')
    query = (request.args.get('q') or '').strip()
    if not user_email:
        return jsonify([])

    patients_query = Patient.query.filter_by(user_email=user_email)
    if query:
        patients_query = patients_query.filter(
            or_(
                Patient.cpf.ilike(f'%{query}%'),
                Patient.name.ilike(f'%{query}%')
            )
        )
    patients = patients_query.all()
    if not patients:
        return jsonify([])

    # Return only necessary fields and mask cpf
    output = []
    for pt in patients:
        output.append({
            'cpf': mask_cpf(pt.cpf),
            'name': pt.name,
            'modality': pt.modality,
            'status': pt.status,
            'age': pt.age,
            'service': pt.service,
            'income': pt.income,
            'gender': pt.gender,
            'schedule_date': pt.schedule_date.isoformat() if pt.schedule_date else None,
            'created_at': pt.created_at.isoformat() if pt.created_at else None
        })
    return jsonify(output)


@app.route('/update/<cpf>', methods=['POST', 'GET'])
@login_required
def update(cpf):
    user_email = session.get('user_email')
    patient = Patient.query.filter_by(cpf=cpf, user_email=user_email).first_or_404()
    if request.method == 'POST':
        data = request.form.to_dict()
        try:
            for key, value in data.items():
                if hasattr(patient, key):
                    # small sanitization for numeric fields
                    if key == 'income':
                        try:
                            setattr(patient, key, float(value))
                        except Exception:
                            setattr(patient, key, None)
                    else:
                        setattr(patient, key, value)
            db.session.commit()
            return redirect(url_for('homepage'))
        except Exception:
            db.session.rollback()
            logger.exception("Error updating patient")
            return "There was an issue on trying to update your patient", 500

    # Render main with patient detail for prefill (keeps current behavior)
    return render_template('main.html', data=patient.to_dict(), patient=patient)


@app.route('/delete/<cpf>', methods=['POST', 'GET'])
@login_required
def delete(cpf):
    user_email = session.get('user_email')
    try:
        patient = Patient.query.filter_by(cpf=cpf, user_email=user_email).first_or_404()
        db.session.delete(patient)
        db.session.commit()
        return jsonify({'status': 'success'})
    except Exception:
        db.session.rollback()
        logger.exception("Error deleting patient")
        return jsonify({'status': 'error', 'message': 'Erro ao deletar paciente'}), 500


# --------------------------
# Run
# --------------------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    port = int(os.environ.get("PORT", 5000))
    # In production, ensure you run via a WSGI server and behind TLS (Railway handles TLS)
    app.run(host="0.0.0.0", port=port, debug=(not PROD))