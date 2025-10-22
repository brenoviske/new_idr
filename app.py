#============================
# IMPORTS
#============================
from flask import Flask, jsonify, request, render_template, redirect, url_for, session
from sqlalchemy import or_
from sklearn.linear_model import LinearRegression
from datetime import datetime
import numpy as np
from werkzeug.security import generate_password_hash, check_password_hash
from collections import Counter
from functools import wraps
from dotenv import load_dotenv
import os

from models import Patient, User
from extensions import db

load_dotenv()

DB_USER = os.environ.get('DB_USER')
DB_PASS = os.environ.get('DB_PASSWORD')
DB_HOST = os.environ.get('DB_HOST')
DB_NAME = os.environ.get('DB_NAME')
SECRET_KEY = os.environ.get("SECRET_KEY", 'dev_secret_key')

#============================
# INIT FLASK
#============================
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+pymysql://{DB_USER}:{DB_PASS}@{DB_HOST}/{DB_NAME}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = SECRET_KEY

db.init_app(app)

#============================
# LOGIN REQUIRED DECORATOR
#============================
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_email' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

#============================
# LOGIN ROUTE
#============================
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

#============================
# SIGNUP ROUTE
#============================
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        data = request.form.to_dict()

        # Capturando apenas os campos necessários
        email = data.get('email', '').strip().lower()
        full_name = data.get('full_name', '').strip()
        username = data.get('username', '').strip()
        phone = data.get('phone', '').strip()
        password = data.get('password', '')

        # Validações básicas
        if not email or not full_name or not username or not phone or not password:
            return jsonify({'status': 'error', 'message': 'Todos os campos são obrigatórios.'}), 400
        if len(password) < 6:
            return jsonify({'status': 'error', 'message': 'A senha precisa ter pelo menos 6 caracteres.'}), 400

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            return jsonify({'status': 'error', 'message': 'Usuário já existente'}), 409

        try:
            # Criando o usuário somente com os campos corretos
            new_user = User(
                email=email,
                full_name=full_name,
                username=username,
                phone=phone,
                password=generate_password_hash(password)
            )
            db.session.add(new_user)
            db.session.commit()
            return jsonify({'status': 'success'})
        except Exception as e:
            db.session.rollback()
            print(f'Error creating user: {e}')
            return jsonify({'status': 'error', 'message': 'Erro ao criar usuário'}), 500

    return render_template('signup.html')

#============================
# FORGOT PASSWORD
#============================
@app.route('/forgotpass', methods=['GET', 'POST'])
def forgotpass():
    if request.method == 'POST':
        user_email = request.form.get('email')
        existing_user = User.query.filter_by(email=user_email).first()
        if not existing_user:
            return jsonify({'status':'error','message': 'E-mail ou telefone não registrado'})
        return jsonify({'status':'success'})
    return render_template('forgotpass.html')

#============================
# HOMEPAGE
#============================
@app.route("/main", methods=['GET','POST'])
@login_required
def homepage():
    user_email = session.get('user_email')
    user = User.query.filter_by(email=user_email).first()
    username = user.username
    patients = Patient.query.filter_by(user_email=user_email).all()
    incomes = [pt.income for pt in patients if pt.income is not None]
    num_patients = len(patients)

    surgeries = consults = max_revenue = min_revenue = mean_revenue = total_revenue = month_revenue = 0

    if num_patients > 0:
        surgeries = Patient.query.filter(
            Patient.user_email==user_email,
            or_(Patient.modality.ilike('%Cirurgia%'), Patient.modality.ilike('%Procedimento%'))
        ).count()
        consults = Patient.query.filter(
            Patient.user_email==user_email,
            or_(Patient.modality.ilike('%Consulta%'), Patient.modality.ilike('%Atendimento%'))
        ).count()

        max_revenue = max(incomes)
        min_revenue = min(incomes)
        total_revenue = sum(incomes)
        mean_revenue = total_revenue / num_patients

        now = datetime.utcnow()
        month_revenue = (
            db.session.query(db.func.sum(Patient.income))
            .filter(Patient.user_email==user_email)
            .filter(db.extract('year', Patient.created_at)==now.year)
            .filter(db.extract('month', Patient.created_at)==now.month)
        ).scalar() or 0

    return render_template('main.html', patients=patients, num_patients=num_patients,
                           surgeries=surgeries, consults=consults,
                           max_revenue=max_revenue, min_revenue=min_revenue,
                           total_revenue=total_revenue, mean_revenue=mean_revenue,
                           month_revenue=month_revenue, username=username)

#============================
# ADD PATIENT
#============================
@app.route("/add_patient", methods=['POST','GET'])
@login_required
def add_patient():
    user_email = session.get('user_email')
    if request.method == 'POST':
        form_data = request.form.to_dict()
        cpf = form_data.get('cpf')
        name = form_data.get('name')

        if not cpf or len(cpf) != 11:
            return jsonify({'status':'error','message':'CPF inválido (precisa ter 11 dígitos)'})

        if Patient.query.filter_by(cpf=cpf, user_email=user_email).first() or \
           Patient.query.filter_by(name=name, user_email=user_email).first():
            return jsonify({'status':'error','message': 'Paciente já existe'})

        try:
            schedule_date_str = form_data.pop("schedule_date", None)
            schedule_date = datetime.strptime(schedule_date_str, '%Y-%m-%d').date() if schedule_date_str else None
            new_patient = Patient(**form_data, schedule_date=schedule_date, user_email=user_email)
            db.session.add(new_patient)
            db.session.commit()
            return jsonify({'status': 'success'})
        except Exception as e:
            db.session.rollback()
            print(f'Error adding patient: {e}')
            return jsonify({'status':'error','message':'Erro ao adicionar paciente'})
    return render_template('main.html')

#============================
# SEARCH PATIENT
#============================
@app.route('/search_patient', methods=['GET'])
@login_required
def search_patient():
    user_email = session.get('user_email')
    query = request.args.get('q','').strip()
    patients_query = Patient.query.filter_by(user_email=user_email)
    if query:
        patients_query = patients_query.filter(
            or_(Patient.cpf.ilike(f'%{query}%'), Patient.name.ilike(f'%{query}%'))
        )
    patients = patients_query.all()
    return jsonify([{
        'cpf': pt.cpf,
        'name': pt.name,
        'modality': pt.modality,
        'status': pt.status,
        'age': pt.age,
        'service': pt.service,
        'income': pt.income,
        'gender': pt.gender,
        'schedule_date': pt.schedule_date.isoformat() if pt.schedule_date else None,
        'created_at': pt.created_at.isoformat() if pt.created_at else None
    } for pt in patients])

#============================
# UPDATE PATIENT
#============================
@app.route('/update/<cpf>', methods=['POST','GET'])
@login_required
def update(cpf):
    user_email = session.get('user_email')
    patient = Patient.query.filter_by(cpf=cpf, user_email=user_email).first_or_404()
    if request.method == 'POST':
        data = request.form.to_dict()
        try:
            for key, value in data.items():
                if hasattr(patient, key):
                    setattr(patient, key, value)
            db.session.commit()
            return redirect(url_for('homepage'))
        except Exception as e:
            db.session.rollback()
            return f'Erro ao atualizar paciente: {e}'
    return render_template('main.html', data=patient.to_dict(), patient=patient)

#============================
# DELETE PATIENT
#============================
@app.route("/delete/<cpf>", methods=['POST','GET'])
@login_required
def delete(cpf):
    user_email = session.get('user_email')
    try:
        patient = Patient.query.filter_by(cpf=cpf, user_email=user_email).first_or_404()
        db.session.delete(patient)
        db.session.commit()
        return jsonify({'status':'success'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'status':'error','message':'Erro ao deletar paciente'}), 500

#============================
# OTHER API ROUTES
#============================
@app.route('/api/age-distribution')
@login_required
def ageDistribution():
    user_email = session.get('user_email')
    ages = [pt.age for pt in Patient.query.filter_by(user_email=user_email).all() if pt.age is not None]
    bins = {'0-18':0, '19-35':0, '36-50':0, '51-65':0, '66+':0}
    for age in ages:
        if age <= 18: bins['0-18']+=1
        elif age <= 35: bins['19-35']+=1
        elif age <= 50: bins['36-50']+=1
        elif age <= 65: bins['51-65']+=1
        else: bins['66+']+=1
    return jsonify({'labels': list(bins.keys()), 'values': list(bins.values())})

@app.route('/api/status-distribution')
@login_required
def statusRelation():
    user_email = session.get('user_email')
    patients = Patient.query.filter_by(user_email=user_email).all()
    confirmed = sum(1 for pt in patients if pt.status.lower()=='confirmado')
    standby = sum(1 for pt in patients if pt.status.lower()=='pendente')
    return jsonify({'labels':['Confirmado','Pendente'], 'values':[confirmed, standby]})

@app.route('/api/gender-distribution')
@login_required
def genderDistribution():
    user_email = session.get('user_email')
    women = sum(1 for pt in Patient.query.filter_by(user_email=user_email).all() if pt.gender.lower()=='feminino')
    men = sum(1 for pt in Patient.query.filter_by(user_email=user_email).all() if pt.gender.lower()=='masculino')
    others = sum(1 for pt in Patient.query.filter_by(user_email = user_email).all() if pt.gender.lower() == 'outro')
    return jsonify({'labels':['Feminino','Masculino'],'values':[women,men]})

#=================
# MONTHLY REVENUE 
#=================

@app.route("/api/monthly-revenue")
@login_required
def monthly_revenue():

    user_email = session.get('user_email') # <- Gathering the user email to adjust the revenue outcome per user
    now = datetime.utcnow()
    month_labels = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'] # Making the 
    monthly_revenues = []


    for month in range(1,13,1):
        total = (
            db.session.query(db.func.sum(Patient.income))
            .filter(Patient.user_email == user_email)
            .filter(db.extract('year', Patient.created_at) == now.year)
            .filter(db.extract('month',Patient.created_at) == month)
        ).scalar() or 0

        monthly_revenues.append( float(total))

    return jsonify({'labels': month_labels,
                    'values':monthly_revenues,
    })

#==========================
# AI PREDICTION OUTCOMES
#==========================

@app.route('/api/current-predicted-revenue')
@login_required
def current_predicted_revenue():
    
    user_email = session.get('user_email')
    now = datetime.utcnow()
    current_month = now.month

    current_revenue = (
        db.session.query(db.func.sum(Patient.income))
        .filter(Patient.user_email == user_email)
        .filter(db.extract('year',Patient.created_at) == now.year)
        .filter(db.extract('month',Patient.created_at) == current_month)
    ).scalar() or 0

    current_revenue = float(current_revenue)

    # Prepare data for prediction ( train on past months )

    past_months = []
    revenues = []

    for month in range(1, current_month+1 ):
        
        total = (
            db.session.query(db.func.sum(Patient.income))
            .filter(Patient.user_email == user_email)
            .filter(db.extract('year', Patient.created_at) == now.year)
            .filter(db.extract('month', Patient.created_at) == month)
        ).scalar() or 0

        past_months.append(month)
        revenues.append(float(total))

    if len(past_months) > 1:
        X = np.array(past_months).reshape(-1,1)
        y = np.array(revenues)
        model = LinearRegression().fit( X , y)
        predicted_revenue = float(model.predict([[current_month +1]]))

    else:
        # Not enough data for prediction
        predicted_revenue = 0.0
    

    
    # Predict the outcome from the next month analyzing the data already avaiable

    return jsonify({
        'labels': ['Mês Atual','Próximo mês(Previsão Financeira)'],
        'values': [current_revenue, predicted_revenue]
    })

#============================
# LOGOUT
#============================
@app.route('/logout')
@login_required
def logout():
    session.clear()
    return redirect(url_for('login'))

#============================
# RUN APP
#============================
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)