# Importing the Data base from the app.py file
from extensions import db
from datetime import datetime


class User(db.Model):

    __tablename__ = 'users'

    email = db.Column( db.String(200), nullable = False, primary_key = True)
    username = db.Column( db.String(200), nullable = False) 
    phone = db.Column(db.String(200), nullable = False)
    password = db.Column(db.String(128), nullable = False)
    

    patients = db.relationship('Patient',back_populates = 'user')


    def to_dict(self):
        return {
            'e-mail':self.email,
            'phone': self.phone
        }





class Patient(db.Model):
    __tablename__ = 'patients'

    cpf = db.Column(db.String(11), primary_key = True , nullable = False)
    name = db.Column(db.String(100), nullable = False)
    age = db.Column(db.Integer, nullable = False)
    modality = db.Column(db.String(100), nullable = True)
    service = db.Column(db.String(100), nullable = True)
    gender = db.Column(db.String(100), nullable = True)
    status = db.Column(db.String(100),nullable = True)
    income = db.Column(db.Float, nullable = True)


    user_email  = db.Column(db.String(200), db.ForeignKey('users.email'), nullable = False)

    user = db.relationship('User',back_populates = 'patients')
    
    # Getting data of appointments and data of patients creations inside of the database
    schedule_date = db.Column(db.Date, nullable = True)
    created_at = db.Column(db.DateTime,default = datetime.utcnow , nullable = False)


    def to_dict(self):
        return {
            'cpf':self.cpf,
            'name':self.name,
            'age':self.age,
            'modality': self.modality,
            'service' : self.service,
            'gender': self.gender,
            'status': self.status,
            'income': self.income,
            'schedule_date': self.schedule_date,
            'created_at': self.created_at
        }
    

