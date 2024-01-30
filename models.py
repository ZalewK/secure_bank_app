from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
import bcrypt
from datetime import datetime, timedelta

db = SQLAlchemy()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(50), nullable=False)
    card_number = db.Column(db.String(16), nullable=False)
    id_number = db.Column(db.String(10), nullable=False)
    account_number = db.Column(db.String(16), unique=True, nullable=False)
    balance = db.Column(db.Integer, default=0.0)
    transfers = db.relationship('Transaction', backref='user', lazy=True)
    last_login = db.Column(db.DateTime, default=datetime.now() + timedelta(hours=1))

    def set_password(self, password):
        self.password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).hex()

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), bytes.fromhex(self.password))
    
    def update_last_login(self):
        self.last_login = datetime.now() + timedelta(hours=1)
        db.session.commit()

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Float, nullable=False)
    title = db.Column(db.String(100), nullable=False)
    recipient_account_number = db.Column(db.String(50), nullable=False)
    sender_account_number = db.Column(db.String(50), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
