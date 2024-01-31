import random
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
import bcrypt
from datetime import datetime, timedelta

db = SQLAlchemy()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(50), nullable=True)
    card_number = db.Column(db.String(16), nullable=False)
    id_number = db.Column(db.String(10), nullable=False)
    account_number = db.Column(db.String(16), unique=True, nullable=False)
    balance = db.Column(db.Integer, default=0.0)
    transfers = db.relationship('Transaction', backref='user', lazy=True)
    password_combinations = db.relationship('Combination', backref='user', lazy=True)
    last_login = db.Column(db.DateTime, default=datetime.now())

    def set_password(self, password):
        salt = bcrypt.gensalt()
        self.password = bcrypt.hashpw(password.encode("utf-8"), salt).hex()
        User.generate_password_combinations(password, salt, user_id=self.id)
        db.session.commit()

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), bytes.fromhex(self.password))
    
    def update_last_login(self):
        self.last_login = datetime.now() + timedelta(hours=1)
        db.session.commit()

    def generate_password_combinations(password, salt, user_id):
        password_length = len(password)
        combination_length = 5
        num_combinations = 10

        for _ in range(num_combinations):
            combination_indexes = random.sample(range(1, password_length + 1), combination_length)
            combination_indexes.sort()

            combination = "".join([password[i - 1] for i in combination_indexes])
            print(combination.encode("utf-8"))
            hashed_combination = bcrypt.hashpw(combination.encode("utf-8"), salt).hex()
            print(hashed_combination)

            used_indexes = ",".join(map(str, combination_indexes))
            print(used_indexes)

            password_combination = Combination(combination=hashed_combination, indexes=used_indexes, user_id=user_id)
            db.session.add(password_combination)
        
        db.session.commit()
    
    def delete_password_combinations(self):
        existing_combinations = Combination.query.filter_by(user_id=self.id).all()

        for combination in existing_combinations:
            db.session.delete(combination)

        db.session.commit()
    
    def change_password(self, password):
        self.delete_password_combinations()
        self.set_password(password)
        db.session.commit()


class Combination(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    combination = db.Column(db.String(55), nullable=False)
    indexes = db.Column(db.String(55), nullable=False)
    activation_date = db.Column(db.DateTime, default=None)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def activate_combination(self):
        self.activation_date = datetime.now()

    def get_random_combination(username):
        user = User.query.filter_by(username=username).first()

        if user:
            combinations = Combination.query.filter_by(user_id=user.id).all()

        #active_credentials = [combination for combination in combinations if Combination.is_password_combination_active(combination.id)]

        #if len(active_credentials) > 0:
            #return active_credentials[0]

        random_combination = random.choice(combinations)
        random_combination.activation_date = datetime.now()
        db.session.commit()

        return random_combination
    
    #get_combination_indexes(combination):
    
    def check_combination(id, password):
        combination = Combination.query.where(Combination.id == id).first()
        print(combination)
        print(password)
        print(password.encode('utf-8'))
        print(bytes.fromhex(combination.combination))

        #is_combination_active = Combination.is_password_combination_active(combination_id)

        #if not is_combination_active:
        #    return False

        if bcrypt.checkpw(password.encode("utf-8"), bytes.fromhex(combination.combination)):
            combination.activation_date = None
            
            db.session.commit()
            return True
        else:
            print('nie zgadzaja sie')
            return False

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Float, nullable=False)
    title = db.Column(db.String(100), nullable=False)
    recipient_account_number = db.Column(db.String(50), nullable=False)
    sender_account_number = db.Column(db.String(50), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
