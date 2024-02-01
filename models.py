import random
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
import bcrypt
from datetime import datetime, timedelta

db = SQLAlchemy()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(60), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=True)
    card_number = db.Column(db.String(16), nullable=False)
    id_number = db.Column(db.String(10), nullable=False)
    account_number = db.Column(db.String(16), unique=True, nullable=False)
    balance = db.Column(db.Integer, default=0.0)
    last_login = db.Column(db.DateTime, default=datetime.now())

    def set_password(self, password):
        self.password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).hex()
        User.generate_password_combinations(password, user_id=self.id)
        db.session.commit()

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), bytes.fromhex(self.password))
    
    def update_last_login(self):
        self.last_login = datetime.now()
        db.session.commit()

    def generate_password_combinations(password, user_id):
        password_length = len(password)
        combination_length = 5
        num_combinations = 10

        for _ in range(num_combinations):
            combination_indexes = random.sample(range(1, password_length + 1), combination_length)
            combination_indexes.sort()

            combination = "".join([password[i - 1] for i in combination_indexes])
            print(combination.encode("utf-8"))
            hashed_combination = bcrypt.hashpw(combination.encode("utf-8"), bcrypt.gensalt()).hex()
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
    combination = db.Column(db.String(60), nullable=False)
    indexes = db.Column(db.String(60), nullable=False)
    activation_date = db.Column(db.DateTime, default=None)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def activate_combination(self):
        self.activation_date = datetime.now()

    def is_combination_active(id):
        combination = Combination.query.get(id)
        if combination.activation_date is not None:
            if combination.activation_date > datetime.now() - timedelta(minutes=2):   
                return True
            else:
                combination.activation_date = None
                db.session.commit()
                return False
        else:
            return False

    def get_random_combination(username):
        user = User.query.filter_by(username=username).first()

        if user:
            combinations = Combination.query.filter_by(user_id=user.id).all()

        active_combinations = [combination for combination in combinations if Combination.is_combination_active(combination.id)]

        if len(active_combinations) > 0:
            return active_combinations[0]

        random_combination = random.choice(combinations)
        random_combination.activation_date = datetime.now()
        db.session.commit()

        return random_combination
    
    def check_combination(id, password):
        combination = Combination.query.get(id)

        if not Combination.is_combination_active(id):
            return False

        if bcrypt.checkpw(password.encode("utf-8"), bytes.fromhex(combination.combination)):
            combination.activation_date = None
            db.session.commit()
            return True
        else:
            return False

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Float, nullable=False)
    title = db.Column(db.String(100), nullable=False)
    recipient_account_number = db.Column(db.String(50), nullable=False)
    sender_account_number = db.Column(db.String(50), nullable=False)
    transaction_date = db.Column(db.DateTime, default=None, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def make_transaction(amount, title, recipient_account_number, sender_account_number, current_user_id):
        transaction = Transaction(amount=amount, 
                                  title=title, 
                                  recipient_account_number=recipient_account_number, 
                                  sender_account_number=sender_account_number, 
                                  transaction_date=datetime.now(), 
                                  user_id=current_user_id)
        db.session.add(transaction)
        db.session.commit()

class Attempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(60), nullable=False)
    login_time = db.Column(db.DateTime, default=datetime.now())
    is_successful = db.Column(db.Boolean, nullable=False)
    is_old = db.Column(db.Boolean, default=False, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def mark_login_attempt(user_id, ip_address, is_successful):
        login_time = datetime.now()
        login_attempt = Attempt(user_id=user_id, ip_address=ip_address, login_time=login_time, is_successful=is_successful)
        db.session.add(login_attempt)
        db.session.commit()

    def count_failed_attempts(user_id, ip_address):
        start_time = datetime.now() - timedelta(minutes=5)

        failed_attempts = Attempt.query.filter(
            Attempt.user_id == user_id,
            Attempt.ip_address == ip_address,
            Attempt.is_successful.is_(False),
            Attempt.is_old.is_(False),
            Attempt.login_time >= start_time
        )
        print("Nieudanych:", failed_attempts.count())

        return failed_attempts.count() > 5
    
    def mark_attempts_as_old(user_id, ip_address):
        login_attempts = Attempt.query.filter(
            Attempt.user_id == user_id,
            Attempt.ip_address == ip_address,
            Attempt.is_old.is_(False)
        )

        for login_attempt in login_attempts:
            login_attempt.is_old = True
            db.session.add(login_attempt)

        db.session.commit()