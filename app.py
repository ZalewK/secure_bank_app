from datetime import timedelta
import os
from users import users_data
from time import sleep
from flask import Flask, render_template, request, redirect, session, url_for, flash
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from forms import EntryForm, LoginForm, TransferForm, ChangePasswordForm
from models import db, User, Transaction
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///bank.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get("FLASK_SECRET_KEY", "default key")
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=20)
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

bcrypt = Bcrypt(app)
db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'index'
csrf = CSRFProtect(app)
login_attempts_memory = {}

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def create_sample_users():
    for user_info in users_data:
        username = user_info['username']
        password = user_info['password']
        card_number = user_info['card_number']
        id_number = user_info['id_number']
        account_number = user_info['account_number']
        balance = user_info['balance']

        user = User.query.filter_by(username=username).first()

        if not user:
            new_user = User(username=username, card_number=card_number, id_number=id_number, account_number=account_number, balance=balance)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()

@app.before_request
def check_session():
    if session.get("user_id", None) is None:
        return
    if session.get("ip_address", None) != request.remote_addr:
        session.pop("user_id", None)
        logout_user()
        return redirect(url_for("index"))

@app.route('/', methods=['GET', 'POST'])
def index():
    form = EntryForm()
    
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    if form.validate_on_submit():
        username = form.username.data
        session['username'] = username
        return redirect(url_for('login'))
    
    return render_template('index.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if 'username' not in session:
        return redirect(url_for('index'))
    
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    if form.validate_on_submit():
        if form.honeypot.data:
            flash('Wystąpił błąd.', 'error')
            sleep(3)
            return redirect(url_for('login'))
        else:
            print("git")
            username = session.get('username')
            password = form.password.data

            if username not in login_attempts_memory:
                login_attempts_memory[username] = 0

            user = User.query.filter_by(username=username).first()

            if user and user.check_password(password):
                login_user(user)
                user.update_last_login()
                session.pop('username', None)
                flash('Pomyślnie zalogowano.', 'success')
                return redirect(url_for('home'))
            else:
                if login_attempts_memory[username] > 5:
                    sleep(10)
                    flash('Zbyt wiele nieudanych prób.', 'error')
                    login_attempts_memory[username] = 0
                    return redirect(url_for('index'))
                flash('Nieprawidłowe dane logowania.', 'error')
                login_attempts_memory[username] += 1
                sleep(2)
    sleep(1)
    return render_template('login.html', form=form)

@app.route('/home', methods=['GET', 'POST'])
@login_required
def home(): 
    return render_template('home.html', user=current_user)

@app.route('/make_transfer', methods=['GET', 'POST'])
@login_required
def make_transfer():
    form = TransferForm()

    if form.validate_on_submit():
        sender_account_number = current_user.account_number
        recipient_account_number = form.recipient_account_number.data
        amount = form.amount.data
        title = form.title.data 

        if sender_account_number == recipient_account_number:
            flash('Nie można wysłać przelewu do własnego konta.', 'error')
            return redirect(url_for('make_transfer'))
        
        if amount <= 0:
            flash('Kwota przelewu nie może być ujemna.', 'error')
            return redirect(url_for('make_transfer'))

        recipient_user = User.query.filter_by(account_number=recipient_account_number).first()

        if recipient_user:
            if current_user.balance >= amount:
                current_user.balance -= amount
                recipient_user.balance += amount

                transaction = Transaction(amount=amount, title=title, recipient_account_number=recipient_user.account_number, sender_account_number=sender_account_number, user=current_user)
                db.session.add(transaction)
                db.session.commit()

                flash('Przelew wykonany pomyślnie.', 'success')
            else:
                flash('Niewystarczające saldo na koncie.', 'error')
        else:
            flash('Użytkownik o podanym numerze konta nie istnieje.', 'error')

    return render_template('make_transfer.html', form=form)

@app.route('/view_sensitive_data')
@login_required
def view_sensitive_data():
    return render_template('view_sensitive_data.html', user=current_user)

@app.route('/view_transaction_list')
@login_required
def view_transaction_list():
    with app.app_context():
        out_trans = Transaction.query.filter_by(user_id=current_user.id).all()
        in_trans = Transaction.query.filter_by(recipient_account_number=current_user.account_number).all()
    return render_template('view_transaction_list.html', out_trans=out_trans, in_trans=in_trans)
    
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()

    if form.validate_on_submit():
        
        if not current_user.check_password(form.current_password.data):
            flash('Błędne aktualne hasło.', 'error')
            return redirect(url_for('change_password'))
        
        if form.current_password.data == form.new_password.data:
            flash('Nowe hasło musi być inne niż obecne.', 'error')
            return redirect(url_for('change_password'))

        current_user.set_password(form.new_password.data)
        db.session.commit()

        flash('Hasło zostało zmienione.', 'success')

    return render_template('change_password.html', form=form)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_sample_users()
    app.run(host='0.0.0.0', port=5000)
