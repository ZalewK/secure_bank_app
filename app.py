from datetime import timedelta
import math
import os
from users import users_data
from time import sleep
from flask import Flask, render_template, request, redirect, session, url_for, flash
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from forms import EntryForm, LoginForm, TransferForm, ChangePasswordForm
from models import Combination, db, User, Transaction, Attempt
from flask_wtf.csrf import CSRFProtect, CSRFError

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///bank.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get("FLASK_SECRET_KEY", "default key")
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=20)
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'index'
csrf = CSRFProtect(app)

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
            db.session.add(new_user)
            db.session.commit()
            new_user.set_password(password)

def entropy(password):
    char_set = set(password)
    entropy = math.log2(len(char_set) ** len(password))
    return entropy

def validate_ip(ip):
    parts = ip.split(".")

    if len(parts) != 4:
        return False
    
    for part in parts:
        try:
            part_as_int = int(part)
        except ValueError:
            return False
        
        if part_as_int < 0 or part_as_int > 255:
            return False
    
    return True

def handle_logout():
    session.pop("user_id", None)
    logout_user()
    return redirect(url_for("index"))

def check_session():
    if session.get("user_id", None) is None:
        return
    if validate_ip(request.remote_addr):
        if session.get("ip_address", None) != request.remote_addr:
            handle_logout()
    else:
        handle_logout()

@app.route('/', methods=['GET', 'POST'])
def index():
    form = EntryForm()
    
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    if form.validate_on_submit():
        sleep(2)
        if form.honeypot.data:
            flash('Dane są niepoprawne.', 'error')
        else:
            username = form.username.data
            session['username'] = username
            return redirect(url_for('login', username=username))
    
    return render_template('index.html', form=form)

@app.route('/login/<username>', methods=['GET', 'POST'])
def login(username):
    combination = Combination.get_random_combination(username)

    if 'username' not in session:
        return redirect(url_for('index'))
    
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    form = LoginForm()

    if form.validate_on_submit():
        sleep(2)
        if form.honeypot.data:
            flash('Dane są niepoprawne.', 'error') 
        else:
            password = form.password.data
            user = User.query.filter_by(username=username).first()

            if validate_ip(request.remote_addr):
                client_ip = request.remote_addr
            else:
                handle_logout()

            print("Nieudanych prób:", Attempt.count_failed_attempts(username, client_ip))
            if Attempt.count_failed_attempts(username, client_ip):
                Attempt.mark_login_attempt(username, client_ip, False)
                flash('Zbyt dużo nieudanych prób logowania. Odczekaj 5 minut.', 'error')
                return render_template('login.html', form=form, username=username, combination=combination)

            if user and Combination.check_combination(combination.id, password):
                login_user(user)
                user.update_last_login()

                session.pop('username', None)
                session["user_id"] = user.id
                session["ip_address"] = client_ip

                Attempt.mark_login_attempt(username, client_ip, True)
                Attempt.mark_attempts_as_old(username, client_ip)

                flash('Pomyślnie zalogowano.', 'success')
                return redirect(url_for('home'))
            else:
                Attempt.mark_login_attempt(username, client_ip, False)
                flash('Dane są niepoprawne.', 'error')
    else:
        for error in form.errors:
            flash(form.errors[error][0], 'error')
    return render_template('login.html', form=form, username=username, combination=combination)

@app.route('/home', methods=['GET', 'POST'])
@login_required
def home(): 
    return render_template('home.html', user=current_user)

@app.route('/make_transfer', methods=['GET', 'POST'])
@login_required
def make_transfer():
    form = TransferForm()

    if form.validate_on_submit():
        sleep(2)
        sender_account_number = current_user.account_number
        recipient_account_number = form.recipient_account_number.data
        amount = form.amount.data
        title = form.title.data 

        if sender_account_number == recipient_account_number:
            flash('Nie można wysłać przelewu do własnego konta.', 'error')
            return render_template('make_transfer.html', form=form)
        
        if amount <= 0:
            flash('Kwota przelewu nie może być ujemna.', 'error')
            return render_template('make_transfer.html', form=form)

        recipient_user = User.query.filter_by(account_number=recipient_account_number).first()

        if recipient_user:
            if current_user.balance >= amount:
                current_user.balance -= amount
                recipient_user.balance += amount

                Transaction.make_transaction(amount, title, recipient_user.account_number, sender_account_number, current_user.id)

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

@app.route('/view_attempts_list')
@login_required
def view_attempts_list():
    attempts = Attempt.query.filter_by(user_id=current_user.username)
    return render_template('view_attempts_list.html', attempts=attempts)

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
        sleep(2)
        if not current_user.check_password(form.current_password.data):
            flash('Błędne aktualne hasło.', 'error')
            return render_template('change_password.html', form=form)
        
        if form.current_password.data == form.new_password.data:
            flash('Nowe hasło musi być inne niż obecne.', 'error')
            return render_template('change_password.html', form=form)
        
        if entropy(form.new_password.data) < 40:
            flash(('Nowe hasło musi mieć większą entropię.'), 'error')
            return render_template('change_password.html', form=form)

        current_user.change_password(form.new_password.data)

        flash('Hasło zostało zmienione.', 'success')
    else:
        for error in form.errors:
            flash(form.errors[error][0], 'error')

    return render_template('change_password.html', form=form)

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    return render_template('csrf_error.html'), 400

@app.errorhandler(404)
def not_found(e):
    return render_template('404_error.html'), 404

def create_key():
    import secrets
    secret_key = secrets.token_hex(128)
    return secret_key

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_sample_users()
    app.run(debug=True, host='0.0.0.0', port=5000)
