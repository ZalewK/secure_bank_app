import os
from users import users_data
from time import sleep
from flask import Flask, render_template, request, redirect, session, url_for, flash
from flask_login import LoginManager, login_user, logout_user, current_user
from flask_bcrypt import Bcrypt
from flask_talisman import Talisman
from forms import EntryForm, LoginForm, TransferForm, ChangePasswordForm
from models import db, User, Transaction
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
talisman = Talisman(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///bank.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
secret_key = os.environ.get("FLASK_SECRET_KEY", "default key")
app.config['SECRET_KEY'] = secret_key
bcrypt = Bcrypt(app)
db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'entry'
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

        # Sprawdź, czy użytkownik już istnieje w bazie danych
        user = User.query.filter_by(username=username).first()

        if not user:
            new_user = User(username=username, card_number=card_number, id_number=id_number, account_number=account_number, balance=balance)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()

@app.before_request
def before_request():
    if not current_user.is_authenticated and request.endpoint and request.endpoint in ['index', 'other_protected_endpoint']:
        return redirect(url_for('entry'))

@app.route('/')
def index():
    with app.app_context():
        return render_template('index.html', user=current_user)

@app.route('/entry', methods=['GET', 'POST'])
def entry():
    form = EntryForm()

    if form.validate_on_submit():
        username = form.username.data
        session['partial_password_username'] = username
        return redirect(url_for('login'))
    
    return render_template('entry.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        print("JESTEM TU")
        if form.honeypot.data:
            flash('Wystąpił błąd.', 'error')
            sleep(3)
            return redirect(url_for('login'))
        else:
            print("git")
            username = session.get('partial_password_username')
            password = form.password.data
            print(username, password)

            if username not in login_attempts_memory:
                login_attempts_memory[username] = 0

            user = User.query.filter_by(username=username).first()

            if user and user.check_password(password):
                login_user(user)
                user.update_last_login()
                session.pop('partial_password_username', None)
                flash('Pomyślnie zalogowano.', 'success')
                return redirect(url_for('index'))
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

@app.route('/make_transfer', methods=['GET', 'POST'])
def make_transfer():
    form = TransferForm()

    if form.validate_on_submit():
        sender_account_number = current_user.account_number
        recipient_account_number = form.recipient_account_number.data
        amount = form.amount.data
        title = form.title.data 

        # Sprawdzenie, czy nie próbujemy wysłać przelewu do samego siebie
        if sender_account_number == recipient_account_number:
            flash('Nie można wysłać przelewu do własnego konta.', 'error')
            return redirect(url_for('make_transfer'))

        # Sprawdzenie, czy istnieje użytkownik o podanym numerze konta
        recipient_user = User.query.filter_by(account_number=recipient_account_number).first()

        if recipient_user:
            # Sprawdzenie, czy saldo wystarcza na wykonanie przelewu
            if current_user.balance >= amount:
                # Aktualizacja salda obu użytkowników
                current_user.balance -= amount
                recipient_user.balance += amount

                # Zapisanie transakcji w bazie danych
                transaction = Transaction(amount=amount, title=title, recipient_account_number=recipient_user.account_number, sender_account_number=sender_account_number, user=current_user)
                db.session.add(transaction)
                db.session.commit()

                flash('Przelew wykonany pomyślnie.', 'success')
                return redirect(url_for('index'))
            else:
                flash('Niewystarczające saldo na koncie.', 'error')
        else:
            flash('Użytkownik o podanym numerze konta nie istnieje.', 'error')

    return render_template('make_transfer.html', form=form)

@app.route('/view_sensitive_data')
def view_sensitive_data():
    return render_template('view_sensitive_data.html', user=current_user)

@app.route('/view_transaction_list')
def view_transaction_list():
    with app.app_context():
        # Pobierz transakcje wychodzące i przychodzące dla bieżącego użytkownika
        out_trans = Transaction.query.filter_by(user_id=current_user.id).all()
        in_trans = Transaction.query.filter_by(recipient_account_number=current_user.account_number).all()
    return render_template('view_transaction_list.html', out_trans=out_trans, in_trans=in_trans)
    
@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    form = ChangePasswordForm()

    if form.validate_on_submit():
        # Sprawdzanie poprawności aktualnego hasła
        if not current_user.check_password(form.current_password.data):
            flash('Błędne aktualne hasło.', 'error')
            print(f'{current_user.password}')
            print(f'{form.current_password.data}')
            return redirect(url_for('change_password'))

        # Aktualizacja hasła w bazie danych
        current_user.set_password(form.new_password.data)
        db.session.commit()

        flash('Hasło zostało zmienione.', 'success')

    return render_template('change_password.html', form=form)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_sample_users()
    app.run(debug=True)
