from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, IntegerField, HiddenField
from wtforms.validators import DataRequired, EqualTo, Length, Regexp, NumberRange

safe_username="^[a-zA-Z0-9_-]{4,50}$"
safe_username_message="Nazwa użytkownika może składać się jedynie z liter, cyfr, podkreślnika lub myślnika."
safe_password="^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[@$!%*?&])[A-Za-z0-9@$!%*?&]{8,16}$"
safe_password_message="Dane są niepoprawne."
safe_combination="^[A-Za-z0-9@$!%*?&]{5}$"
current_password_message="Obecne hasło jest niepoprawne."
new_password_message="Nowe hasło musi zawierać co najmniej jedną małą literę, dużą literę, cyfrę, znak specjalny i mieć długość co najmniej 8 znaków."
confirm_password_message="Powtórzone hasło jest niepoprawne."
safe_transaction_amount="^[0-9]{1,50}$"
safe_transaction_amount_message="Kwota przelewu musi być liczbą."
safe_transaction_title="^[a-zA-Z0-9_-]{1,100}$"
safe_transaction_title_message="Tytuł transakcji może zawierać tylko litery, cyfry, podkreślnik lub myślnik."
safe_account_number="^[0-9]{16}$"
safe_account_number_message="Numer konta może składać się jedynie z cyfr."

class EntryForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(4, 50), Regexp(safe_username, message=safe_username_message)])
    honeypot = HiddenField()
    submit = SubmitField('Zaloguj się')

class LoginForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired(), Length(5, 5), Regexp(safe_combination, message=safe_password_message)])
    honeypot = HiddenField()
    submit = SubmitField('Zaloguj się')

class TransferForm(FlaskForm):
    amount = IntegerField('Amount', validators=[DataRequired(message="Kwota przelewu musi być liczbą naturalną."), NumberRange(min=1, max=1000000)])
    title = StringField('Title', validators=[DataRequired(), Length(1, 100), Regexp(safe_transaction_title, message=safe_account_number_message)])
    recipient_account_number = StringField('Recipient Account Number', validators=[DataRequired(), Length(16, 16), Regexp(safe_account_number, message=safe_account_number_message)])
    submit = SubmitField('Wykonaj przelew')

class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Aktualne hasło', validators=[DataRequired(), Length(8, 16), Regexp(safe_password, message=current_password_message)])
    new_password = PasswordField('Nowe hasło', validators=[DataRequired(), Length(8, 16), Regexp(safe_password, message=new_password_message)])
    confirm_password = PasswordField('Potwierdź nowe hasło', validators=[DataRequired(), Length(8, 16), Regexp(safe_password, message=confirm_password_message), EqualTo('new_password', message="Hasła muszą się zgadzać.")])
    submit = SubmitField('Zmień hasło')