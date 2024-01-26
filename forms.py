from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, FloatField, HiddenField
from wtforms.validators import DataRequired, EqualTo, Length, Regexp

safe_username="^[a-zA-Z0-9_-]{4,50}$"
safe_username_message="Nazwa użytkownika może składać się jedynie z liter, cyfr, podkreślnika lub myślnika."
safe_password="^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[@$!%*?&])[A-Za-z0-9@$!%*?&]{4,12}$"
safe_password_message="Hasło musi zawierać co najmniej jedną małą literę, jedną dużą literę, jedną cyfrę oraz znak specjalny."
safe_account_number="^[0-9]{16}$"
safe_account_number_message="Numer konta może składać się jedynie z cyfr."

class EntryForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(4, 50), Regexp(safe_username, message=safe_username_message)])
    honeypot = HiddenField()
    submit = SubmitField('Zaloguj się')

class LoginForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired(), Length(4, 12), Regexp(safe_password, message=safe_password_message)])
    honeypot = HiddenField()
    submit = SubmitField('Zaloguj się')

class TransferForm(FlaskForm):
    amount = FloatField('Amount', validators=[DataRequired(message="Kwota musi być liczbą.")])
    title = StringField('Title', validators=[DataRequired()])
    recipient_account_number = StringField('Recipient Account Number', validators=[DataRequired()])
    submit = SubmitField('Wykonaj przelew')

class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Aktualne hasło', validators=[DataRequired()])
    new_password = PasswordField('Nowe hasło', validators=[DataRequired()])
    confirm_password = PasswordField('Potwierdź nowe hasło', validators=[DataRequired(), EqualTo('new_password', message="Hasła muszą się zgadzać.")])
    submit = SubmitField('Zmień hasło')