from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, FloatField, HiddenField
from wtforms.validators import DataRequired, EqualTo, Length

class EntryForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    submit = SubmitField('Zaloguj się')

class LoginForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired()])
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