from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, IntegerField, TextAreaField
from wtforms.validators import Length, EqualTo, Email, DataRequired, ValidationError
import string

def check_alphanum(form, field):
    if not any(c in string.ascii_letters for c in field.data) or not any(c in string.digits for c in field.data):
        raise ValidationError('Password must contain both alphabets and digits')

class RegisterForm(FlaskForm):
    username = StringField(label='User Name:', validators=[Length(min=2, max=30), DataRequired()])
    email_address = StringField(label='E-mail Address:', validators=[Email(), DataRequired()])
    password1 = PasswordField(label='Password:', validators=[Length(min=6), DataRequired(), check_alphanum])
    password2 = PasswordField(label='Confirm Password:', validators=[EqualTo('password1'), DataRequired()])
    submit = SubmitField(label='Create Account')

class LoginForm(FlaskForm):
    username = StringField(label='User Name: ', validators=[DataRequired()])
    password = PasswordField(label='Password: ', validators=[DataRequired()])
    submit = SubmitField(label='Sign In')

class PurchaseItemform(FlaskForm):
    submit = SubmitField(label='Purchase Item')

class SellItemform(FlaskForm):
    submit = SubmitField(label='Sell Item')

class ResetPassword(FlaskForm):
    email_address = StringField(label='e-mail Address: ', validators=[Email(), DataRequired()])
    submit = SubmitField(label='Send Password Reset Token')    

class EnterOTP(FlaskForm):
    token = IntegerField(label='Enter OTP: ', validators=[DataRequired()])
    submit = SubmitField(label='Enter OTP')

class NewPassword(FlaskForm):
    password1 = PasswordField(label='Enter New Password: ', validators=[DataRequired(), check_alphanum])
    password2 = PasswordField(label='Confirm New Password: ', validators=[EqualTo('password1'), DataRequired()])
    submit = SubmitField(label='Create New Password')

class CreateAdvert(FlaskForm):
    name = StringField(label='Name of Item: ', validators=[Length(min=2, max=50), DataRequired()])
    price = IntegerField(label='Enter Item Price: ', validators=[DataRequired()])
    barcode = StringField(label='Enter Item Barcode: ',validators=[Length(min=2, max=12), DataRequired()])
    description = TextAreaField(label='Description of Item: ', validators=[Length(min=10, max=500), DataRequired()])
    submit = SubmitField(label='Put Item on the Market')

