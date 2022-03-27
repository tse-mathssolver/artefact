from wtforms import PasswordField, SubmitField, EmailField
from wtforms.validators import InputRequired, Length, ValidationError, Email
from flask_wtf import FlaskForm
from models import User

class RegisterForm(FlaskForm):
    email = EmailField(validators=[InputRequired(), Email(), Length(min=4, max=20)], render_kw={"placeholder": "Email"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Register")

    def validate_email(self, email):
        email_exists = User.query.filter_by(email=email.data).first()
        if email_exists:
            raise ValidationError("This email already exists.")

class LoginForm(FlaskForm):
    email = EmailField(validators=[InputRequired(), Email(), Length(min=4, max=20)], render_kw={"placeholder": "Email"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Login")