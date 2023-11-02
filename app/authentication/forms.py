from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import InputRequired, Length
from ..models import User

class LoginForm(FlaskForm):
    username = StringField("Username", validators = [InputRequired(), 
        Length(3, 64)])
    password = PasswordField("Password", validators = [InputRequired(), 
        Length(8, 32)])
