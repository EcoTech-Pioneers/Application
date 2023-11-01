from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField 
from wtforms import ValidationError
from wtforms.validators import (DataRequired, Email, Length, EqualTo, 
        DataRequired)
from ..models import User


class RegisterUserForm(FlaskForm):
    username = StringField("Username", [DataRequired(), Length(4, 25)])
    password = PasswordField("Password", [DataRequired(), Length(4, 25)])
    confirm_password = PasswordField("Confirm Password", [DataRequired(), 
        Length(4, 25), EqualTo("password", message = "Passwords must match")])
    email = StringField("Email Address", [DataRequired(), Email(), Length(4, 25)])
    phone_number = StringField("Phone Number",[DataRequired(), Length(10, 15)] )
