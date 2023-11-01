import os
import flask
import json
import secrets
import requests
from urllib.parse import urlencode
from flask_login import current_user, login_required, login_user
from . import registration
from .forms import (RegisterUserForm) 
from .. import db
from ..models import User


@registration.route("/api/register", methods = ["POST"])
def register_user():
    form = RegisterUserForm(request.form)
    if form.validate_on_submit():
        user = User(
                username = form.username.data,
                password = form.password.data,
                emailAddress = form.email.data,
                phoneNumber = form.phone_number.data
                )
        db.session.add(user)
        db.session.commit()

        login_user(user)
        return jsonify({"message": "User registered successfully"}), 201

    else:
        return jsonify({"message": "Invalid form data"}), 400
