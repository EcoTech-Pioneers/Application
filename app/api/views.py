import os
import flask
import json
import secrets
import requests
from urllib.parse import urlencode
from flask_login import current_user, login_required, login_user
from . import api
from .forms import (RegisterUserForm) 
from .. import db
from ..models import User


@api.route("/register_user", methods = ["POST"])
def register_user():
    form = flask.request.form

    # Check the uniqueness of email, username and phone_number
    if User.query.filter_by(username = form.get('username')).first():
        return flask.jsonify({"message": "Username already exists"}), 400

    if User.query.filter_by(emailAddress = form.get('email')).first():
        return flask.jsonify({"message": "Email already exists"}), 400

    if User.query.filter_by(phoneNumber = form.get('phone_number')).first():
        return flask.jsonify({"message": "Phone Number already exists"}), 400

    # Create a new user
    user = User()
    user.register(form)

    # Log in the newly registered user
    login_user(user)
    return flask.jsonify({"message": "User registered successfully"}), 201


@api.route("/login", methods = ["POST"])
def login_user():
    form = flask.request.form
    # Check whether user with username exists
    user = User.query.filter_by(username = form.get("username")).first()
    if user:
        # Check whether password is valid
        if user.login(form.get('password')):
            return flask.jsonify({"message": "Login successful"}), 201

    else:
        return flask.jsonify({"message": "User not found"}), 400

