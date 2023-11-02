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
from ..models import User, Record

# =====================================================================
# REGISTRATION ROUTES
# =====================================================================

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


#====================================================================
# AUTHENTICATION ROUTES
# ====================================================================
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

#====================================================================
# PROFILES ROUTES
# ====================================================================
@api.route("/add_record", methods = ["POST"])
def add_record():
    form = flask.request.form
    if (current_user.addRecord(form)):
        return flask.jsonify({"message": "Record added successfully"}), 201
    
    return flask.jsonify({"message": "An error occurred while saving data"}), 400


@api.route("/all_records", methods = ["GET"])
def all_records():
    results = Record.query
    
    page = flask.request.args.get('page', 1, type = int)
    per_page = min(flask.request.args.get('per_page', 10, type = int), 100)
    results = Record.to_collection_dict(results, page, per_page, 
            'api.all_records')
    return flask.jsonify(results)


@api.route("/records", methods = ["GET"])
def records():
    results = current_user.getRecords()
    
    page = flask.request.args.get('page', 1, type = int)
    per_page = min(flask.request.args.get('per_page', 10, type = int), 100)
    results = Record.to_collection_dict(results, page, per_page, 
            'api.get_records')
    return flask.jsonify(results)


@api.route("/register_event", methods = ["POST"])
def register_event():
    form = flask.request.form
    if (current_user.scheduleEvent(form)):
        return flask.jsonify({"message": "Event registered successfully"}), 201

    return flask.jsonify({"message": "An error occurred while saving data"}), 400


@api.route("/all_events", methods = ["GET"])
def all_events():
    results = Event.query
    
    page = flask.request.args.get('page', 1, type = int)
    per_page = min(flask.request.args.get('per_page', 10, type = int), 100)
    results = Record.to_collection_dict(results, page, per_page, 
            'api.all_events')
    return flask.jsonify(results)


@api.route("/events", methods = ["GET"])
def events():
    results = current_user.getCreatedEvents()
    
    page = flask.request.args.get('page', 1, type = int)
    per_page = min(flask.request.args.get('per_page', 10, type = int), 100)
    results = Record.to_collection_dict(results, page, per_page, 
            'api.events')
    return flask.jsonify(results)

