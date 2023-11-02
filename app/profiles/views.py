import os
import flask
import glob
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
from sqlalchemy import func, or_
from geopy.geocoders import ArcGIS
from datetime import timedelta, datetime

from . import profiles
from .. import db
from .forms import AddRecordForm, CreateEventForm
from ..models import User


@profiles.route('/dashboard', methods = ["GET"])
def dashboard():
    return flask.render_template("profiles/dashboard.html")


@profiles.route('/add_record', methods = ["GET"])
def add_record():
    form = AddRecordForm()
    return flask.render_template("profiles/add_record.html", form = form)


@profiles.route('/all_records', methods = ["GET"])
def all_records():
    return flask.render_template("profiles/all_records.html")


@profiles.route('/other_events', methods = ["GET"])
def other_records():
    return flask.render_template("profiles/other_events.html")


@profiles.route("/create_event", methods = ["GET"])
def create_event():
    form = CreateEventForm()
    return flask.render_template("profiles/create_event.html", form = form)
