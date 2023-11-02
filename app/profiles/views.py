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
from ..models import User


@profiles.route('/dashboard', methods = ["GET"])
def dashboard():
    return flask.render_template("analytics/mapping.html")
