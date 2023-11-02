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


@registration.route("/register_user", methods = ["GET"])
def register_user():
    form = RegisterUserForm()
    return flask.render_template("registration/register_user.html", form = form)
