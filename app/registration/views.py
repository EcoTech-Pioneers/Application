import os
import flask
import json
import secrets
import requests
from urllib.parse import urlencode
from flask_login import current_user, login_required, login_user
from . import registration
#from .forms import () 
from .. import db
from ..models import User
