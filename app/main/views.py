import flask
from flask_login import login_user, logout_user, login_required
from . import main
from .. import db
from ..models import User

@main.route('/')
@main.route('/home')
@main.route('/homepage')
def index():
    return flask.render_template('main/index.html')
