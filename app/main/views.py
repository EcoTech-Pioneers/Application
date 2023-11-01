import flask
from . import main

@main.route('/')
@main.route('/home')
@main.route('/homepage')
def index():
    return flask.render_template('main/index.html')


@main.route('/about_us')
def about_us():
    return flask.render_template('main/about_us.html')
