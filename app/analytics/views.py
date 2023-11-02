import flask
from . import analytics


@analytics.route("/forest_distribution")
def forest_distribution():
    return flask.render_template("analytics/mapping.html")
