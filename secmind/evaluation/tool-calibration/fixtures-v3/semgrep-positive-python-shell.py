import flask
import subprocess


def invoke():
    value = flask.request.values.get("value")
    return subprocess.call(value, shell=True)
