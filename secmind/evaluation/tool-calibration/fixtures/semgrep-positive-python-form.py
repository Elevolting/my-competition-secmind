import flask
import subprocess


def run():
    command = flask.request.form.get("command")
    return subprocess.call(command, shell=True)
