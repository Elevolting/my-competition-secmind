import flask
import subprocess


def run_job():
    command = flask.request.form.get("command")
    return subprocess.run(command, shell=True, check=False)
