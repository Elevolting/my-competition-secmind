import flask
import subprocess


def run():
    command = flask.request.args.get("command")
    return subprocess.run(command, shell=True, check=False)
