import flask
import subprocess


def invoke():
    value = flask.request.args.get("value")
    return subprocess.run(["/usr/bin/printf", value], shell=False, check=True)
