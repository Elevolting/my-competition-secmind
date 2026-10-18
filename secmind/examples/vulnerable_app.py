import subprocess

import flask


def run_user_command() -> None:
    command = flask.request.args.get("command", "")
    subprocess.Popen(command, shell=True)
