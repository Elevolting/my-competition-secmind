import os
import subprocess

import flask


def vulnerable_run() -> None:
    command = flask.request.args.get("command")
    # ruleid: secmind.python.flask-shell-command-injection
    subprocess.run(command, shell=True)


def vulnerable_system() -> None:
    command = flask.request.form.get("command")
    # ruleid: secmind.python.flask-shell-command-injection
    os.system(command)


def fixed_argument_list() -> None:
    value = flask.request.args.get("value")
    # ok: secmind.python.flask-shell-command-injection
    subprocess.run(["/usr/bin/printf", "%s", value], shell=False)


def unrelated_shell() -> None:
    # ok: secmind.python.flask-shell-command-injection
    subprocess.run("/usr/bin/id", shell=True)
