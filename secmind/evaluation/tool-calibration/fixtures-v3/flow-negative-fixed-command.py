import subprocess


def execute() -> None:
    subprocess.run(["/usr/bin/printf", "ok"], shell=False, check=True)
