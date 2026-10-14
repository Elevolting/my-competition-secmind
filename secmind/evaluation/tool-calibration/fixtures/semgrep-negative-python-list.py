import subprocess


def run(command: str):
    return subprocess.run(["echo", command], check=True, shell=False)
