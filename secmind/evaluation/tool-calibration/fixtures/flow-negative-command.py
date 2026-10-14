import subprocess


def run() -> None:
    subprocess.run(["echo", "fixed"], check=True)
