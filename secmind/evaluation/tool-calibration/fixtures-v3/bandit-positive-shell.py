import subprocess


def launch(command: str) -> None:
    subprocess.Popen(command, shell=True)
