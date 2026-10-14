import subprocess


def run(user_command: str) -> None:
    subprocess.Popen(user_command, shell=True)
