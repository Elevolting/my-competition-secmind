import subprocess


def run_user_command(command: str) -> None:
    subprocess.Popen(command, shell=True)
