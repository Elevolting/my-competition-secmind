import subprocess


def run_command(user_input: str) -> None:
    subprocess.run(user_input, shell=True)
