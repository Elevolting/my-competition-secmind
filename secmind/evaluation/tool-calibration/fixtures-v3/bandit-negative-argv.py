import subprocess


def launch(command: str) -> None:
    subprocess.run(["/usr/bin/logger", command], shell=False, check=True)
