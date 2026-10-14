import subprocess


def run_fixed():
    return subprocess.run(["/usr/bin/true"], shell=False, check=True)
