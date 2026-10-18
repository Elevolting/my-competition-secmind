import subprocess


def run():
    return subprocess.run(["/usr/bin/printf", "ok"], check=True, shell=False)
