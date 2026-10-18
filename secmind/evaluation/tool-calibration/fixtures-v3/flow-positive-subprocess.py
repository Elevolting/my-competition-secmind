import subprocess


def execute(request):
    command = request.args.get("command")
    subprocess.run(command, shell=True)
