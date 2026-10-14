from urllib.request import urlopen


def fetch():
    return urlopen("https://example.invalid/health")
