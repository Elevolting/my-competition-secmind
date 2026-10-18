from xml import etree


def parse() -> object:
    return etree.fromstring("<safe />")
