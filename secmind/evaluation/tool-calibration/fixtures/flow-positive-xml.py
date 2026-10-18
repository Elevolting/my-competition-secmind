from xml import etree


def parse(user_xml: str) -> object:
    return etree.fromstring(user_xml)
