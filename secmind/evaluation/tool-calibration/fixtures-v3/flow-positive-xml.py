def parse_payload(request):
    import xml.etree.ElementTree as etree

    payload = request.values.get("xml")
    return etree.fromstring(payload)
