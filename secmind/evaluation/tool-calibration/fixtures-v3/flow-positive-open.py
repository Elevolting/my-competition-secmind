def read_document(request):
    path = request.form.get("path")
    with open(path, "rb") as handle:
        return handle.read()
