def lookup(request) -> object:
    name = request.POST.get("name")
    query = "SELECT * FROM users WHERE name='" + name + "'"
    return database.execute(query)
