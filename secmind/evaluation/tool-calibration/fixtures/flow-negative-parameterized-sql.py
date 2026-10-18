def lookup(name: str) -> object:
    return database.execute("SELECT * FROM users WHERE name = ?", (name,))
