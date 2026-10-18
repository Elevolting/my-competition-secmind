def lookup(cursor, username: str):
    return cursor.execute("SELECT id FROM users WHERE name = ?", (username,))
