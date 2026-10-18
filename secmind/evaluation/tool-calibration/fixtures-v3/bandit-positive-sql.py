def lookup(cursor, username: str):
    query = "SELECT id FROM users WHERE name = '" + username + "'"
    return cursor.execute(query)
