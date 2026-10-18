import sqlite3


def find_user(name: str) -> object:
    query = "SELECT * FROM users WHERE name = '%s'" % name
    return sqlite3.connect(":memory:").execute(query).fetchall()
