import sqlite3


def find_user(name: str) -> object:
    connection = sqlite3.connect(":memory:")
    return connection.execute("SELECT * FROM users WHERE name = ?", (name,)).fetchall()
