def find_user(request, connection):
    user_id = request.json.get("user_id")
    return connection.cursor().execute("SELECT * FROM users WHERE id = ?", (user_id,))
