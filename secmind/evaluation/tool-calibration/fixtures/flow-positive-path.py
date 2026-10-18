def read_file(user_path: str) -> str:
    with open(user_path, encoding="utf-8") as handle:
        return handle.read()
