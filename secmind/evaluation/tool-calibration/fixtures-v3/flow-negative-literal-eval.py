def calculate() -> object:
    return eval("1 + 1", {"__builtins__": {}}, {})
