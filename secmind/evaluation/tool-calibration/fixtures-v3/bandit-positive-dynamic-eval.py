def run_expression(expression: str) -> object:
    return eval(expression, {"__builtins__": {}}, {})
