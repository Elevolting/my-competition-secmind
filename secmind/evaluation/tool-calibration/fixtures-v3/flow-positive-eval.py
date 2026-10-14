def calculate():
    import json

    expression = input("expression: ")
    return eval(expression, {"__builtins__": {}}, json.loads("{}"))
