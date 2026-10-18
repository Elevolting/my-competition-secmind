from secmind.python_dataflow import analyze_python_source


def test_user_controlled_seed_returned_generator_value_is_reported() -> None:
    source = """
import randomish

def _seed(user_input):
    randomish.seed(user_input)

def issue_value(user_input):
    _seed(user_input)
    return str(randomish.randomish())
"""

    findings = analyze_python_source(source)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "CWE-330"
    assert finding.native_rule_id == "PYFLOW-PREDICTABLE-PRNG-001"
    assert finding.line == 9
    assert finding.source_names == ("parameter:user_input",)


def test_constant_seed_or_unexposed_generator_is_not_reported() -> None:
    constant_seed = """
import random

def simulation():
    random.seed(7)
    return random.random()
"""
    unexposed = """
import random

def shuffle_for_test(user_input):
    random.seed(user_input)
    value = random.random()
    return "done"
"""

    assert analyze_python_source(constant_seed) == ()
    assert analyze_python_source(unexposed) == ()
