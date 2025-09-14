#!/usr/bin/env python3
"""
Example code that demonstrates the py.no-eval rule violation.
This code should trigger the security rule.
"""

def unsafe_eval_example():
    """This function demonstrates unsafe eval usage."""
    user_input = input("Enter expression: ")
    result = eval(user_input)  # This will trigger the rule
    return result

def another_unsafe_example():
    """Another example of unsafe eval usage."""
    expression = "2 + 2"
    result = eval(expression)  # This will also trigger the rule
    return result

def dynamic_code_execution():
    """Example of dynamic code execution with eval."""
    code = "print('Hello from eval!')"
    eval(code)  # This will trigger the rule

if __name__ == "__main__":
    unsafe_eval_example()
    another_unsafe_example()
    dynamic_code_execution()
