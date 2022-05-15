from sympy import *
from sympy.parsing.sympy_parser import standard_transformations, implicit_multiplication_application

import re

transformations = (standard_transformations + (implicit_multiplication_application,))

answer = "No answer"


def solver(eq):
    MULTIPLY_SYMBOLS = ["x", "X", "×"]
    OTHER_SYMBOLS = ["+", "-", "=", "/", "÷"]
    answer = ""
    x_indexs = []

    eq = eq.replace(" ", "")
    eq = eq.replace("^", "**")
    eq = eq.replace("÷", "/")

    for symbol in MULTIPLY_SYMBOLS:
        x_indexs.extend([i.start() for i in re.finditer(symbol, eq)])

    for index in x_indexs:
        temp = list(eq)

        if (index+1) < len(eq) and not any(eq[index+1] in char for char in OTHER_SYMBOLS) and not any(eq[index+1] in char for char in MULTIPLY_SYMBOLS):
            temp[index] = "*"
        else:
            temp[index] = "x"

        eq = "".join(temp)

    try:
        eq_left = 0
        eq_right = 0

        if "=" in eq:
            eq_left = simplify(parse_expr(eq.split("=")[0], transformations=transformations))
            eq_right = simplify(parse_expr(eq.split("=")[1], transformations=transformations))

            answer = solve(Eq(eq_left, eq_right))

        else:
            answer = simplify(parse_expr(eq, transformations=transformations))

        try:
            answer = str(answer).replace("*", "")
        except Exception as ex:
            print(ex.args)

        return answer

    except Exception as ex:
        print(ex.args)