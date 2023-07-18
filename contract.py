import math

pi = 0.0
for k in range(20):
    pi += (1 / 16 ** k) * (
        (4 / (8 * k + 1)) -
        (2 / (8 * k + 4)) -
        (1 / (8 * k + 5)) -
        (1 / (8 * k + 6))
    )

print(pi)


