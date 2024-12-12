from typing import List
from scalar_types import Scalar

###########################################################################################################
# POLYNOMIAL AND LAGRANGE INTERPOLATION
###########################################################################################################

class Polynomial:
    """Implementation of polynomial operations over ZR"""
    def __init__(self, coeffs: List[Scalar]):
        self.coeffs = coeffs
        self.degree = len(coeffs) - 1

    def eval(self, x: Scalar) -> Scalar:
        """Evaluate polynomial at point x"""
        result = Scalar.zero()
        x_power = Scalar.one()
        for coeff in self.coeffs:
            result = result + (coeff * x_power)
            x_power = x_power * x
        return result

    @staticmethod
    def lagrange_coefficients(xs: List[Scalar]) -> List[Scalar]:
        """Compute Lagrange coefficients for x=0"""
        result = []
        for i, x_i in enumerate(xs):
            num = Scalar.one()
            den = Scalar.one()
            for j, x_j in enumerate(xs):
                if i != j:
                    num = num * x_j
                    den = den * (x_j - x_i)
            if den.value == 0:
                raise ValueError("Duplicate x values in Lagrange interpolation")
            result.append(num * den.invert())
        return result

def sample_random_poly(degree: int) -> Polynomial:
    """Generate a random polynomial of given degree"""
    coeffs = [Scalar.random() for _ in range(degree + 1)]
    return Polynomial(coeffs)
