from charm.toolbox.pairinggroup import PairingGroup, ZR
from charm.core.math.integer import integer

# Initialize the pairing group
group = PairingGroup('BN254')

class Scalar:
    """Wrapper for ZR elements with arithmetic operations"""
    def __init__(self, value):
        if isinstance(value, integer):
            self.value = group.init(ZR, int(value))
        elif isinstance(value, int):
            self.value = group.init(ZR, value)
        else:
            self.value = value

    @classmethod
    def zero(cls):
        return cls(0)

    @classmethod
    def one(cls):
        return cls(1)

    def __add__(self, other):
        return Scalar(self.value + other.value)

    def __sub__(self, other):
        return Scalar(self.value - other.value)

    def __mul__(self, other):
        return Scalar(self.value * other.value)

    def __eq__(self, other):
        return self.value == other.value

    def __neg__(self):
        return Scalar(-self.value)

    def invert(self):
        if self.value == 0:
            return None
        return Scalar(1 / self.value)

    @classmethod
    def random(cls):
        """Generate a random scalar"""
        return cls(group.random(ZR))