import collections
import hashlib
import random
import binascii

EllipticCurve = collections.namedtuple('EllipticCurve', 'name p a b g n h')

secp256k1 = EllipticCurve(
    'secp256k1',
    # Field characteristic.
    p=0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f,
    # Curve coefficients.
    a=0,
    b=7,
    # Base point.
    g=(0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
       0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8),
    # Subgroup order.
    n=0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141,
    # Subgroup cofactor.
    h=1,
)

secp256r1 = EllipticCurve(
    'secp256r1',
    # Field ffffffff00000001000000000000000000000000ffffffffffffffffffffffff.
    p=0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f,
    # Curve coefficients.
    a=0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc,
    b=0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
    # Base point.
    g=(0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
       0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5),
    # Subgroup order.
    n=0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551,
    # Subgroup cofactor.
    h=1,
)


# Modular arithmetic ##########################################################
def inverse_mod(k, p):
    """Returns the inverse of k modulo p.
    This function returns the only integer x such that (x * k) % p == 1.
    k must be non-zero and p must be a prime.
    """
    if k == 0:
        raise ZeroDivisionError('division by zero')

    if k < 0:
        # k ** -1 = p - (-k) ** -1  (mod p)
        return p - inverse_mod(-k, p)

    # Extended Euclidean algorithm.
    s, old_s = 0, 1
    t, old_t = 1, 0
    r, old_r = p, k

    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t

    gcd, x, y = old_r, old_s, old_t

    assert gcd == 1
    assert (k * x) % p == 1

    return x % p


# Functions that work on curve points #########################################

def is_on_curve(point, curve):
    """Returns True if the given point lies on the elliptic curve."""
    if point is None:
        # None represents the point at infinity.
        return True

    x, y = point

    return (y * y - x * x * x - curve.a * x - curve.b) % curve.p == 0

# Point negation
def point_neg(point, curve):
    """Returns -point."""
    assert is_on_curve(point)

    if point is None:
        # -0 = 0
        return None

    x, y = point
    result = (x, (curve.p - y) % curve.p)

    assert is_on_curve(result, curve)

    return result

def point_double(point, curve):
    """Returns 2 * point."""
    return point_add(point, point, curve)
    # assert is_on_curve(point, curve)

    # if point is None:
    #     # 2 * 0 = 0
    #     return None

    # x, y = point

    # s = ((3 * x * x - curve.a) * inverse_mod(2 * y, curve.p)) % curve.p
    # x3 = (s * s - 2 * x) % curve.p
    # y3 = curve.p - (y + s * (x - x3)) % curve.p
    # result = (x3, y3)

    # assert is_on_curve(result, curve)

    # return result




def point_add(point1, point2, curve):
    """Returns the result of point1 + point2 according to the group law."""
    assert is_on_curve(point1, curve)
    assert is_on_curve(point2, curve)

    if point1 is None:
        # 0 + point2 = point2
        return point2
    if point2 is None:
        # point1 + 0 = point1
        return point1

    x1, y1 = point1
    x2, y2 = point2

    if x1 == x2 and y1 != y2:
        # point1 + (-point1) = 0
        return None

    if x1 == x2:
        # This is the case point1 == point2.
        m = ((3 * x1 * x1 + curve.a) * inverse_mod(2 * y1, curve.p)) % curve.p
    else:
        # This is the case point1 != point2.
        m = ((y1 - y2) * inverse_mod(x1 - x2, curve.p)) % curve.p

    x3 = (m * m - x1 - x2) % curve.p
    y3 = (y1 + m * (x3 - x1) ) % curve.p
    result = (x3 % curve.p,
              -y3 % curve.p)

    assert is_on_curve(result, curve)

    return result

def point_add_steps(point1, point2, curve):
    """Returns the result of point1 + point2 according to the group law."""

    print("Input parameters:")
    print("point1.x = ", hex(point1[0]))
    print("point1.y = ", hex(point1[1]))
    print("point2.x = ", hex(point2[0]))
    print("point2.y = ", hex(point2[1]))

    assert is_on_curve(point1, curve)
    assert is_on_curve(point2, curve)

    if point1 is None:
        # 0 + point2 = point2
        print("point1 is at infinity, returning point2")
        return point2
    if point2 is None:
        # point1 + 0 = point1
        print("point2 is at infinity, returning point1")
        return point1

    x1, y1 = point1
    x2, y2 = point2

    if x1 == x2 and y1 != y2:
        # point1 + (-point1) = 0
        print("point1 + (-point1) = 0")
        return None

    if x1 == x2:
        print("point1 == point2")
        # This is the case point1 == point2.
        m = ((3 * x1 * x1 + curve.a) * inverse_mod(2 * y1, curve.p)) % curve.p
    else:
        # This is the case point1 != point2.
        m = ((y1 - y2) * inverse_mod(x1 - x2, curve.p)) % curve.p

    print("m = ", hex(m))

    # calculate x3 = (m * m - x1 - x2) % curve.p
    msqrx12 = (m * m) % curve.p
    print("msqr = ", hex(msqrx12))

    msqrx12 = (msqrx12 - x1) % curve.p
    print("msqr - x1 = ", hex(msqrx12))

    x3 = (msqrx12 - x2) % curve.p
    print("x3 = ", hex(x3))

    # calculate y3 = (y1 + m * (x3 - x1) ) % curve.p
    x3subx1 = (x3 - x1) % curve.p
    print("x3 - x1 = ", hex(x3subx1))
    x3subx1mulM = (m * (x3 - x1)) % curve.p
    print("m * (x3 - x1) = ", hex(x3subx1mulM))

    y3 = (y1 + x3subx1mulM) % curve.p
    print("y3 = ", hex(y3))

    y3 = -y3 % curve.p
    print("-y3 % curve.p = ", hex(y3))

    result = (x3 ,  y3)

    assert is_on_curve(result, curve)
    print("y3= ", hex(y3))

    return result

def scalar_mul(k, point, curve):
    """Returns k * point computed using the double and point_add algorithm."""
    assert is_on_curve(point, curve)

    if k % curve.n == 0 or point is None:
        return None

    if k < 0:
        # k * point = -k * (-point)
        return scalar_mul(-k, point_neg(point, curve), curve)

    result = None
    addend = point

    while k:
        if k & 1:
            # Add.
            result = point_add(result, addend, curve)

        # Double.
        addend = point_add(addend, addend, curve)

        k >>= 1

    assert is_on_curve(result, curve)

    return result


# Uses Shamir's trick to compute the point R = a*P + b*Q
def mul_add_fast(a, P, b, Q, curve):
    """
    Given two points P and Q and two integers a and b, computes the point R = a*P + b*Q
    using Shamir's trick.
    """
    if a == 0:
        return scalar_mul(b, Q, curve)
    if b == 0:
        return scalar_mul(a, P, curve)

    # Handle the case when P and Q are the same point
    if P == Q:
        return scalar_mul(a + b, P, curve)

    # Neither a nor b should be greater than n, the order of the curve, but we'll check just in case
    n = curve.n
    if a >= n or b >= n:
        raise ValueError("a and b should be in the range [0, n)")

    # Write a and b in binary, with the same number
    # of digits as n.
    a_bin = bin(a)[2:]
    b_bin = bin(b)[2:]
    max_len = max(len(a_bin), len(b_bin))
    if len(a_bin) < max_len:
        a_bin = '0' * (max_len - len(a_bin)) + a_bin
    if len(b_bin) < max_len:
        b_bin = '0' * (max_len - len(b_bin)) + b_bin

    # Compute R = a*P + b*Q using the binary representation of a and b.
    R = None
    pq_sum = point_add(P, Q, curve)
    for i in range(max_len):
        R = point_double(R, curve)
        if a_bin[i] == '1' and b_bin[i] == '1':
            R = point_add(R, pq_sum, curve)
        elif a_bin[i] == '1':
            R = point_add(R, P, curve)
        elif b_bin[i] == '1':
            R = point_add(R, Q, curve)

    assert is_on_curve(R, curve)
    return R

# Uses Shamir's trick to compute the point R = a*P + b*Q
def mul_add_fast_steps(a, P, b, Q, curve):
    """
    Given two points P and Q and two integers a and b, computes the point R = a*P + b*Q
    using Shamir's trick.
    """
    print("mul_add_fast params")
    print("a: ", hex(a))
    print("P: ", hex(P[0]), hex(P[1]))
    print("b: ", hex(b))
    print("Q: ", hex(Q[0]), hex(Q[1]))
    print("curve.p: ", hex(curve.p))
    print("curve.a: ", hex(curve.a))


    if a == 0:
        return scalar_mul(b, Q, curve)
    if b == 0:
        return scalar_mul(a, P, curve)

    # Handle the case when P and Q are the same point
    if P == Q:
        return scalar_mul(a + b, P, curve)

    # Neither a nor b should be greater than n, the order of the curve, but we'll check just in case
    n = curve.n
    if a >= n or b >= n:
        raise ValueError("a and b should be in the range [0, n)")

    # Write a and b in binary, with the same number
    # of digits as n.
    a_bin = bin(a)[2:]
    b_bin = bin(b)[2:]
    max_len = max(len(a_bin), len(b_bin))
    if len(a_bin) < max_len:
        a_bin = '0' * (max_len - len(a_bin)) + a_bin
    if len(b_bin) < max_len:
        b_bin = '0' * (max_len - len(b_bin)) + b_bin


    print("max_len: ", max_len)

    # Compute R = a*P + b*Q using the binary representation of a and b.
    R = None
    pq_sum = point_add(P, Q, curve)
    print("pq_sum: ", hex(pq_sum[0]), hex(pq_sum[1]))
    for i in range(max_len):
        R = point_double(R, curve)
        if R:
            print("R after double: ", hex(R[0]), hex(R[1]))
        else:
            print("R after double: ", R)

        if a_bin[i] == '1' and b_bin[i] == '1':
            print("a and b test bit")
            R = point_add(R, pq_sum, curve)
        elif a_bin[i] == '1':
            print("a test bit")
            R = point_add(R, P, curve)
        elif b_bin[i] == '1':
            print("b test bit")
            R = point_add(R, Q, curve)

        print("R after add: ", hex(R[0]), hex(R[1]))
        print("")


    assert is_on_curve(R, curve)

    return R

def ecdsa_verify(q, e, r, s, curve) -> bool:
    """Verifies an ECDSA signature."""
    if r < 1 or r > curve.n - 1:
        return False
    if s < 1 or s > curve.n - 1:
        return False

    w = inverse_mod(s, curve.n)
    u1 = (e * w) % curve.n
    u2 = (r * w) % curve.n
    x, y = point_add(scalar_mul(u1, curve.g, curve), scalar_mul(u2, q, curve), curve)

    if x % curve.n == r:
        return True
    else:
        return False

def ecdsa_verify_fast(q, e, r, s, curve) -> bool:
    """Verifies an ECDSA signature."""
    if r < 1 or r > curve.n - 1:
        return False
    if s < 1 or s > curve.n - 1:
        return False

    w = inverse_mod(s, curve.n)
    u1 = (e * w) % curve.n
    u2 = (r * w) % curve.n

    x1, y1 = mul_add_fast(u1, curve.g, u2, q, curve)

    # x2, y2 = point_add(scalar_mul(u1, curve.g, curve), scalar_mul(u2, q, curve), curve)
    # assert x1 == x2
    # assert y1 == y2

    if x1 % curve.n == r:
        return True
    else:
        return False

def ecdsa_verify_steps(q, e, r, s, curve) -> bool:
    """Verifies an ECDSA signature."""
    print("Input parameters:")
    print("Q.x = ", hex(q_x))
    print("Q.y = ", hex(q_y))

    print("r = ", hex(r))
    print("s = ", hex(s))

    print("e = ", hex(e))

    print("\nVerifying:")

    if r < 1 or r > curve.n - 1:
        print("r is not in range")
        return False
    if s < 1 or s > curve.n - 1:
        print("s is not in range")
        return False

    w = inverse_mod(s, curve.n)
    print("w = ", hex(w))

    u1 = (e * w) % curve.n
    print("u1 = ", hex(u1))

    u2 = (r * w) % curve.n
    print("u2 = ", hex(u2))

    x1, y1 = point_add(scalar_mul(u1, curve.g, curve), scalar_mul(u2, q, curve), curve)

    print("x1 = ", hex(x1))
    print("y1 = ", hex(y1))

    valid = x1 % curve.n == r
    print("Signature is", "valid" if valid else "invalid", "!")
    return valid

def ecdsa_verify_fast_steps(q, e, r, s, curve) -> bool:
    """Verifies an ECDSA signature."""
    print("Input parameters:")
    print("Q.x = ", hex(q_x))
    print("Q.y = ", hex(q_y))

    print("r = ", hex(r))
    print("s = ", hex(s))

    print("e = ", hex(e))

    print("\nVerifying:")

    if r < 1 or r > curve.n - 1:
        print("r is not in range")
        return False
    if s < 1 or s > curve.n - 1:
        print("s is not in range")
        return False

    w = inverse_mod(s, curve.n)
    print("w = ", hex(w))

    u1 = (e * w) % curve.n
    print("u1 = ", hex(u1))

    u2 = (r * w) % curve.n
    print("u2 = ", hex(u2))

    x1, y1 = mul_add_fast_steps(u1, curve.g, u2, q, curve)

    print("x1 = ", hex(x1))
    print("y1 = ", hex(y1))

    valid = x1 % curve.n == r
    print("Signature is", "valid" if valid else "invalid", "!")
    return valid
