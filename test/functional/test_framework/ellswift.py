#!/usr/bin/env python3
# Copyright (c) 2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test-only Elligator Swift implementation

WARNING: This code is slow and uses bad randomness.
Do not use for anything but tests."""

import random
import unittest

from .key import FE, GE

MINUS_3_SQRT = FE(-3).sqrt()

def xswiftec(u, t):
    """Decode field elements (u, t) to an X coordinate on the curve."""
    if u == 0:
        u = FE(1)
    if t == 0:
        t = FE(1)
    if u**3 + t**2 + 7 == 0:
        t = 2 * t
    X = (u**3 - t**2 + 7) / (2 * t)
    Y = (X + t) / (MINUS_3_SQRT * u)
    for x in (u + 4 * Y**2, (-X / Y - u) / 2, (X / Y - u) / 2):
        if GE.is_valid_x(x):
            return x
    assert False

def xswiftec_inv(x, u, case):
    """Given x and u, find t such that xswiftec(u, t) = x, or return None.
    Case selects which of the up to 8 results to return."""
    if case & 2 == 0:
        if GE.is_valid_x(-x - u):
            return None
        v = x if case & 1 == 0 else -x - u
        s = -(u**3 + 7) / (u**2 + u*v + v**2)
    else:
        s = x - u
        if s == 0:
            return None
        r = (-s * (4 * (u**3 + 7) + 3 * s * u**2)).sqrt()
        if r is None:
            return None
        if case & 1:
            if r == 0:
                return None
            r = -r
        v = (-u + r / s) / 2
    w = s.sqrt()
    if w is None:
        return None
    if case & 4:
        w = -w
    t1 = w * (u * (MINUS_3_SQRT - 1) / 2 - v)
    t2 = w * (u * (MINUS_3_SQRT + 1) / 2 + v)
    t3 = w * (u * (-MINUS_3_SQRT - 1) / 2 - v)
    t4 = w * (u * (-MINUS_3_SQRT + 1) / 2 + v)
    return t1, t2, t3, t4

def xelligatorswift(x):
    """Given a field element X on the curve, find (u, t) that encode them."""
    while True:
        u = FE(random.randrange(1, GE.ORDER))
        case = random.randrange(0, 8)
        list_of_all_t = xswiftec_inv(x, u, case)
        if list_of_all_t is None:
            continue
        print("x we start round trip with")
        print(x)
        t1, t2, t3, t4 = list_of_all_t
        x1, x2, x3, x4 = xswiftec(u, t1), xswiftec(u, t2), xswiftec(u, t3), xswiftec(u, t4)
        print("x values using xswiftec(u, [t1, t2, t3, t4])")
        assert x2 == x4
        print(x1)
        print(x2)
        print(x3)
        print(x4)
        return u, t1

class TestFrameworkEllSwift(unittest.TestCase):
    def test_elligator_roundtrip(self):
        """Verify that encoding using xelligatorswift decodes back using xswiftec."""
        for _ in range(1):
            while True:
                # Loop until we find a valid X coordinate on the curve.
                x = FE(random.randrange(1, FE.SIZE))
                if GE.is_valid_x(x):
                    break
            # Encoding it to (u, t), decode it back, and compare.
            u, t = xelligatorswift(x)
            x2 = xswiftec(u, t)

            print("MINUS_3_SQRT - 1 == -1 + MINUS_3_SQRT ?", MINUS_3_SQRT - 1 == -1 + MINUS_3_SQRT)
            self.assertEqual(x2, x)
