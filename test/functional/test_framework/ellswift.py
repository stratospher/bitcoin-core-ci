#!/usr/bin/env python3
# Copyright (c) 2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test-only Elligator Swift implementation

WARNING: This code is slow and uses bad randomness.
Do not use for anything but tests."""

import os
import hashlib
import unittest
import random

from .key import ECKey, ECPubKey, FE, GE, SECP256K1_G

C1 = FE(-3).sqrt()
C2 = -(C1 - FE(1))/2
B = FE(7)

def forward_map(u, t):
    """Forward mapping function

    Parameters:
        FE, FE : any field element
    Returns:
        FE : X coordinate of a point on the secp256k1 curve
    """
    if u == 0:
        u = FE(1)
    if t == 0:
        t = FE(1)
    if u**3 + t**2 + B == 0:
        t = 2 * t
    X = (u**3 - t**2 + B) / (2 * t)
    Y = (X + t) / (C1 * u)
    x3 = u + 4 * Y**2
    if GE.is_valid_x(x3):
        return x3
    x2 = (-X / Y - u) / 2
    if GE.is_valid_x(x2):
        return x2
    x1 = (X / Y - u) / 2
    return x1
#
def reverse_map(x, u, i):
    """Reverse mapping function

    Parameters:
        FE, FE : x is X coordinate of a point, u is a random fe
        i      : integer in range [0,7]
    Returns:
        t (of type FE) : such that forward_map(u, t) = x or None
    """
    g = u**3 + B
    if i&2 == 0:
        o = (-x - u)**3 + B
        if o.is_square():
            return None
        if i&1:
            x = -x - u
        w = g / (u * x - (x + u)**2)
    else:
        w = x - u
        if w == FE(0):
            return None
        r = -w * (FE(4) * g + FE(3) * w * u**2)
        r = r.sqrt()
        if r is None:
            return None
        if i&1:
            if r == FE(0):
                return None
            r = -r
        x = -(r / w + u) / 2
    w = w.sqrt()
    if w is None:
        return None
    if i&4:
        w = -w
    u = u * C2 + x
    t = w * u
    return t
#
# def encode(P, hasher):
#     cnt = 0
#     while True:
#         if cnt % 64 == 0:
#             hash = hasher.copy()
#             hash.update(cnt.to_bytes(4, 'little'))
#             cnt += 1
#             branch_hash = hash.digest()
#
#         j = (branch_hash[(64-cnt) % 64 >> 1] >> (((64-cnt) % 64 & 1) << 2)) & 7
#         hash = hasher.copy()
#         hash.update(cnt.to_bytes(4, 'little'))
#         cnt += 1
#         u = FE(int.from_bytes(hash.digest(), 'big'))
#         if u == FE(0):
#             continue
#         t = reverse_map(P.x, u, j)
#         if t is None:
#             continue
#         if t.is_even() != P.y.is_even():
#             t = -t
#         return u.to_bytes() + t.to_bytes()
#
# def ellswift_create(privkey, rnd32=bytearray(32)):
#     """
#     generates elligator swift encoding of pubkey
#     with privkey also used as entropy
#     Parameters:
#         privkey : ECKey object
#         randombytes : 32 bytes entropy
#     Returns: 64 bytes encoding
#     """
#     m = hashlib.sha256()
#     m.update(b"secp256k1_ellswift_create")
#     m.update(bytearray(7))
#     m.update(privkey.get_bytes())
#     m.update(rnd32)
#     m.update(bytearray(19))
#     pubkey = privkey.get_pubkey()
#     return encode(pubkey.get_group_element(), m)
#
# def ellswift_decode(enc):
#     """
#      decodes elligator swift encoding to obtain pubkey
#      Parameters:
#          enc : 64 bytes encoding
#      Returns: ECPubKey object
#      """
#     u, t = FE.from_bytes(enc[:32]), FE.from_bytes(enc[32:])
#     x = forward_map(u, t)
#     curve_point = GE.lift_x(x)
#     if not t.is_even():
#         curve_point = -curve_point
#     pubkey = ECPubKey()
#     pubkey.set(curve_point.to_bytes_compressed())
#     return pubkey
#
# def ellswift_ecdh_xonly(ellswift_theirs, secretkey):
#     their_pubkey = ellswift_decode(ellswift_theirs)
#     our_privkey = int.from_bytes(secretkey.get_bytes(), "big")
#     return (our_privkey * their_pubkey.get_group_element()).x.to_bytes()
#
# class TestFrameworkEllSwift(unittest.TestCase):
#     def test_create_decode(self):
#         for _ in range(32):
#             privkey = ECKey()
#             privkey.generate()
#             pubkey1 = privkey.get_pubkey()
#             rnd32 = os.urandom(32)
#             encoding = ellswift_create(privkey, rnd32)
#             pubkey2 = ellswift_decode(encoding)
#             assert pubkey1.get_bytes() == pubkey2.get_bytes()
#
#     def test_ellswift_ecdh_xonly(self):
#         for _ in range(32):
#             randombytes1 = os.urandom(32)
#             randombytes2 = os.urandom(32)
#             privkey1 = ECKey()
#             privkey1.generate()
#             privkey2 = ECKey()
#             privkey2.generate()
#             encoding1 = ellswift_create(privkey1, randombytes1)
#             encoding2 = ellswift_create(privkey2, randombytes2)
#             shared_secret1 = ellswift_ecdh_xonly(encoding1, privkey2)
#             shared_secret2 = ellswift_ecdh_xonly(encoding2, privkey1)
#             assert shared_secret1 == shared_secret2

### ElligatorSwift

# Precomputed constant square root of -3 modulo p.
MINUS_3_SQRT = FE(-3).sqrt()

def xswiftec(u, t):
    """Decode field elements (u, t) to an X coordinate on the curve."""
    if u == 0:
        u = FE(1)
    if t == 0:
        t = FE(1)
    if u**3 + t**2 + 7 == 0:
        t = 2 * t
    X = (u**3 + 7 - t**2) / (2 * t)
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
    if case & 4 == 0: #if (!(c & 4)) secp256k1_fe_negate(&w, &w, 1); /* w = -w [= algorithm -w] */
        w = -w
    # x = (-MINUS_3_SQRT + 1)
    # y = -(-1 + MINUS_3_SQRT)
    x = w * (u * (-MINUS_3_SQRT + 1) / 2 + v)
    y = -w * (u * (-1 + MINUS_3_SQRT) / 2 - v)
    # print(x)
    # print(y)
    # assert x == y
    return w * (u * (-MINUS_3_SQRT + 1) / 2 + v)
    #return -w * (u * (MINUS_3_SQRT - 1) / 2 - v)

def xelligatorswift(x):
    """Given a field element X on the curve, find (u, t) that encode them."""
    while True:
        u = FE(random.randrange(1, GE.ORDER))
        case = random.randrange(0, 8)
        t = xswiftec_inv(x, u, case)
        t1 = reverse_map(x, u, case)
        # print("t", t)
        # print("t1", t1)
        if t is not None:
            return u, t

def ellswift_create():
    """Generate a (privkey, ellswift_pubkey) pair."""
    priv = random.randrange(1, GE.ORDER)
    # print("priv", priv)
    # print("pub", priv * SECP256K1_G)
    u, t = xelligatorswift((priv * SECP256K1_G).x)
    return priv.to_bytes(32, 'big'), u.to_bytes() + t.to_bytes() #, priv * SECP256K1_G

def ellswift_decode(enc):
    u, t = FE.from_bytes(enc[:32]), FE.from_bytes(enc[32:])
    x = forward_map(u, t)
    curve_point = GE.lift_x(x)
    if not t.is_even():
        curve_point = -curve_point
    return curve_point

def ellswift_ecdh_xonly(pubkey_theirs, privkey):
    """Compute X coordinate of shared ECDH point between elswift pubkey and privkey."""
    u = FE(int.from_bytes(pubkey_theirs[:32], 'big'))
    t = FE(int.from_bytes(pubkey_theirs[32:], 'big'))
    d = int.from_bytes(privkey, 'big')
    # x1 = forward_map(u, t)#xswiftec(u, t)
    x2 = xswiftec(u, t)
    # assert x1 == x2
    # print("---------------")
    # print("priv2", d)
    curve_point = GE.lift_x(x2)
    # print("pub2", curve_point)
    # print("---------------")
    # if not t.is_even():
    #     print("hi")
    #     curve_point = -curve_point
    return (d * curve_point).x.to_bytes()
    # return (d * GE.lift_x(xswiftec(u, t))).x.to_bytes()

class TestFrameworkEllSwift(unittest.TestCase):
    # def test_create_decode(self):
    #     for _ in range(1):
    #         privkey, encoding, pubkey = ellswift_create()
    #         pubkey2 = ellswift_decode(encoding)
    #         print(pubkey)
    #         print(pubkey2)
    #         assert pubkey == pubkey2
    def test_ellswift_ecdh_xonly(self):
        for _ in range(1000):
            privkey1, encoding1, pubkey1 = ellswift_create()
            privkey2, encoding2, pubkey2 = ellswift_create()
            shared_secret1 = ellswift_ecdh_xonly(encoding1, privkey2)
            shared_secret2 = ellswift_ecdh_xonly(encoding2, privkey1)
            # print(shared_secret1.hex())
            # print(shared_secret2.hex())
            # print("*************")
            # print(int.from_bytes(privkey1, 'big')*pubkey2)
            # print(int.from_bytes(privkey2, 'big')*pubkey1)
            # print("*************")
            assert shared_secret1 == shared_secret2

# hmm... so it seems you don't need eckey object
# how would you rewrite tests

# step 1
# before lunch, i want you to review and understanf v2_p2p.py - it;s literally 1 commit
# document your understanding
# also test when c++ gives < 4095 bytes garbage and > 4095 bytes garbage

# step 2
# i want you to understand and document how we call the handshake functions

# write ellswift tests to verift behaviour!