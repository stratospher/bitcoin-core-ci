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

from .key import ECKey, ECPubKey, FE, GE

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

def encode(P, hasher):
    cnt = 0
    while True:
        if cnt % 64 == 0:
            hash = hasher.copy()
            hash.update(cnt.to_bytes(4, 'little'))
            cnt += 1
            branch_hash = hash.digest()

        j = (branch_hash[(64-cnt) % 64 >> 1] >> (((64-cnt) % 64 & 1) << 2)) & 7
        hash = hasher.copy()
        hash.update(cnt.to_bytes(4, 'little'))
        cnt += 1
        u = FE(int.from_bytes(hash.digest(), 'big'))
        if u == FE(0):
            continue
        t = reverse_map(P.x, u, j)
        if t is None:
            continue
        if t.is_even() != P.y.is_even():
            t = -t
        return u.to_bytes() + t.to_bytes()

def ellswift_create(privkey, rnd32=bytearray(32)):
    """
    generates elligator swift encoding of pubkey
    with privkey also used as entropy
    Parameters:
        privkey : ECKey object
        randombytes : 32 bytes entropy
    Returns: 64 bytes encoding
    """
    m = hashlib.sha256()
    m.update(b"secp256k1_ellswift_create")
    m.update(bytearray(7))
    m.update(privkey.get_bytes())
    m.update(rnd32)
    m.update(bytearray(19))
    pubkey = privkey.get_pubkey()
    return encode(pubkey.get_group_element(), m)

def ellswift_decode(enc):
    """
     decodes elligator swift encoding to obtain pubkey
     Parameters:
         enc : 64 bytes encoding
     Returns: ECPubKey object
     """
    u, t = FE.from_bytes(enc[:32]), FE.from_bytes(enc[32:])
    x = forward_map(u, t)
    curve_point = GE.lift_x(x)
    if not t.is_even():
        curve_point = -curve_point
    pubkey = ECPubKey()
    pubkey.set(curve_point.to_bytes_compressed())
    return pubkey

def ellswift_ecdh_xonly(ellswift_theirs, secretkey):
    their_pubkey = ellswift_decode(ellswift_theirs)
    our_privkey = int.from_bytes(secretkey.get_bytes(), "big")
    return (our_privkey * their_pubkey.get_group_element()).x.to_bytes()

class TestFrameworkEllSwift(unittest.TestCase):
    def test_create_decode(self):
        for _ in range(32):
            privkey = ECKey()
            privkey.generate()
            pubkey1 = privkey.get_pubkey()
            rnd32 = os.urandom(32)
            encoding = ellswift_create(privkey, rnd32)
            pubkey2 = ellswift_decode(encoding)
            assert pubkey1.get_bytes() == pubkey2.get_bytes()

    def test_ellswift_ecdh_xonly(self):
        for _ in range(32):
            randombytes1 = os.urandom(32)
            randombytes2 = os.urandom(32)
            privkey1 = ECKey()
            privkey1.generate()
            privkey2 = ECKey()
            privkey2.generate()
            encoding1 = ellswift_create(privkey1, randombytes1)
            encoding2 = ellswift_create(privkey2, randombytes2)
            shared_secret1 = ellswift_ecdh_xonly(encoding1, privkey2)
            shared_secret2 = ellswift_ecdh_xonly(encoding2, privkey1)
            assert shared_secret1 == shared_secret2
