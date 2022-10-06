#!/usr/bin/env python3
# Copyright (c) 2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Implementation of Poly1305 authenticator for RFC 7539"""

class Poly1305:
    """Class representing a running poly1305 computation."""
    MODULUS = 2**130 - 5

    def __init__(self, key):
        self.r = int.from_bytes(key[:16], 'little') & 0xffffffc0ffffffc0ffffffc0fffffff
        self.s = int.from_bytes(key[16:], 'little')
        self.acc = 0

    def add(self, msg, length=None, pad=False):
        """Add a message of any length. Input so far must be a multiple of 16 bytes."""
        length = len(msg) if length is None else length
        for i in range((length + 15) // 16):
            chunk = msg[i * 16:i * 16 + min(16, length - i * 16)]
            val = int.from_bytes(chunk, 'little') + 256**(16 if pad else len(chunk))
            self.acc = (self.r * (self.acc + val)) % Poly1305.MODULUS
        return self

    def tag(self):
        """Compute the poly1305 tag."""
        return ((self.acc + self.s) & 0xffffffffffffffffffffffffffffffff).to_bytes(16, 'little')
