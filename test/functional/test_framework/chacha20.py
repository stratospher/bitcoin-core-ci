#!/usr/bin/env python3
# Copyright (c) 2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Python implementation of ChaCha20 cipher"""

CHACHA20_INDICES = (
    (0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15),
    (0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14)
)

CHACHA20_CONSTANTS = (0x61707865, 0x3320646e, 0x79622d32, 0x6b206574)

def rotl32(v, bits):
    """Rotate the 32-bit value v left by bits bits."""
    return ((v << bits) & 0xffffffff) | (v >> (32 - bits))

def chacha20_doubleround(s):
    """Apply a ChaCha20 double round to 16-element state array s.
    See https://cr.yp.to/chacha/chacha-20080128.pdf and https://tools.ietf.org/html/rfc8439
    """
    for a, b, c, d in CHACHA20_INDICES:
        s[a] = (s[a] + s[b]) & 0xffffffff
        s[d] = rotl32(s[d] ^ s[a], 16)
        s[c] = (s[c] + s[d]) & 0xffffffff
        s[b] = rotl32(s[b] ^ s[c], 12)
        s[a] = (s[a] + s[b]) & 0xffffffff
        s[d] = rotl32(s[d] ^ s[a], 8)
        s[c] = (s[c] + s[d]) & 0xffffffff
        s[b] = rotl32(s[b] ^ s[c], 7)

def chacha20_block(key, nonce, cnt):
    """Compute the 64-byte output of the ChaCha20 block function.
    Takes as input a 32-byte key, 12-byte nonce, and 32-bit integer counter.
    """
    # Initial state.
    init = [0 for _ in range(16)]
    for i in range(4):
        init[i] = CHACHA20_CONSTANTS[i]
    for i in range(8):
        init[4 + i] = int.from_bytes(key[4 * i:4 * (i+1)], 'little')
    init[12] = cnt
    for i in range(3):
        init[13 + i] = int.from_bytes(nonce[4 * i:4 * (i+1)], 'little')
    # Perform 20 rounds.
    state = [v for v in init]
    for _ in range(10):
        chacha20_doubleround(state)
    # Add initial values back into state.
    for i in range(16):
        state[i] = (state[i] + init[i]) & 0xffffffff
    # Produce byte output
    return b''.join(state[i].to_bytes(4, 'little') for i in range(16))
