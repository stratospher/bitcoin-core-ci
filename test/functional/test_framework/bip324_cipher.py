#!/usr/bin/env python3
# Copyright (c) 2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""ChaCha20 Poly1305 AEAD Construction in RFC 8439"""

from .chacha20 import chacha20_block
from .poly1305 import Poly1305

def aead_chacha20_poly1305_encrypt(key, nonce, aad, plaintext):
    """Encrypt a plaintext using ChaCha20Poly1305."""
    ret = bytearray()
    msg_len = len(plaintext)
    for i in range((msg_len + 63) // 64):
        now = min(64, msg_len - 64 * i)
        keystream = chacha20_block(key, nonce, i + 1)
        for j in range(now):
            ret.append(plaintext[j + 64 * i] ^ keystream[j])
    poly1305 = Poly1305(chacha20_block(key, nonce, 0)[:32])
    poly1305.add(aad, pad=True).add(ret, pad=True)
    poly1305.add(len(aad).to_bytes(8, 'little') + msg_len.to_bytes(8, 'little'))
    ret += poly1305.tag()
    return bytes(ret)

def aead_chacha20_poly1305_decrypt(key, nonce, aad, ciphertext):
    """Decrypt a ChaCha20Poly1305 ciphertext."""
    if len(ciphertext) < 16:
        return None
    msg_len = len(ciphertext) - 16
    poly1305 = Poly1305(chacha20_block(key, nonce, 0)[:32])
    poly1305.add(aad, pad=True)
    poly1305.add(ciphertext, length=msg_len, pad=True)
    poly1305.add(len(aad).to_bytes(8, 'little') + msg_len.to_bytes(8, 'little'))
    if ciphertext[-16:] != poly1305.tag():
        return None
    ret = bytearray()
    for i in range((msg_len + 63) // 64):
        now = min(64, msg_len - 64 * i)
        keystream = chacha20_block(key, nonce, i + 1)
        for j in range(now):
            ret.append(ciphertext[j + 64 * i] ^ keystream[j])
    return bytes(ret)
