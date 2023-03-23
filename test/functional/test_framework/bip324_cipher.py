#!/usr/bin/env python3
# Copyright (c) 2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""ChaCha20 Poly1305 AEAD Construction in RFC 8439, FSChaCha20Poly1305 and FSChaCha20 for BIP 324"""

from .chacha20 import chacha20_block
from .poly1305 import Poly1305

REKEY_INTERVAL = 224 # packets

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

class FSChaCha20Poly1305:
    """Rekeying wrapper AEAD around ChaCha20Poly1305."""
    def __init__(self, initial_key):
        self.key = initial_key
        self.packet_counter = 0

    def crypt(self, aad, text, is_decrypt):
        nonce = ((self.packet_counter % REKEY_INTERVAL).to_bytes(4, 'little') +
                 (self.packet_counter // REKEY_INTERVAL).to_bytes(8, 'little'))
        if is_decrypt:
            ret = aead_chacha20_poly1305_decrypt(self.key, nonce, aad, text)
        else:
            ret = aead_chacha20_poly1305_encrypt(self.key, nonce, aad, text)
        if (self.packet_counter + 1) % REKEY_INTERVAL == 0:
            rekey_nonce = b"\xFF\xFF\xFF\xFF" + nonce[4:]
            self.key = aead_chacha20_poly1305_encrypt(self.key, rekey_nonce, b"", b"\x00" * 32)[:32]
        self.packet_counter += 1
        return ret

    def decrypt(self, aad, ciphertext):
        return self.crypt(aad, ciphertext, True)

    def encrypt(self, aad, plaintext):
        return self.crypt(aad, plaintext, False)

class FSChaCha20:
    """Rekeying wrapper stream cipher around ChaCha20."""
    def __init__(self, initial_key):
        self.key = initial_key
        self.block_counter = 0
        self.chunk_counter = 0
        self.keystream = b''

    def get_keystream_bytes(self, nbytes):
        while len(self.keystream) < nbytes:
            nonce = ((0).to_bytes(4, 'little') + (self.chunk_counter // REKEY_INTERVAL).to_bytes(8, 'little'))
            self.keystream += chacha20_block(self.key, nonce, self.block_counter)
            self.block_counter += 1
        ret = self.keystream[:nbytes]
        self.keystream = self.keystream[nbytes:]
        return ret

    def crypt(self, chunk):
        ks = self.get_keystream_bytes(len(chunk))
        ret = bytes([ks[i] ^ chunk[i] for i in range(len(chunk))])
        if ((self.chunk_counter + 1) % REKEY_INTERVAL) == 0:
            self.key = self.get_keystream_bytes(32)
            self.block_counter = 0
        self.chunk_counter += 1
        return ret
