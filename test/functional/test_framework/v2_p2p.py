#!/usr/bin/env python3
# Copyright (c) 2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Class for v2 P2P protocol (see BIP 324)"""

import logging
import os
import random

from .bip324_cipher import FSChaCha20, FSChaCha20Poly1305
from .ellswift import ellswift_create, ellswift_ecdh_xonly
from .key import hkdf_sha256, TaggedHash

logger = logging.getLogger("TestFramework.v2_p2p")

MAGIC_BYTES = {
    "regtest": b"\xfa\xbf\xb5\xda"   # regtest
}
CHACHA20POLY1305_EXPANSION = 16
HEADER_LEN = 1
IGNORE_BIT_POS = 7
LENGTH_FIELD_LEN = 3
TRANSPORT_VERSION = b''
V1_PREFIX = MAGIC_BYTES["regtest"] + b'version\x00'

SHORTID = {
    13 : b"addr",
    14 : b"block",
    15 : b"blocktxn",
    16 : b"cmpctblock",
    17 : b"feefilter",
    18 : b"filteradd",
    19 : b"filterclear",
    20 : b"filterload",
    21 : b"getaddr",
    22 : b"getblocks",
    23 : b"getblocktxn",
    24 : b"getdata",
    25 : b"getheaders",
    26 : b"headers",
    27 : b"inv",
    28 : b"mempool",
    29 : b"merkleblock",
    30 : b"notfound",
    31 : b"ping",
    32 : b"pong",
    33 : b"sendcmpct",
    34 : b"sendheaders",
    35 : b"tx",
    36 : b"verack",
    37 : b"version",
    38 : b"getcfilters",
    39 : b"cfilter",
    40 : b"getcfheaders",
    41 : b"cfheaders",
    42 : b"getcfcheckpt",
    43 : b"cfcheckpt",
    44 : b"wtxidrelay",
    45 : b"addrv2",
    46 : b"sendaddrv2",
}

def GetShortIDFromMessageType(msgtype):
    """Returns 1-byte short message type ID for the P2P message"""
    msgtype_to_shortid = dict(map(reversed, SHORTID.items()))
    assert msgtype in msgtype_to_shortid
    return msgtype_to_shortid[msgtype].to_bytes(1, 'big')

class V2P2PEncryption:
    """A class for performing v2 P2P protocol functions:
    - perform the initial handshake(key exchange and version negotiation) to instantiate the encrypted transport
    - encrypt/decrypt v2 P2P messages
    """
    def __init__(self, **kwargs):
        self.initiating = kwargs['initiating'] # True if initiator
        self.peer = {} # object with various BIP324 derived keys and ciphers
        self.privkey_ours = None
        self.ellswift_ours = None
        self.sent_garbage = b""
        self.received_garbage = b""
        self.received_prefix = b"" # received ellswift bytes till the first mismatch from 12 bytes V1_PREFIX
        self.tried_v2_handshake = False # True when the initial handshake is over

    @staticmethod
    def v2_ecdh(priv, ellswift_theirs, ellswift_ours, initiating):
        """Compute BIP324 shared secret."""
        ecdh_point_x32 = ellswift_ecdh_xonly(ellswift_theirs, priv)
        if initiating:
            # Initiating, place our public key encoding first.
            return TaggedHash("bip324_ellswift_xonly_ecdh", ellswift_ours + ellswift_theirs + ecdh_point_x32)
        else:
            # Responding, place their public key encoding first.
            return TaggedHash("bip324_ellswift_xonly_ecdh", ellswift_theirs + ellswift_ours + ecdh_point_x32)

    def initiate_v2_handshake(self, garbage_len=random.randrange(4096)):
        self.privkey_ours, self.ellswift_ours = ellswift_create()
        self.sent_garbage = os.urandom(garbage_len)
        logger.debug("sending %d bytes of garbage data" % garbage_len)
        return self.ellswift_ours + self.sent_garbage

    def respond_v2_handshake(self, response, garbage_len=random.randrange(4096)):
        while len(self.received_prefix) < 12:
            byte = response.read(1)
            if not byte:
                return None
            self.received_prefix += byte
            if self.received_prefix[-1] != V1_PREFIX[len(self.received_prefix) - 1]:
                self.privkey_ours, self.ellswift_ours = ellswift_create()
                self.sent_garbage = os.urandom(garbage_len)
                logger.debug("sending %d bytes of garbage data" % garbage_len)
                return self.ellswift_ours + self.sent_garbage
        # only after all 12 bytes processed, we decide v1
        return -1

    def complete_handshake(self, response):
        received_prefix = b'' if self.initiating else self.received_prefix
        ellswift_theirs = received_prefix + response.read(64 - len(received_prefix))
        ecdh_secret = self.v2_ecdh(self.privkey_ours, ellswift_theirs, self.ellswift_ours, self.initiating)
        self.initialize_v2_transport(ecdh_secret)
        # Send garbage terminator + garbage authentication packet + version packet.
        return self.peer['send_garbage_terminator'] + self.v2_enc_packet(b'', aad=self.sent_garbage) + self.v2_enc_packet(TRANSPORT_VERSION)

    def authenticate_handshake(self, response):
        # Skip garbage, until encountering garbage terminator.
        received_garbage = response[:16]
        response = response[16:]
        if received_garbage != self.peer['recv_garbage_terminator']:
            return False
        # Receive, decode, and ignore garbage authentication packet (decoy or not)
        length, _ = self.v2_receive_packet(response, skip_decoy=False)
        if length == -1:
            return False
        response = response[length:]
        # Receive, decode, and ignore version packet, skipping decoys
        length, _ = self.v2_receive_packet(response)
        if length == -1:
            return False
        self.tried_v2_handshake=True
        return True

    def initialize_v2_transport(self, ecdh_secret):
        """Return a peer object with various BIP324 derived keys and ciphers."""
        peer = {}
        salt = b'bitcoin_v2_shared_secret' + MAGIC_BYTES["regtest"]
        for name, length in (
                ('initiator_L', 32), ('initiator_P', 32), ('responder_L', 32), ('responder_P', 32),
                ('garbage_terminators', 32), ('rekey_salt', 23), ('session_id', 32)):
            peer[name] = hkdf_sha256(salt=salt, ikm=ecdh_secret, info=name.encode('utf-8'), length=length)
        peer['initiator_garbage_terminator'] = peer['garbage_terminators'][:16]
        peer['responder_garbage_terminator'] = peer['garbage_terminators'][16:]
        del peer['garbage_terminators']
        if self.initiating:
            self.peer['send_L'] = FSChaCha20(peer['initiator_L'], peer['rekey_salt'])
            self.peer['send_P'] = FSChaCha20Poly1305(peer['initiator_P'], peer['rekey_salt'])
            self.peer['send_garbage_terminator'] = peer['initiator_garbage_terminator']
            self.peer['recv_L'] = FSChaCha20(peer['responder_L'], peer['rekey_salt'])
            self.peer['recv_P'] = FSChaCha20Poly1305(peer['responder_P'], peer['rekey_salt'])
            self.peer['recv_garbage_terminator'] = peer['responder_garbage_terminator']
        else:
            self.peer['send_L'] = FSChaCha20(peer['responder_L'], peer['rekey_salt'])
            self.peer['send_P'] = FSChaCha20Poly1305(peer['responder_P'], peer['rekey_salt'])
            self.peer['send_garbage_terminator'] = peer['responder_garbage_terminator']
            self.peer['recv_L'] = FSChaCha20(peer['initiator_L'], peer['rekey_salt'])
            self.peer['recv_P'] = FSChaCha20Poly1305(peer['initiator_P'], peer['rekey_salt'])
            self.peer['recv_garbage_terminator'] = peer['initiator_garbage_terminator']
        self.peer['session_id'] = peer['session_id']

    def v2_enc_packet(self, contents, aad=b'', ignore=False):
        """Encrypt a BIP324 packet."""
        assert len(contents) <= 2**24 - 1
        header = (ignore << IGNORE_BIT_POS).to_bytes(HEADER_LEN, 'little')
        plaintext = header + contents
        aead_ciphertext = self.peer['send_P'].encrypt(aad, plaintext)
        enc_plaintext_len = self.peer['send_L'].crypt(len(contents).to_bytes(LENGTH_FIELD_LEN, 'little'))
        return enc_plaintext_len + aead_ciphertext

    def v2_receive_packet(self, response, aad=b'', skip_decoy=True):
        """Decrypt a BIP324 packet"""
        if len(response) < LENGTH_FIELD_LEN:
            return 0, b""
        enc_contents_len = response[:LENGTH_FIELD_LEN]
        response = response[LENGTH_FIELD_LEN:]
        contents_len = int.from_bytes(self.peer['recv_L'].crypt(enc_contents_len), 'little')
        if len(response) < HEADER_LEN + contents_len + CHACHA20POLY1305_EXPANSION:
            return 0, b""
        aead_ciphertext = response[:HEADER_LEN + contents_len + CHACHA20POLY1305_EXPANSION]
        plaintext = self.peer['recv_P'].decrypt(aad, aead_ciphertext)
        if plaintext is None:
            return -1, None #disconnect
        header = plaintext[:HEADER_LEN]
        if not (skip_decoy and header[0] & (1 << IGNORE_BIT_POS)):
            return LENGTH_FIELD_LEN + HEADER_LEN + contents_len + CHACHA20POLY1305_EXPANSION, plaintext[HEADER_LEN:]
