#!/usr/bin/env python3
# Copyright (c) 2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import os
import random

from test_framework.test_framework import BitcoinTestFramework
from test_framework.ellswift import ellswift_create
from test_framework.p2p import P2PInterface
from test_framework.v2_p2p import V2P2PEncryption

class StepwiseV2Handshake(V2P2PEncryption):
    def __init__(self):
        super().__init__(initiating=True)
        self.is_network_magic = True
        self.can_data_be_received = False

    def initiate_v2_handshake(self, garbage_len=random.randrange(4096)):
        if self.is_network_magic:
            self.privkey_ours, self.ellswift_ours = ellswift_create()
            self.sent_garbage = os.urandom(garbage_len)
            self.is_network_magic = False
            return b"\xfa\xbf\xb5\xda"
        else:
            self.can_data_be_received = True
            return self.ellswift_ours[4:] + self.sent_garbage

class PeerEarlyKey(P2PInterface):
    def __init__(self):
        super().__init__()
        self.v2_connection = None

    def connection_made(self, *args, **kwargs):
        self.v2_connection = StepwiseV2Handshake()
        super(PeerEarlyKey, self).connection_made(*args, **kwargs)

    def data_received(self, t):
        try:
            assert self.v2_connection.can_data_be_received
            super(PeerEarlyKey, self).data_received(t)
        except Exception:
            pass

class P2PEarlyKey(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.extra_args = [["-v2transport=1", "-peertimeout=3"]]

    def run_test(self):
        # testing BIP 324 "The responder waits until one byte is received which does not match the 12 bytes
        # consisting of the network magic followed by "version\x00"."
        self.log.info('Sending ellswift bytes in parts to ensure that response from responder is received only when')
        self.log.info('ellswift bytes have a mismatch from the 12 bytes(network magic followed by "version\\x00")')
        node0 = self.nodes[0]
        self.log.info('Sending first 4 bytes of ellswift which match network magic')
        self.log.info('If at all we received a response, data_received() would result in assertion failure since can_data_be_received = False')
        peer1 = node0.add_p2p_connection(PeerEarlyKey(), wait_for_verack=False, support_v2_p2p=True, advertise_v2_p2p=True)
        self.log.info('Sending next 60 bytes of ellswift and optional garbage bytes which are different from wanted 12 bytes for v1 connections')
        self.log.info('data_received() wouldn\'t result in assertion failure since can_data_be_received = True')
        initiator_hdata = peer1.v2_connection.initiate_v2_handshake()
        peer1.send_raw_message(initiator_hdata)
        peer1.wait_for_disconnect(timeout=5)
        self.log.info('successful disconnection when MITM happens in the key exchange phase')

if __name__ == '__main__':
    P2PEarlyKey().main()
