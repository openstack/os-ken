# Copyright (C) 2012 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import unittest
import logging
import struct
from struct import *
from os_ken.ofproto import ether, inet
from os_ken.lib.packet.ethernet import ethernet
from os_ken.lib.packet.arp import arp
from os_ken.lib import addrconv


LOG = logging.getLogger('test_ethernet')


class Test_ethernet(unittest.TestCase):
    """ Test case for ethernet
    """

    dst = 'aa:aa:aa:aa:aa:aa'
    src = 'bb:bb:bb:bb:bb:bb'
    ethertype = ether.ETH_TYPE_ARP

    buf = pack(ethernet._PACK_STR,
               addrconv.mac.text_to_bin(dst),
               addrconv.mac.text_to_bin(src), ethertype)

    e = ethernet(dst, src, ethertype)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def find_protocol(self, pkt, name):
        for p in pkt.protocols:
            if p.protocol_name == name:
                return p

    def test_init(self):
        self.assertEqual(self.dst, self.e.dst)
        self.assertEqual(self.src, self.e.src)
        self.assertEqual(self.ethertype, self.e.ethertype)

    def test_parser(self):
        res, ptype, _ = self.e.parser(self.buf)
        LOG.debug((res, ptype))

        self.assertEqual(res.dst, self.dst)
        self.assertEqual(res.src, self.src)
        self.assertEqual(res.ethertype, self.ethertype)
        self.assertEqual(ptype, arp)

    def test_serialize(self):
        data = bytearray()
        prev = None
        buf = self.e.serialize(data, prev)

        fmt = ethernet._PACK_STR
        res = struct.unpack(fmt, buf)

        self.assertEqual(res[0], addrconv.mac.text_to_bin(self.dst))
        self.assertEqual(res[1], addrconv.mac.text_to_bin(self.src))
        self.assertEqual(res[2], self.ethertype)

    def test_malformed_ethernet(self):
        m_short_buf = self.buf[1:ethernet._MIN_LEN]
        self.assertRaises(Exception, ethernet.parser, m_short_buf)

    def test_default_args(self):
        e = ethernet()
        buf = e.serialize(bytearray(), None)
        res = struct.unpack(e._PACK_STR, bytes(buf))

        self.assertEqual(res[0], addrconv.mac.text_to_bin('ff:ff:ff:ff:ff:ff'))
        self.assertEqual(res[1], addrconv.mac.text_to_bin('00:00:00:00:00:00'))
        self.assertEqual(res[2], ether.ETH_TYPE_IP)

    def test_json(self):
        jsondict = self.e.to_jsondict()
        e = ethernet.from_jsondict(jsondict['ethernet'])
        self.assertEqual(str(self.e), str(e))
