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

# vim: tabstop=4 shiftwidth=4 softtabstop=4

import unittest
import logging
import struct
from struct import *
from os_ken.ofproto import ether, inet
from os_ken.lib.packet.ethernet import ethernet
from os_ken.lib.packet.packet import Packet
from os_ken.lib.packet.ipv4 import ipv4
from os_ken.lib.packet.vlan import vlan
from os_ken.lib.packet.vlan import svlan


LOG = logging.getLogger('test_vlan')


class Test_vlan(unittest.TestCase):
    """ Test case for vlan
    """

    pcp = 0
    cfi = 0
    vid = 32
    tci = pcp << 15 | cfi << 12 | vid
    ethertype = ether.ETH_TYPE_IP

    buf = pack(vlan._PACK_STR, tci, ethertype)

    v = vlan(pcp, cfi, vid, ethertype)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def find_protocol(self, pkt, name):
        for p in pkt.protocols:
            if p.protocol_name == name:
                return p

    def test_init(self):
        self.assertEqual(self.pcp, self.v.pcp)
        self.assertEqual(self.cfi, self.v.cfi)
        self.assertEqual(self.vid, self.v.vid)
        self.assertEqual(self.ethertype, self.v.ethertype)

    def test_parser(self):
        res, ptype, _ = self.v.parser(self.buf)

        self.assertEqual(res.pcp, self.pcp)
        self.assertEqual(res.cfi, self.cfi)
        self.assertEqual(res.vid, self.vid)
        self.assertEqual(res.ethertype, self.ethertype)
        self.assertEqual(ptype, ipv4)

    def test_serialize(self):
        data = bytearray()
        prev = None
        buf = self.v.serialize(data, prev)

        fmt = vlan._PACK_STR
        res = struct.unpack(fmt, buf)

        self.assertEqual(res[0], self.tci)
        self.assertEqual(res[1], self.ethertype)

    def _build_vlan(self):
        src_mac = '00:07:0d:af:f4:54'
        dst_mac = '00:00:00:00:00:00'
        ethertype = ether.ETH_TYPE_8021Q
        e = ethernet(dst_mac, src_mac, ethertype)

        version = 4
        header_length = 20
        tos = 0
        total_length = 24
        identification = 0x8a5d
        flags = 0
        offset = 1480
        ttl = 64
        proto = inet.IPPROTO_ICMP
        csum = 0xa7f2
        src = '131.151.32.21'
        dst = '131.151.32.129'
        option = b'TEST'
        ip = ipv4(version, header_length, tos, total_length, identification,
                  flags, offset, ttl, proto, csum, src, dst, option)

        p = Packet()

        p.add_protocol(e)
        p.add_protocol(self.v)
        p.add_protocol(ip)
        p.serialize()

        return p

    def test_build_vlan(self):
        p = self._build_vlan()

        e = self.find_protocol(p, "ethernet")
        self.assertTrue(e)
        self.assertEqual(e.ethertype, ether.ETH_TYPE_8021Q)

        v = self.find_protocol(p, "vlan")
        self.assertTrue(v)
        self.assertEqual(v.ethertype, ether.ETH_TYPE_IP)

        ip = self.find_protocol(p, "ipv4")
        self.assertTrue(ip)

        self.assertEqual(v.pcp, self.pcp)
        self.assertEqual(v.cfi, self.cfi)
        self.assertEqual(v.vid, self.vid)
        self.assertEqual(v.ethertype, self.ethertype)

    def test_malformed_vlan(self):
        m_short_buf = self.buf[1:vlan._MIN_LEN]
        self.assertRaises(Exception, vlan.parser, m_short_buf)

    def test_json(self):
        jsondict = self.v.to_jsondict()
        v = vlan.from_jsondict(jsondict['vlan'])
        self.assertEqual(str(self.v), str(v))


class Test_svlan(unittest.TestCase):

    pcp = 0
    cfi = 0
    vid = 32
    tci = pcp << 15 | cfi << 12 | vid
    ethertype = ether.ETH_TYPE_8021Q

    buf = pack(svlan._PACK_STR, tci, ethertype)

    sv = svlan(pcp, cfi, vid, ethertype)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def find_protocol(self, pkt, name):
        for p in pkt.protocols:
            if p.protocol_name == name:
                return p

    def test_init(self):
        self.assertEqual(self.pcp, self.sv.pcp)
        self.assertEqual(self.cfi, self.sv.cfi)
        self.assertEqual(self.vid, self.sv.vid)
        self.assertEqual(self.ethertype, self.sv.ethertype)

    def test_parser(self):
        res, ptype, _ = self.sv.parser(self.buf)

        self.assertEqual(res.pcp, self.pcp)
        self.assertEqual(res.cfi, self.cfi)
        self.assertEqual(res.vid, self.vid)
        self.assertEqual(res.ethertype, self.ethertype)
        self.assertEqual(ptype, vlan)

    def test_serialize(self):
        data = bytearray()
        prev = None
        buf = self.sv.serialize(data, prev)

        fmt = svlan._PACK_STR
        res = struct.unpack(fmt, buf)

        self.assertEqual(res[0], self.tci)
        self.assertEqual(res[1], self.ethertype)

    def _build_svlan(self):
        src_mac = '00:07:0d:af:f4:54'
        dst_mac = '00:00:00:00:00:00'
        ethertype = ether.ETH_TYPE_8021AD
        e = ethernet(dst_mac, src_mac, ethertype)

        pcp = 0
        cfi = 0
        vid = 32
        tci = pcp << 15 | cfi << 12 | vid
        ethertype = ether.ETH_TYPE_IP
        v = vlan(pcp, cfi, vid, ethertype)

        version = 4
        header_length = 20
        tos = 0
        total_length = 24
        identification = 0x8a5d
        flags = 0
        offset = 1480
        ttl = 64
        proto = inet.IPPROTO_ICMP
        csum = 0xa7f2
        src = '131.151.32.21'
        dst = '131.151.32.129'
        option = b'TEST'
        ip = ipv4(version, header_length, tos, total_length, identification,
                  flags, offset, ttl, proto, csum, src, dst, option)

        p = Packet()

        p.add_protocol(e)
        p.add_protocol(self.sv)
        p.add_protocol(v)
        p.add_protocol(ip)
        p.serialize()

        return p

    def test_build_svlan(self):
        p = self._build_svlan()

        e = self.find_protocol(p, "ethernet")
        self.assertTrue(e)
        self.assertEqual(e.ethertype, ether.ETH_TYPE_8021AD)

        sv = self.find_protocol(p, "svlan")
        self.assertTrue(sv)
        self.assertEqual(sv.ethertype, ether.ETH_TYPE_8021Q)

        v = self.find_protocol(p, "vlan")
        self.assertTrue(v)
        self.assertEqual(v.ethertype, ether.ETH_TYPE_IP)

        ip = self.find_protocol(p, "ipv4")
        self.assertTrue(ip)

        self.assertEqual(sv.pcp, self.pcp)
        self.assertEqual(sv.cfi, self.cfi)
        self.assertEqual(sv.vid, self.vid)
        self.assertEqual(sv.ethertype, self.ethertype)

    def test_malformed_svlan(self):
        m_short_buf = self.buf[1:svlan._MIN_LEN]
        self.assertRaises(Exception, vlan.parser, m_short_buf)

    def test_json(self):
        jsondict = self.sv.to_jsondict()
        sv = svlan.from_jsondict(jsondict['svlan'])
        self.assertEqual(str(self.sv), str(sv))
