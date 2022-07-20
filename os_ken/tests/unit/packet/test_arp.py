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
from os_ken.ofproto import ether
from os_ken.lib.packet.ethernet import ethernet
from os_ken.lib.packet.packet import Packet
from os_ken.lib.packet.arp import arp
from os_ken.lib.packet.vlan import vlan
from os_ken.lib import addrconv


LOG = logging.getLogger('test_arp')


class Test_arp(unittest.TestCase):
    """ Test case for arp
    """

    hwtype = 1
    proto = 0x0800
    hlen = 6
    plen = 4
    opcode = 1
    src_mac = '00:07:0d:af:f4:54'
    src_ip = '24.166.172.1'
    dst_mac = '00:00:00:00:00:00'
    dst_ip = '24.166.173.159'

    fmt = arp._PACK_STR
    buf = pack(fmt, hwtype, proto, hlen, plen, opcode,
               addrconv.mac.text_to_bin(src_mac),
               addrconv.ipv4.text_to_bin(src_ip),
               addrconv.mac.text_to_bin(dst_mac),
               addrconv.ipv4.text_to_bin(dst_ip))

    a = arp(hwtype, proto, hlen, plen, opcode, src_mac, src_ip, dst_mac,
            dst_ip)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def find_protocol(self, pkt, name):
        for p in pkt.protocols:
            if p.protocol_name == name:
                return p

    def test_init(self):
        self.assertEqual(self.hwtype, self.a.hwtype)
        self.assertEqual(self.proto, self.a.proto)
        self.assertEqual(self.hlen, self.a.hlen)
        self.assertEqual(self.plen, self.a.plen)
        self.assertEqual(self.opcode, self.a.opcode)
        self.assertEqual(self.src_mac, self.a.src_mac)
        self.assertEqual(self.src_ip, self.a.src_ip)
        self.assertEqual(self.dst_mac, self.a.dst_mac)
        self.assertEqual(self.dst_ip, self.a.dst_ip)

    def test_parser(self):
        _res = self.a.parser(self.buf)
        if type(_res) is tuple:
            res = _res[0]
        else:
            res = _res

        self.assertEqual(res.hwtype, self.hwtype)
        self.assertEqual(res.proto, self.proto)
        self.assertEqual(res.hlen, self.hlen)
        self.assertEqual(res.plen, self.plen)
        self.assertEqual(res.opcode, self.opcode)
        self.assertEqual(res.src_mac, self.src_mac)
        self.assertEqual(res.src_ip, self.src_ip)
        self.assertEqual(res.dst_mac, self.dst_mac)
        self.assertEqual(res.dst_ip, self.dst_ip)

    def test_serialize(self):
        data = bytearray()
        prev = None
        buf = self.a.serialize(data, prev)

        fmt = arp._PACK_STR
        res = struct.unpack(fmt, buf)

        self.assertEqual(res[0], self.hwtype)
        self.assertEqual(res[1], self.proto)
        self.assertEqual(res[2], self.hlen)
        self.assertEqual(res[3], self.plen)
        self.assertEqual(res[4], self.opcode)
        self.assertEqual(res[5], addrconv.mac.text_to_bin(self.src_mac))
        self.assertEqual(res[6], addrconv.ipv4.text_to_bin(self.src_ip))
        self.assertEqual(res[7], addrconv.mac.text_to_bin(self.dst_mac))
        self.assertEqual(res[8], addrconv.ipv4.text_to_bin(self.dst_ip))

    def _build_arp(self, vlan_enabled):
        if vlan_enabled is True:
            ethertype = ether.ETH_TYPE_8021Q
            v = vlan(1, 1, 3, ether.ETH_TYPE_ARP)
        else:
            ethertype = ether.ETH_TYPE_ARP
        e = ethernet(self.dst_mac, self.src_mac, ethertype)
        p = Packet()

        p.add_protocol(e)
        if vlan_enabled is True:
            p.add_protocol(v)
        p.add_protocol(self.a)
        p.serialize()
        return p

    def test_build_arp_vlan(self):
        p = self._build_arp(True)

        e = self.find_protocol(p, "ethernet")
        self.assertTrue(e)
        self.assertEqual(e.ethertype, ether.ETH_TYPE_8021Q)

        v = self.find_protocol(p, "vlan")
        self.assertTrue(v)
        self.assertEqual(v.ethertype, ether.ETH_TYPE_ARP)

        a = self.find_protocol(p, "arp")
        self.assertTrue(a)

        self.assertEqual(a.hwtype, self.hwtype)
        self.assertEqual(a.proto, self.proto)
        self.assertEqual(a.hlen, self.hlen)
        self.assertEqual(a.plen, self.plen)
        self.assertEqual(a.opcode, self.opcode)
        self.assertEqual(a.src_mac, self.src_mac)
        self.assertEqual(a.src_ip, self.src_ip)
        self.assertEqual(a.dst_mac, self.dst_mac)
        self.assertEqual(a.dst_ip, self.dst_ip)

    def test_build_arp_novlan(self):
        p = self._build_arp(False)

        e = self.find_protocol(p, "ethernet")
        self.assertTrue(e)
        self.assertEqual(e.ethertype, ether.ETH_TYPE_ARP)

        a = self.find_protocol(p, "arp")
        self.assertTrue(a)

        self.assertEqual(a.hwtype, self.hwtype)
        self.assertEqual(a.proto, self.proto)
        self.assertEqual(a.hlen, self.hlen)
        self.assertEqual(a.plen, self.plen)
        self.assertEqual(a.opcode, self.opcode)
        self.assertEqual(a.src_mac, self.src_mac)
        self.assertEqual(a.src_ip, self.src_ip)
        self.assertEqual(a.dst_mac, self.dst_mac)
        self.assertEqual(a.dst_ip, self.dst_ip)

    def test_malformed_arp(self):
        m_short_buf = self.buf[1:arp._MIN_LEN]
        self.assertRaises(Exception, arp.parser, m_short_buf)

    def test_json(self):
        jsondict = self.a.to_jsondict()
        a = arp.from_jsondict(jsondict['arp'])
        self.assertEqual(str(self.a), str(a))
