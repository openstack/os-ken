# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
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

import logging
import struct
import unittest

from os_ken.ofproto import ether
from os_ken.ofproto import inet
from os_ken.lib.packet import ethernet
from os_ken.lib.packet import packet
from os_ken.lib.packet import ipv4
from os_ken.lib.packet import vlan
from os_ken.lib.packet import pbb


LOG = logging.getLogger(__name__)


class Test_itag(unittest.TestCase):

    pcp = 3
    dei = 0
    uca = 1
    sid = 16770000
    data = pcp << 29 | dei << 28 | uca << 27 | sid
    buf = struct.pack(pbb.itag._PACK_STR, data)
    it = pbb.itag(pcp, dei, uca, sid)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        self.assertEqual(self.pcp, self.it.pcp)
        self.assertEqual(self.dei, self.it.dei)
        self.assertEqual(self.uca, self.it.uca)
        self.assertEqual(self.sid, self.it.sid)

    def test_parser(self):
        _res = pbb.itag.parser(self.buf)
        if type(_res) is tuple:
            res = _res[0]
        else:
            res = _res
        self.assertEqual(res.pcp, self.pcp)
        self.assertEqual(res.dei, self.dei)
        self.assertEqual(res.uca, self.uca)
        self.assertEqual(res.sid, self.sid)

    def test_serialize(self):
        data = bytearray()
        prev = None
        buf = self.it.serialize(data, prev)
        res = struct.unpack(pbb.itag._PACK_STR, buf)
        self.assertEqual(res[0], self.data)

    def _build_itag(self):
        b_src_mac = '00:07:0d:af:f4:54'
        b_dst_mac = '00:00:00:00:00:00'
        b_ethertype = ether.ETH_TYPE_8021AD
        e1 = ethernet.ethernet(b_dst_mac, b_src_mac, b_ethertype)

        b_pcp = 0
        b_cfi = 0
        b_vid = 32
        b_ethertype = ether.ETH_TYPE_8021Q
        bt = vlan.svlan(b_pcp, b_cfi, b_vid, b_ethertype)

        c_src_mac = '11:11:11:11:11:11'
        c_dst_mac = 'aa:aa:aa:aa:aa:aa'
        c_ethertype = ether.ETH_TYPE_8021AD
        e2 = ethernet.ethernet(c_dst_mac, c_src_mac, c_ethertype)

        s_pcp = 0
        s_cfi = 0
        s_vid = 32
        s_ethertype = ether.ETH_TYPE_8021Q
        st = vlan.svlan(s_pcp, s_cfi, s_vid, s_ethertype)

        c_pcp = 0
        c_cfi = 0
        c_vid = 32
        c_ethertype = ether.ETH_TYPE_IP
        ct = vlan.vlan(c_pcp, c_cfi, c_vid, c_ethertype)

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
        ip = ipv4.ipv4(version, header_length, tos, total_length,
                       identification, flags, offset, ttl, proto, csum,
                       src, dst, option)

        p = packet.Packet()

        p.add_protocol(e1)
        p.add_protocol(bt)
        p.add_protocol(self.it)
        p.add_protocol(e2)
        p.add_protocol(st)
        p.add_protocol(ct)
        p.add_protocol(ip)
        p.serialize()

        return p

    def test_build_itag(self):
        p = self._build_itag()

        e = p.get_protocols(ethernet.ethernet)
        self.assertTrue(e)
        self.assertIsInstance(e, list)
        self.assertEqual(e[0].ethertype, ether.ETH_TYPE_8021AD)
        self.assertEqual(e[1].ethertype, ether.ETH_TYPE_8021AD)

        sv = p.get_protocols(vlan.svlan)
        self.assertTrue(sv)
        self.assertIsInstance(sv, list)
        self.assertEqual(sv[0].ethertype, ether.ETH_TYPE_8021Q)
        self.assertEqual(sv[1].ethertype, ether.ETH_TYPE_8021Q)

        it = p.get_protocol(pbb.itag)
        self.assertTrue(it)

        v = p.get_protocol(vlan.vlan)
        self.assertTrue(v)
        self.assertEqual(v.ethertype, ether.ETH_TYPE_IP)

        ip = p.get_protocol(ipv4.ipv4)
        self.assertTrue(ip)

        self.assertEqual(it.pcp, self.pcp)
        self.assertEqual(it.dei, self.dei)
        self.assertEqual(it.uca, self.uca)
        self.assertEqual(it.sid, self.sid)

    def test_malformed_itag(self):
        m_short_buf = self.buf[1:pbb.itag._MIN_LEN]
        self.assertRaises(Exception, pbb.itag.parser, m_short_buf)

    def test_json(self):
        jsondict = self.it.to_jsondict()
        it = pbb.itag.from_jsondict(jsondict['itag'])
        self.assertEqual(str(self.it), str(it))
