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
from os_ken.ofproto import inet
from os_ken.lib.packet import packet_utils
from os_ken.lib.packet.ipv4 import ipv4
from os_ken.lib.packet.tcp import tcp
from os_ken.lib import addrconv


LOG = logging.getLogger('test_ipv4')


class Test_ipv4(unittest.TestCase):
    """ Test case for ipv4
    """

    version = 4
    header_length = 5 + 10
    ver_hlen = version << 4 | header_length
    tos = 0
    total_length = header_length + 64
    identification = 30774
    flags = 4
    offset = 1480
    flg_off = flags << 13 | offset
    ttl = 64
    proto = inet.IPPROTO_TCP
    csum = 0xadc6
    src = '131.151.32.21'
    dst = '131.151.32.129'
    length = header_length * 4
    option = b'\x86\x28\x00\x00\x00\x01\x01\x22' \
        + b'\x00\x01\xae\x00\x00\x00\x00\x00' \
        + b'\x00\x00\x00\x00\x00\x00\x00\x00' \
        + b'\x00\x00\x00\x00\x00\x00\x00\x00' \
        + b'\x00\x00\x00\x00\x00\x00\x00\x01'

    buf = pack(ipv4._PACK_STR, ver_hlen, tos, total_length, identification,
               flg_off, ttl, proto, csum,
               addrconv.ipv4.text_to_bin(src),
               addrconv.ipv4.text_to_bin(dst)) \
        + option

    ip = ipv4(version, header_length, tos, total_length, identification,
              flags, offset, ttl, proto, csum, src, dst, option)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        self.assertEqual(self.version, self.ip.version)
        self.assertEqual(self.header_length, self.ip.header_length)
        self.assertEqual(self.tos, self.ip.tos)
        self.assertEqual(self.total_length, self.ip.total_length)
        self.assertEqual(self.identification, self.ip.identification)
        self.assertEqual(self.flags, self.ip.flags)
        self.assertEqual(self.offset, self.ip.offset)
        self.assertEqual(self.ttl, self.ip.ttl)
        self.assertEqual(self.proto, self.ip.proto)
        self.assertEqual(self.csum, self.ip.csum)
        self.assertEqual(self.src, self.ip.src)
        self.assertEqual(self.dst, self.ip.dst)
        self.assertEqual(self.length, len(self.ip))
        self.assertEqual(self.option, self.ip.option)

    def test_parser(self):
        res, ptype, _ = self.ip.parser(self.buf)

        self.assertEqual(res.version, self.version)
        self.assertEqual(res.header_length, self.header_length)
        self.assertEqual(res.tos, self.tos)
        self.assertEqual(res.total_length, self.total_length)
        self.assertEqual(res.identification, self.identification)
        self.assertEqual(res.flags, self.flags)
        self.assertEqual(res.offset, self.offset)
        self.assertEqual(res.ttl, self.ttl)
        self.assertEqual(res.proto, self.proto)
        self.assertEqual(res.csum, self.csum)
        self.assertEqual(res.src, self.src)
        self.assertEqual(res.dst, self.dst)
        self.assertEqual(ptype, tcp)

    def test_serialize(self):
        buf = self.ip.serialize(bytearray(), None)
        res = struct.unpack_from(ipv4._PACK_STR, bytes(buf))
        option = buf[ipv4._MIN_LEN:ipv4._MIN_LEN + len(self.option)]

        self.assertEqual(res[0], self.ver_hlen)
        self.assertEqual(res[1], self.tos)
        self.assertEqual(res[2], self.total_length)
        self.assertEqual(res[3], self.identification)
        self.assertEqual(res[4], self.flg_off)
        self.assertEqual(res[5], self.ttl)
        self.assertEqual(res[6], self.proto)
        self.assertEqual(res[8], addrconv.ipv4.text_to_bin(self.src))
        self.assertEqual(res[9], addrconv.ipv4.text_to_bin(self.dst))
        self.assertEqual(option, self.option)

        # checksum
        csum = packet_utils.checksum(buf)
        self.assertEqual(csum, 0)

    def test_malformed_ipv4(self):
        m_short_buf = self.buf[1:ipv4._MIN_LEN]
        self.assertRaises(Exception, ipv4.parser, m_short_buf)

    def test_json(self):
        jsondict = self.ip.to_jsondict()
        ip = ipv4.from_jsondict(jsondict['ipv4'])
        self.assertEqual(str(self.ip), str(ip))
