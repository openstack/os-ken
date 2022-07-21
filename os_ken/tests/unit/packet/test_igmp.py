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

import unittest
import inspect
import logging

from struct import pack, unpack_from, pack_into
from os_ken.ofproto import ether
from os_ken.ofproto import inet
from os_ken.lib.packet.ethernet import ethernet
from os_ken.lib.packet.ipv4 import ipv4
from os_ken.lib.packet.packet import Packet
from os_ken.lib.packet.packet_utils import checksum
from os_ken.lib import addrconv
from os_ken.lib.packet.igmp import igmp
from os_ken.lib.packet.igmp import igmpv3_query
from os_ken.lib.packet.igmp import igmpv3_report
from os_ken.lib.packet.igmp import igmpv3_report_group
from os_ken.lib.packet.igmp import IGMP_TYPE_QUERY
from os_ken.lib.packet.igmp import IGMP_TYPE_REPORT_V3
from os_ken.lib.packet.igmp import MODE_IS_INCLUDE

LOG = logging.getLogger(__name__)


class Test_igmp(unittest.TestCase):
    """ Test case for Internet Group Management Protocol
    """

    def setUp(self):
        self.msgtype = IGMP_TYPE_QUERY
        self.maxresp = 100
        self.csum = 0
        self.address = '225.0.0.1'

        self.buf = pack(igmp._PACK_STR, self.msgtype, self.maxresp,
                        self.csum,
                        addrconv.ipv4.text_to_bin(self.address))

        self.g = igmp(self.msgtype, self.maxresp, self.csum,
                      self.address)

    def tearDown(self):
        pass

    def find_protocol(self, pkt, name):
        for p in pkt.protocols:
            if p.protocol_name == name:
                return p

    def test_init(self):
        self.assertEqual(self.msgtype, self.g.msgtype)
        self.assertEqual(self.maxresp, self.g.maxresp)
        self.assertEqual(self.csum, self.g.csum)
        self.assertEqual(self.address, self.g.address)

    def test_parser(self):
        _res = self.g.parser(self.buf)
        if type(_res) is tuple:
            res = _res[0]
        else:
            res = _res

        self.assertEqual(res.msgtype, self.msgtype)
        self.assertEqual(res.maxresp, self.maxresp)
        self.assertEqual(res.csum, self.csum)
        self.assertEqual(res.address, self.address)

    def test_serialize(self):
        data = bytearray()
        prev = None
        buf = self.g.serialize(data, prev)

        res = unpack_from(igmp._PACK_STR, bytes(buf))

        self.assertEqual(res[0], self.msgtype)
        self.assertEqual(res[1], self.maxresp)
        self.assertEqual(res[2], checksum(self.buf))
        self.assertEqual(res[3], addrconv.ipv4.text_to_bin(self.address))

    def _build_igmp(self):
        dl_dst = '11:22:33:44:55:66'
        dl_src = 'aa:bb:cc:dd:ee:ff'
        dl_type = ether.ETH_TYPE_IP
        e = ethernet(dl_dst, dl_src, dl_type)

        total_length = 20 + igmp._MIN_LEN
        nw_proto = inet.IPPROTO_IGMP
        nw_dst = '11.22.33.44'
        nw_src = '55.66.77.88'
        i = ipv4(total_length=total_length, src=nw_src, dst=nw_dst,
                 proto=nw_proto)

        p = Packet()

        p.add_protocol(e)
        p.add_protocol(i)
        p.add_protocol(self.g)
        p.serialize()
        return p

    def test_build_igmp(self):
        p = self._build_igmp()

        e = self.find_protocol(p, "ethernet")
        self.assertIsNotNone(e)
        self.assertEqual(e.ethertype, ether.ETH_TYPE_IP)

        i = self.find_protocol(p, "ipv4")
        self.assertTrue(i)
        self.assertEqual(i.proto, inet.IPPROTO_IGMP)

        g = self.find_protocol(p, "igmp")
        self.assertTrue(g)

        self.assertEqual(g.msgtype, self.msgtype)
        self.assertEqual(g.maxresp, self.maxresp)
        self.assertEqual(g.csum, checksum(self.buf))
        self.assertEqual(g.address, self.address)

    def test_to_string(self):
        igmp_values = {'msgtype': repr(self.msgtype),
                       'maxresp': repr(self.maxresp),
                       'csum': repr(self.csum),
                       'address': repr(self.address)}
        _g_str = ','.join(['%s=%s' % (k, igmp_values[k])
                           for k, v in inspect.getmembers(self.g)
                           if k in igmp_values])
        g_str = '%s(%s)' % (igmp.__name__, _g_str)

        self.assertEqual(str(self.g), g_str)
        self.assertEqual(repr(self.g), g_str)

    def test_malformed_igmp(self):
        m_short_buf = self.buf[1:igmp._MIN_LEN]
        self.assertRaises(Exception, igmp.parser, m_short_buf)

    def test_default_args(self):
        ig = igmp()
        buf = ig.serialize(bytearray(), None)
        res = unpack_from(igmp._PACK_STR, bytes(buf))

        self.assertEqual(res[0], 0x11)
        self.assertEqual(res[1], 0)
        self.assertEqual(res[3], addrconv.ipv4.text_to_bin('0.0.0.0'))

    def test_json(self):
        jsondict = self.g.to_jsondict()
        g = igmp.from_jsondict(jsondict['igmp'])
        self.assertEqual(str(self.g), str(g))


class Test_igmpv3_query(unittest.TestCase):
    """ Test case for Internet Group Management Protocol v3
    Membership Query Message"""

    def setUp(self):
        self.msgtype = IGMP_TYPE_QUERY
        self.maxresp = 100
        self.csum = 0
        self.address = '225.0.0.1'
        self.s_flg = 0
        self.qrv = 2
        self.qqic = 10
        self.num = 0
        self.srcs = []

        self.s_qrv = self.s_flg << 3 | self.qrv

        self.buf = pack(igmpv3_query._PACK_STR, self.msgtype,
                        self.maxresp, self.csum,
                        addrconv.ipv4.text_to_bin(self.address),
                        self.s_qrv, self.qqic, self.num)

        self.g = igmpv3_query(
            self.msgtype, self.maxresp, self.csum, self.address,
            self.s_flg, self.qrv, self.qqic, self.num, self.srcs)

    def setUp_with_srcs(self):
        self.srcs = ['192.168.1.1', '192.168.1.2', '192.168.1.3']
        self.num = len(self.srcs)
        self.buf = pack(igmpv3_query._PACK_STR, self.msgtype,
                        self.maxresp, self.csum,
                        addrconv.ipv4.text_to_bin(self.address),
                        self.s_qrv, self.qqic, self.num)
        for src in self.srcs:
            self.buf += pack('4s', addrconv.ipv4.text_to_bin(src))
        self.g = igmpv3_query(
            self.msgtype, self.maxresp, self.csum, self.address,
            self.s_flg, self.qrv, self.qqic, self.num, self.srcs)

    def tearDown(self):
        pass

    def find_protocol(self, pkt, name):
        for p in pkt.protocols:
            if p.protocol_name == name:
                return p

    def test_init(self):
        self.assertEqual(self.msgtype, self.g.msgtype)
        self.assertEqual(self.maxresp, self.g.maxresp)
        self.assertEqual(self.csum, self.g.csum)
        self.assertEqual(self.address, self.g.address)
        self.assertEqual(self.s_flg, self.g.s_flg)
        self.assertEqual(self.qrv, self.g.qrv)
        self.assertEqual(self.qqic, self.g.qqic)
        self.assertEqual(self.num, self.g.num)
        self.assertEqual(self.srcs, self.g.srcs)

    def test_init_with_srcs(self):
        self.setUp_with_srcs()
        self.test_init()

    def test_parser(self):
        _res = self.g.parser(self.buf)
        if type(_res) is tuple:
            res = _res[0]
        else:
            res = _res

        self.assertEqual(res.msgtype, self.msgtype)
        self.assertEqual(res.maxresp, self.maxresp)
        self.assertEqual(res.csum, self.csum)
        self.assertEqual(res.address, self.address)
        self.assertEqual(res.s_flg, self.s_flg)
        self.assertEqual(res.qrv, self.qrv)
        self.assertEqual(res.qqic, self.qqic)
        self.assertEqual(res.num, self.num)
        self.assertEqual(res.srcs, self.srcs)

    def test_parser_with_srcs(self):
        self.setUp_with_srcs()
        self.test_parser()

    def test_serialize(self):
        data = bytearray()
        prev = None
        buf = self.g.serialize(data, prev)

        res = unpack_from(igmpv3_query._PACK_STR, bytes(buf))

        self.assertEqual(res[0], self.msgtype)
        self.assertEqual(res[1], self.maxresp)
        self.assertEqual(res[2], checksum(self.buf))
        self.assertEqual(res[3], addrconv.ipv4.text_to_bin(self.address))
        self.assertEqual(res[4], self.s_qrv)
        self.assertEqual(res[5], self.qqic)
        self.assertEqual(res[6], self.num)

    def test_serialize_with_srcs(self):
        self.setUp_with_srcs()
        data = bytearray()
        prev = None
        buf = self.g.serialize(data, prev)

        res = unpack_from(igmpv3_query._PACK_STR, bytes(buf))
        (src1, src2, src3) = unpack_from('4s4s4s', bytes(buf),
                                         igmpv3_query._MIN_LEN)

        self.assertEqual(res[0], self.msgtype)
        self.assertEqual(res[1], self.maxresp)
        self.assertEqual(res[2], checksum(self.buf))
        self.assertEqual(res[3], addrconv.ipv4.text_to_bin(self.address))
        self.assertEqual(res[4], self.s_qrv)
        self.assertEqual(res[5], self.qqic)
        self.assertEqual(res[6], self.num)
        self.assertEqual(src1, addrconv.ipv4.text_to_bin(self.srcs[0]))
        self.assertEqual(src2, addrconv.ipv4.text_to_bin(self.srcs[1]))
        self.assertEqual(src3, addrconv.ipv4.text_to_bin(self.srcs[2]))

    def _build_igmp(self):
        dl_dst = '11:22:33:44:55:66'
        dl_src = 'aa:bb:cc:dd:ee:ff'
        dl_type = ether.ETH_TYPE_IP
        e = ethernet(dl_dst, dl_src, dl_type)

        total_length = len(ipv4()) + len(self.g)
        nw_proto = inet.IPPROTO_IGMP
        nw_dst = '11.22.33.44'
        nw_src = '55.66.77.88'
        i = ipv4(total_length=total_length, src=nw_src, dst=nw_dst,
                 proto=nw_proto, ttl=1)

        p = Packet()

        p.add_protocol(e)
        p.add_protocol(i)
        p.add_protocol(self.g)
        p.serialize()
        return p

    def test_build_igmp(self):
        p = self._build_igmp()

        e = self.find_protocol(p, "ethernet")
        self.assertTrue(e)
        self.assertEqual(e.ethertype, ether.ETH_TYPE_IP)

        i = self.find_protocol(p, "ipv4")
        self.assertTrue(i)
        self.assertEqual(i.proto, inet.IPPROTO_IGMP)

        g = self.find_protocol(p, "igmpv3_query")
        self.assertTrue(g)

        self.assertEqual(g.msgtype, self.msgtype)
        self.assertEqual(g.maxresp, self.maxresp)
        self.assertEqual(g.csum, checksum(self.buf))
        self.assertEqual(g.address, self.address)
        self.assertEqual(g.s_flg, self.s_flg)
        self.assertEqual(g.qrv, self.qrv)
        self.assertEqual(g.qqic, self.qqic)
        self.assertEqual(g.num, self.num)
        self.assertEqual(g.srcs, self.srcs)

    def test_build_igmp_with_srcs(self):
        self.setUp_with_srcs()
        self.test_build_igmp()

    def test_to_string(self):
        igmp_values = {'msgtype': repr(self.msgtype),
                       'maxresp': repr(self.maxresp),
                       'csum': repr(self.csum),
                       'address': repr(self.address),
                       's_flg': repr(self.s_flg),
                       'qrv': repr(self.qrv),
                       'qqic': repr(self.qqic),
                       'num': repr(self.num),
                       'srcs': repr(self.srcs)}
        _g_str = ','.join(['%s=%s' % (k, igmp_values[k])
                           for k, v in inspect.getmembers(self.g)
                           if k in igmp_values])
        g_str = '%s(%s)' % (igmpv3_query.__name__, _g_str)

        self.assertEqual(str(self.g), g_str)
        self.assertEqual(repr(self.g), g_str)

    def test_to_string_with_srcs(self):
        self.setUp_with_srcs()
        self.test_to_string()

    def test_num_larger_than_srcs(self):
        self.srcs = ['192.168.1.1', '192.168.1.2', '192.168.1.3']
        self.num = len(self.srcs) + 1
        self.buf = pack(igmpv3_query._PACK_STR, self.msgtype,
                        self.maxresp, self.csum,
                        addrconv.ipv4.text_to_bin(self.address),
                        self.s_qrv, self.qqic, self.num)
        for src in self.srcs:
            self.buf += pack('4s', addrconv.ipv4.text_to_bin(src))
        self.g = igmpv3_query(
            self.msgtype, self.maxresp, self.csum, self.address,
            self.s_flg, self.qrv, self.qqic, self.num, self.srcs)
        self.assertRaises(Exception, self.test_parser)

    def test_num_smaller_than_srcs(self):
        self.srcs = ['192.168.1.1', '192.168.1.2', '192.168.1.3']
        self.num = len(self.srcs) - 1
        self.buf = pack(igmpv3_query._PACK_STR, self.msgtype,
                        self.maxresp, self.csum,
                        addrconv.ipv4.text_to_bin(self.address),
                        self.s_qrv, self.qqic, self.num)
        for src in self.srcs:
            self.buf += pack('4s', addrconv.ipv4.text_to_bin(src))
        self.g = igmpv3_query(
            self.msgtype, self.maxresp, self.csum, self.address,
            self.s_flg, self.qrv, self.qqic, self.num, self.srcs)
        self.assertRaises(Exception, self.test_parser)

    def test_default_args(self):
        prev = ipv4(proto=inet.IPPROTO_IGMP)
        g = igmpv3_query()
        prev.serialize(g, None)
        buf = g.serialize(bytearray(), prev)
        res = unpack_from(igmpv3_query._PACK_STR, bytes(buf))
        buf = bytearray(buf)
        pack_into('!H', buf, 2, 0)

        self.assertEqual(res[0], IGMP_TYPE_QUERY)
        self.assertEqual(res[1], 100)
        self.assertEqual(res[2], checksum(buf))
        self.assertEqual(res[3], addrconv.ipv4.text_to_bin('0.0.0.0'))
        self.assertEqual(res[4], 2)
        self.assertEqual(res[5], 0)
        self.assertEqual(res[6], 0)

        # srcs without num
        prev = ipv4(proto=inet.IPPROTO_IGMP)
        srcs = ['192.168.1.1', '192.168.1.2', '192.168.1.3']
        g = igmpv3_query(srcs=srcs)
        prev.serialize(g, None)
        buf = g.serialize(bytearray(), prev)
        res = unpack_from(igmpv3_query._PACK_STR, bytes(buf))
        buf = bytearray(buf)
        pack_into('!H', buf, 2, 0)

        self.assertEqual(res[0], IGMP_TYPE_QUERY)
        self.assertEqual(res[1], 100)
        self.assertEqual(res[2], checksum(buf))
        self.assertEqual(res[3], addrconv.ipv4.text_to_bin('0.0.0.0'))
        self.assertEqual(res[4], 2)
        self.assertEqual(res[5], 0)
        self.assertEqual(res[6], len(srcs))

        res = unpack_from('4s4s4s', bytes(buf), igmpv3_query._MIN_LEN)

        self.assertEqual(res[0], addrconv.ipv4.text_to_bin(srcs[0]))
        self.assertEqual(res[1], addrconv.ipv4.text_to_bin(srcs[1]))
        self.assertEqual(res[2], addrconv.ipv4.text_to_bin(srcs[2]))

    def test_json(self):
        jsondict = self.g.to_jsondict()
        g = igmpv3_query.from_jsondict(jsondict['igmpv3_query'])
        self.assertEqual(str(self.g), str(g))

    def test_json_with_srcs(self):
        self.setUp_with_srcs()
        self.test_json()


class Test_igmpv3_report(unittest.TestCase):
    """ Test case for Internet Group Management Protocol v3
    Membership Report Message"""

    def setUp(self):
        self.msgtype = IGMP_TYPE_REPORT_V3
        self.csum = 0
        self.record_num = 0
        self.records = []

        self.buf = pack(igmpv3_report._PACK_STR, self.msgtype,
                        self.csum, self.record_num)

        self.g = igmpv3_report(
            self.msgtype, self.csum, self.record_num, self.records)

    def setUp_with_records(self):
        self.record1 = igmpv3_report_group(
            MODE_IS_INCLUDE, 0, 0, '225.0.0.1')
        self.record2 = igmpv3_report_group(
            MODE_IS_INCLUDE, 0, 2, '225.0.0.2',
            ['172.16.10.10', '172.16.10.27'])
        self.record3 = igmpv3_report_group(
            MODE_IS_INCLUDE, 1, 0, '225.0.0.3', [], b'abc\x00')
        self.record4 = igmpv3_report_group(
            MODE_IS_INCLUDE, 2, 2, '225.0.0.4',
            ['172.16.10.10', '172.16.10.27'], b'abcde\x00\x00\x00')
        self.records = [self.record1, self.record2, self.record3,
                        self.record4]
        self.record_num = len(self.records)
        self.buf = pack(igmpv3_report._PACK_STR, self.msgtype,
                        self.csum, self.record_num)
        self.buf += self.record1.serialize()
        self.buf += self.record2.serialize()
        self.buf += self.record3.serialize()
        self.buf += self.record4.serialize()
        self.g = igmpv3_report(
            self.msgtype, self.csum, self.record_num, self.records)

    def tearDown(self):
        pass

    def find_protocol(self, pkt, name):
        for p in pkt.protocols:
            if p.protocol_name == name:
                return p

    def test_init(self):
        self.assertEqual(self.msgtype, self.g.msgtype)
        self.assertEqual(self.csum, self.g.csum)
        self.assertEqual(self.record_num, self.g.record_num)
        self.assertEqual(self.records, self.g.records)

    def test_init_with_records(self):
        self.setUp_with_records()
        self.test_init()

    def test_parser(self):
        _res = self.g.parser(bytes(self.buf))
        if type(_res) is tuple:
            res = _res[0]
        else:
            res = _res

        self.assertEqual(res.msgtype, self.msgtype)
        self.assertEqual(res.csum, self.csum)
        self.assertEqual(res.record_num, self.record_num)
        self.assertEqual(repr(res.records), repr(self.records))

    def test_parser_with_records(self):
        self.setUp_with_records()
        self.test_parser()

    def test_serialize(self):
        data = bytearray()
        prev = None
        buf = self.g.serialize(data, prev)

        res = unpack_from(igmpv3_report._PACK_STR, bytes(buf))

        self.assertEqual(res[0], self.msgtype)
        self.assertEqual(res[1], checksum(self.buf))
        self.assertEqual(res[2], self.record_num)

    def test_serialize_with_records(self):
        self.setUp_with_records()
        data = bytearray()
        prev = None
        buf = bytes(self.g.serialize(data, prev))

        res = unpack_from(igmpv3_report._PACK_STR, buf)
        offset = igmpv3_report._MIN_LEN
        rec1 = igmpv3_report_group.parser(buf[offset:])
        offset += len(rec1)
        rec2 = igmpv3_report_group.parser(buf[offset:])
        offset += len(rec2)
        rec3 = igmpv3_report_group.parser(buf[offset:])
        offset += len(rec3)
        rec4 = igmpv3_report_group.parser(buf[offset:])

        self.assertEqual(res[0], self.msgtype)
        self.assertEqual(res[1], checksum(self.buf))
        self.assertEqual(res[2], self.record_num)
        self.assertEqual(repr(rec1), repr(self.record1))
        self.assertEqual(repr(rec2), repr(self.record2))
        self.assertEqual(repr(rec3), repr(self.record3))
        self.assertEqual(repr(rec4), repr(self.record4))

    def _build_igmp(self):
        dl_dst = '11:22:33:44:55:66'
        dl_src = 'aa:bb:cc:dd:ee:ff'
        dl_type = ether.ETH_TYPE_IP
        e = ethernet(dl_dst, dl_src, dl_type)

        total_length = len(ipv4()) + len(self.g)
        nw_proto = inet.IPPROTO_IGMP
        nw_dst = '11.22.33.44'
        nw_src = '55.66.77.88'
        i = ipv4(total_length=total_length, src=nw_src, dst=nw_dst,
                 proto=nw_proto, ttl=1)

        p = Packet()

        p.add_protocol(e)
        p.add_protocol(i)
        p.add_protocol(self.g)
        p.serialize()
        return p

    def test_build_igmp(self):
        p = self._build_igmp()

        e = self.find_protocol(p, "ethernet")
        self.assertTrue(e)
        self.assertEqual(e.ethertype, ether.ETH_TYPE_IP)

        i = self.find_protocol(p, "ipv4")
        self.assertTrue(i)
        self.assertEqual(i.proto, inet.IPPROTO_IGMP)

        g = self.find_protocol(p, "igmpv3_report")
        self.assertTrue(g)

        self.assertEqual(g.msgtype, self.msgtype)
        self.assertEqual(g.csum, checksum(self.buf))
        self.assertEqual(g.record_num, self.record_num)
        self.assertEqual(g.records, self.records)

    def test_build_igmp_with_records(self):
        self.setUp_with_records()
        self.test_build_igmp()

    def test_to_string(self):
        igmp_values = {'msgtype': repr(self.msgtype),
                       'csum': repr(self.csum),
                       'record_num': repr(self.record_num),
                       'records': repr(self.records)}
        _g_str = ','.join(['%s=%s' % (k, igmp_values[k])
                           for k, v in inspect.getmembers(self.g)
                           if k in igmp_values])
        g_str = '%s(%s)' % (igmpv3_report.__name__, _g_str)

        self.assertEqual(str(self.g), g_str)
        self.assertEqual(repr(self.g), g_str)

    def test_to_string_with_records(self):
        self.setUp_with_records()
        self.test_to_string()

    def test_record_num_larger_than_records(self):
        self.record1 = igmpv3_report_group(
            MODE_IS_INCLUDE, 0, 0, '225.0.0.1')
        self.record2 = igmpv3_report_group(
            MODE_IS_INCLUDE, 0, 2, '225.0.0.2',
            ['172.16.10.10', '172.16.10.27'])
        self.record3 = igmpv3_report_group(
            MODE_IS_INCLUDE, 1, 0, '225.0.0.3', [], b'abc\x00')
        self.record4 = igmpv3_report_group(
            MODE_IS_INCLUDE, 1, 2, '225.0.0.4',
            ['172.16.10.10', '172.16.10.27'], b'abc\x00')
        self.records = [self.record1, self.record2, self.record3,
                        self.record4]
        self.record_num = len(self.records) + 1
        self.buf = pack(igmpv3_report._PACK_STR, self.msgtype,
                        self.csum, self.record_num)
        self.buf += self.record1.serialize()
        self.buf += self.record2.serialize()
        self.buf += self.record3.serialize()
        self.buf += self.record4.serialize()
        self.g = igmpv3_report(
            self.msgtype, self.csum, self.record_num, self.records)
        self.assertRaises(Exception, self.test_parser)

    def test_record_num_smaller_than_records(self):
        self.record1 = igmpv3_report_group(
            MODE_IS_INCLUDE, 0, 0, '225.0.0.1')
        self.record2 = igmpv3_report_group(
            MODE_IS_INCLUDE, 0, 2, '225.0.0.2',
            ['172.16.10.10', '172.16.10.27'])
        self.record3 = igmpv3_report_group(
            MODE_IS_INCLUDE, 1, 0, '225.0.0.3', [], b'abc\x00')
        self.record4 = igmpv3_report_group(
            MODE_IS_INCLUDE, 1, 2, '225.0.0.4',
            ['172.16.10.10', '172.16.10.27'], b'abc\x00')
        self.records = [self.record1, self.record2, self.record3,
                        self.record4]
        self.record_num = len(self.records) - 1
        self.buf = pack(igmpv3_report._PACK_STR, self.msgtype,
                        self.csum, self.record_num)
        self.buf += self.record1.serialize()
        self.buf += self.record2.serialize()
        self.buf += self.record3.serialize()
        self.buf += self.record4.serialize()
        self.g = igmpv3_report(
            self.msgtype, self.csum, self.record_num, self.records)
        self.assertRaises(Exception, self.test_parser)

    def test_default_args(self):
        prev = ipv4(proto=inet.IPPROTO_IGMP)
        g = igmpv3_report()
        prev.serialize(g, None)
        buf = g.serialize(bytearray(), prev)
        res = unpack_from(igmpv3_report._PACK_STR, bytes(buf))
        buf = bytearray(buf)
        pack_into('!H', buf, 2, 0)

        self.assertEqual(res[0], IGMP_TYPE_REPORT_V3)
        self.assertEqual(res[1], checksum(buf))
        self.assertEqual(res[2], 0)

        # records without record_num
        prev = ipv4(proto=inet.IPPROTO_IGMP)
        record1 = igmpv3_report_group(
            MODE_IS_INCLUDE, 0, 0, '225.0.0.1')
        record2 = igmpv3_report_group(
            MODE_IS_INCLUDE, 0, 2, '225.0.0.2',
            ['172.16.10.10', '172.16.10.27'])
        record3 = igmpv3_report_group(
            MODE_IS_INCLUDE, 1, 0, '225.0.0.3', [], b'abc\x00')
        record4 = igmpv3_report_group(
            MODE_IS_INCLUDE, 1, 2, '225.0.0.4',
            ['172.16.10.10', '172.16.10.27'], b'abc\x00')
        records = [record1, record2, record3, record4]
        g = igmpv3_report(records=records)
        prev.serialize(g, None)
        buf = g.serialize(bytearray(), prev)
        res = unpack_from(igmpv3_report._PACK_STR, bytes(buf))
        buf = bytearray(buf)
        pack_into('!H', buf, 2, 0)

        self.assertEqual(res[0], IGMP_TYPE_REPORT_V3)
        self.assertEqual(res[1], checksum(buf))
        self.assertEqual(res[2], len(records))

    def test_json(self):
        jsondict = self.g.to_jsondict()
        g = igmpv3_report.from_jsondict(jsondict['igmpv3_report'])
        self.assertEqual(str(self.g), str(g))

    def test_json_with_records(self):
        self.setUp_with_records()
        self.test_json()


class Test_igmpv3_report_group(unittest.TestCase):
    """Test case for Group Records of
    Internet Group Management Protocol v3 Membership Report Message"""

    def setUp(self):
        self.type_ = MODE_IS_INCLUDE
        self.aux_len = 0
        self.num = 0
        self.address = '225.0.0.1'
        self.srcs = []
        self.aux = None

        self.buf = pack(igmpv3_report_group._PACK_STR, self.type_,
                        self.aux_len, self.num,
                        addrconv.ipv4.text_to_bin(self.address))

        self.g = igmpv3_report_group(
            self.type_, self.aux_len, self.num, self.address,
            self.srcs, self.aux)

    def setUp_with_srcs(self):
        self.srcs = ['192.168.1.1', '192.168.1.2', '192.168.1.3']
        self.num = len(self.srcs)
        self.buf = pack(igmpv3_report_group._PACK_STR, self.type_,
                        self.aux_len, self.num,
                        addrconv.ipv4.text_to_bin(self.address))
        for src in self.srcs:
            self.buf += pack('4s', addrconv.ipv4.text_to_bin(src))
        self.g = igmpv3_report_group(
            self.type_, self.aux_len, self.num, self.address,
            self.srcs, self.aux)

    def setUp_with_aux(self):
        self.aux = b'\x01\x02\x03\x04\x05\x00\x00\x00'
        self.aux_len = len(self.aux) // 4
        self.buf = pack(igmpv3_report_group._PACK_STR, self.type_,
                        self.aux_len, self.num,
                        addrconv.ipv4.text_to_bin(self.address))
        self.buf += self.aux
        self.g = igmpv3_report_group(
            self.type_, self.aux_len, self.num, self.address,
            self.srcs, self.aux)

    def setUp_with_srcs_and_aux(self):
        self.srcs = ['192.168.1.1', '192.168.1.2', '192.168.1.3']
        self.num = len(self.srcs)
        self.aux = b'\x01\x02\x03\x04\x05\x00\x00\x00'
        self.aux_len = len(self.aux) // 4
        self.buf = pack(igmpv3_report_group._PACK_STR, self.type_,
                        self.aux_len, self.num,
                        addrconv.ipv4.text_to_bin(self.address))
        for src in self.srcs:
            self.buf += pack('4s', addrconv.ipv4.text_to_bin(src))
        self.buf += self.aux
        self.g = igmpv3_report_group(
            self.type_, self.aux_len, self.num, self.address,
            self.srcs, self.aux)

    def tearDown(self):
        pass

    def test_init(self):
        self.assertEqual(self.type_, self.g.type_)
        self.assertEqual(self.aux_len, self.g.aux_len)
        self.assertEqual(self.num, self.g.num)
        self.assertEqual(self.address, self.g.address)
        self.assertEqual(self.srcs, self.g.srcs)
        self.assertEqual(self.aux, self.g.aux)

    def test_init_with_srcs(self):
        self.setUp_with_srcs()
        self.test_init()

    def test_init_with_aux(self):
        self.setUp_with_aux()
        self.test_init()

    def test_init_with_srcs_and_aux(self):
        self.setUp_with_srcs_and_aux()
        self.test_init()

    def test_parser(self):
        _res = self.g.parser(self.buf)
        if type(_res) is tuple:
            res = _res[0]
        else:
            res = _res

        self.assertEqual(res.type_, self.type_)
        self.assertEqual(res.aux_len, self.aux_len)
        self.assertEqual(res.num, self.num)
        self.assertEqual(res.address, self.address)
        self.assertEqual(res.srcs, self.srcs)
        self.assertEqual(res.aux, self.aux)

    def test_parser_with_srcs(self):
        self.setUp_with_srcs()
        self.test_parser()

    def test_parser_with_aux(self):
        self.setUp_with_aux()
        self.test_parser()

    def test_parser_with_srcs_and_aux(self):
        self.setUp_with_srcs_and_aux()
        self.test_parser()

    def test_serialize(self):
        buf = self.g.serialize()
        res = unpack_from(igmpv3_report_group._PACK_STR, bytes(buf))

        self.assertEqual(res[0], self.type_)
        self.assertEqual(res[1], self.aux_len)
        self.assertEqual(res[2], self.num)
        self.assertEqual(res[3], addrconv.ipv4.text_to_bin(self.address))

    def test_serialize_with_srcs(self):
        self.setUp_with_srcs()
        buf = self.g.serialize()
        res = unpack_from(igmpv3_report_group._PACK_STR, bytes(buf))
        (src1, src2, src3) = unpack_from('4s4s4s', bytes(buf),
                                         igmpv3_report_group._MIN_LEN)
        self.assertEqual(res[0], self.type_)
        self.assertEqual(res[1], self.aux_len)
        self.assertEqual(res[2], self.num)
        self.assertEqual(res[3], addrconv.ipv4.text_to_bin(self.address))
        self.assertEqual(src1, addrconv.ipv4.text_to_bin(self.srcs[0]))
        self.assertEqual(src2, addrconv.ipv4.text_to_bin(self.srcs[1]))
        self.assertEqual(src3, addrconv.ipv4.text_to_bin(self.srcs[2]))

    def test_serialize_with_aux(self):
        self.setUp_with_aux()
        buf = self.g.serialize()
        res = unpack_from(igmpv3_report_group._PACK_STR, bytes(buf))
        (aux, ) = unpack_from('%ds' % (self.aux_len * 4), bytes(buf),
                              igmpv3_report_group._MIN_LEN)
        self.assertEqual(res[0], self.type_)
        self.assertEqual(res[1], self.aux_len)
        self.assertEqual(res[2], self.num)
        self.assertEqual(res[3], addrconv.ipv4.text_to_bin(self.address))
        self.assertEqual(aux, self.aux)

    def test_serialize_with_srcs_and_aux(self):
        self.setUp_with_srcs_and_aux()
        buf = self.g.serialize()
        res = unpack_from(igmpv3_report_group._PACK_STR, bytes(buf))
        (src1, src2, src3) = unpack_from('4s4s4s', bytes(buf),
                                         igmpv3_report_group._MIN_LEN)
        (aux, ) = unpack_from('%ds' % (self.aux_len * 4), bytes(buf),
                              igmpv3_report_group._MIN_LEN + 12)
        self.assertEqual(res[0], self.type_)
        self.assertEqual(res[1], self.aux_len)
        self.assertEqual(res[2], self.num)
        self.assertEqual(res[3], addrconv.ipv4.text_to_bin(self.address))
        self.assertEqual(src1, addrconv.ipv4.text_to_bin(self.srcs[0]))
        self.assertEqual(src2, addrconv.ipv4.text_to_bin(self.srcs[1]))
        self.assertEqual(src3, addrconv.ipv4.text_to_bin(self.srcs[2]))
        self.assertEqual(aux, self.aux)

    def test_to_string(self):
        igmp_values = {'type_': repr(self.type_),
                       'aux_len': repr(self.aux_len),
                       'num': repr(self.num),
                       'address': repr(self.address),
                       'srcs': repr(self.srcs),
                       'aux': repr(self.aux)}
        _g_str = ','.join(['%s=%s' % (k, igmp_values[k])
                           for k, v in inspect.getmembers(self.g)
                           if k in igmp_values])
        g_str = '%s(%s)' % (igmpv3_report_group.__name__, _g_str)

        self.assertEqual(str(self.g), g_str)
        self.assertEqual(repr(self.g), g_str)

    def test_to_string_with_srcs(self):
        self.setUp_with_srcs()
        self.test_to_string()

    def test_to_string_with_aux(self):
        self.setUp_with_aux()
        self.test_to_string()

    def test_to_string_with_srcs_and_aux(self):
        self.setUp_with_srcs_and_aux()
        self.test_to_string()

    def test_len(self):
        self.assertEqual(len(self.g), 8)

    def test_len_with_srcs(self):
        self.setUp_with_srcs()
        self.assertEqual(len(self.g), 20)

    def test_len_with_aux(self):
        self.setUp_with_aux()
        self.assertEqual(len(self.g), 16)

    def test_len_with_srcs_and_aux(self):
        self.setUp_with_srcs_and_aux()
        self.assertEqual(len(self.g), 28)

    def test_num_larger_than_srcs(self):
        self.srcs = ['192.168.1.1', '192.168.1.2', '192.168.1.3']
        self.num = len(self.srcs) + 1
        self.buf = pack(igmpv3_report_group._PACK_STR, self.type_,
                        self.aux_len, self.num,
                        addrconv.ipv4.text_to_bin(self.address))
        for src in self.srcs:
            self.buf += pack('4s', addrconv.ipv4.text_to_bin(src))
        self.g = igmpv3_report_group(
            self.type_, self.aux_len, self.num, self.address,
            self.srcs, self.aux)
        self.assertRaises(AssertionError, self.test_parser)

    def test_num_smaller_than_srcs(self):
        self.srcs = ['192.168.1.1', '192.168.1.2', '192.168.1.3']
        self.num = len(self.srcs) - 1
        self.buf = pack(igmpv3_report_group._PACK_STR, self.type_,
                        self.aux_len, self.num,
                        addrconv.ipv4.text_to_bin(self.address))
        for src in self.srcs:
            self.buf += pack('4s', addrconv.ipv4.text_to_bin(src))
        self.g = igmpv3_report_group(
            self.type_, self.aux_len, self.num, self.address,
            self.srcs, self.aux)
        self.assertRaises(AssertionError, self.test_parser)

    def test_aux_len_larger_than_aux(self):
        self.aux = b'\x01\x02\x03\x04\x05\x00\x00\x00'
        self.aux_len = len(self.aux) // 4 + 1
        self.buf = pack(igmpv3_report_group._PACK_STR, self.type_,
                        self.aux_len, self.num,
                        addrconv.ipv4.text_to_bin(self.address))
        self.buf += self.aux
        self.g = igmpv3_report_group(
            self.type_, self.aux_len, self.num, self.address,
            self.srcs, self.aux)
        self.assertRaises(Exception, self.test_parser)

    def test_aux_len_smaller_than_aux(self):
        self.aux = b'\x01\x02\x03\x04\x05\x00\x00\x00'
        self.aux_len = len(self.aux) // 4 - 1
        self.buf = pack(igmpv3_report_group._PACK_STR, self.type_,
                        self.aux_len, self.num,
                        addrconv.ipv4.text_to_bin(self.address))
        self.buf += self.aux
        self.g = igmpv3_report_group(
            self.type_, self.aux_len, self.num, self.address,
            self.srcs, self.aux)
        self.assertRaises(AssertionError, self.test_parser)

    def test_default_args(self):
        rep = igmpv3_report_group()
        buf = rep.serialize()
        res = unpack_from(igmpv3_report_group._PACK_STR, bytes(buf))

        self.assertEqual(res[0], 0)
        self.assertEqual(res[1], 0)
        self.assertEqual(res[2], 0)
        self.assertEqual(res[3], addrconv.ipv4.text_to_bin('0.0.0.0'))

        # srcs without num
        srcs = ['192.168.1.1', '192.168.1.2', '192.168.1.3']
        rep = igmpv3_report_group(srcs=srcs)
        buf = rep.serialize()
        res = unpack_from(igmpv3_report_group._PACK_STR, bytes(buf))

        self.assertEqual(res[0], 0)
        self.assertEqual(res[1], 0)
        self.assertEqual(res[2], len(srcs))
        self.assertEqual(res[3], addrconv.ipv4.text_to_bin('0.0.0.0'))

        res = unpack_from('4s4s4s', bytes(buf),
                          igmpv3_report_group._MIN_LEN)

        self.assertEqual(res[0], addrconv.ipv4.text_to_bin(srcs[0]))
        self.assertEqual(res[1], addrconv.ipv4.text_to_bin(srcs[1]))
        self.assertEqual(res[2], addrconv.ipv4.text_to_bin(srcs[2]))

        # aux without aux_len
        aux = b'abcde'
        rep = igmpv3_report_group(aux=aux)
        buf = rep.serialize()
        res = unpack_from(igmpv3_report_group._PACK_STR, bytes(buf))

        self.assertEqual(res[0], 0)
        self.assertEqual(res[1], 2)
        self.assertEqual(res[2], 0)
        self.assertEqual(res[3], addrconv.ipv4.text_to_bin('0.0.0.0'))
        self.assertEqual(buf[igmpv3_report_group._MIN_LEN:], b'abcde\x00\x00\x00')
