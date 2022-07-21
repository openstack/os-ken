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
import inspect

from os_ken.ofproto import ether, inet
from os_ken.lib.packet.ethernet import ethernet
from os_ken.lib.packet import icmpv6
from os_ken.lib.packet.ipv6 import ipv6
from os_ken.lib.packet import packet_utils
from os_ken.lib import addrconv


LOG = logging.getLogger(__name__)


def icmpv6_csum(prev, buf):
    ph = struct.pack('!16s16sI3xB',
                     addrconv.ipv6.text_to_bin(prev.src),
                     addrconv.ipv6.text_to_bin(prev.dst),
                     prev.payload_length, prev.nxt)
    h = bytearray(buf)
    struct.pack_into('!H', h, 2, 0)

    return packet_utils.checksum(ph + h)


class Test_icmpv6_header(unittest.TestCase):
    type_ = 255
    code = 0
    csum = 207
    buf = b'\xff\x00\x00\xcf'
    icmp = icmpv6.icmpv6(type_, code, 0)

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        self.assertEqual(self.type_, self.icmp.type_)
        self.assertEqual(self.code, self.icmp.code)
        self.assertEqual(0, self.icmp.csum)

    def test_parser(self):
        msg, n, _ = self.icmp.parser(self.buf)

        self.assertEqual(msg.type_, self.type_)
        self.assertEqual(msg.code, self.code)
        self.assertEqual(msg.csum, self.csum)
        self.assertEqual(msg.data, b'')
        self.assertEqual(n, None)

    def test_serialize(self):
        src_ipv6 = 'fe80::200:ff:fe00:ef'
        dst_ipv6 = 'fe80::200:ff:fe00:1'
        prev = ipv6(6, 0, 0, 4, 58, 255, src_ipv6, dst_ipv6)

        buf = self.icmp.serialize(bytearray(), prev)
        (type_, code, csum) = struct.unpack(self.icmp._PACK_STR, bytes(buf))

        self.assertEqual(type_, self.type_)
        self.assertEqual(code, self.code)
        self.assertEqual(csum, self.csum)

    def test_malformed_icmpv6(self):
        m_short_buf = self.buf[1:self.icmp._MIN_LEN]
        self.assertRaises(struct.error, self.icmp.parser, m_short_buf)

    def test_default_args(self):
        prev = ipv6(nxt=inet.IPPROTO_ICMPV6)
        ic = icmpv6.icmpv6()
        prev.serialize(ic, None)
        buf = ic.serialize(bytearray(), prev)
        res = struct.unpack(icmpv6.icmpv6._PACK_STR, bytes(buf))

        self.assertEqual(res[0], 0)
        self.assertEqual(res[1], 0)
        self.assertEqual(res[2], icmpv6_csum(prev, buf))

    def test_json(self):
        jsondict = self.icmp.to_jsondict()
        icmp = icmpv6.icmpv6.from_jsondict(jsondict['icmpv6'])
        self.assertEqual(str(self.icmp), str(icmp))


class Test_icmpv6_echo_request(unittest.TestCase):
    type_ = 128
    code = 0
    csum = 0xa572
    id_ = 0x7620
    seq = 0
    data = b'\x01\xc9\xe7\x36\xd3\x39\x06\x00'
    buf = b'\x80\x00\xa5\x72\x76\x20\x00\x00'

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        echo = icmpv6.echo(0, 0)
        self.assertEqual(echo.id, 0)
        self.assertEqual(echo.seq, 0)
        self.assertEqual(echo.data, None)

    def _test_parser(self, data=None):
        buf = self.buf + (data or b'')
        msg, n, _ = icmpv6.icmpv6.parser(buf)

        self.assertEqual(msg.type_, self.type_)
        self.assertEqual(msg.code, self.code)
        self.assertEqual(msg.csum, self.csum)
        self.assertEqual(msg.data.id, self.id_)
        self.assertEqual(msg.data.seq, self.seq)
        self.assertEqual(msg.data.data, data)
        self.assertEqual(n, None)

    def test_parser_without_data(self):
        self._test_parser()

    def test_parser_with_data(self):
        self._test_parser(self.data)

    def _test_serialize(self, echo_data=None):
        buf = self.buf + (echo_data or b'')
        src_ipv6 = '3ffe:507:0:1:200:86ff:fe05:80da'
        dst_ipv6 = '3ffe:501:0:1001::2'
        prev = ipv6(6, 0, 0, len(buf), 64, 255, src_ipv6, dst_ipv6)
        echo_csum = icmpv6_csum(prev, buf)

        echo = icmpv6.echo(self.id_, self.seq, echo_data)
        icmp = icmpv6.icmpv6(self.type_, self.code, 0, echo)
        buf = bytes(icmp.serialize(bytearray(), prev))

        (type_, code, csum) = struct.unpack_from(icmp._PACK_STR, buf, 0)
        (id_, seq) = struct.unpack_from(echo._PACK_STR, buf, icmp._MIN_LEN)
        data = buf[(icmp._MIN_LEN + echo._MIN_LEN):]
        data = data if len(data) != 0 else None

        self.assertEqual(type_, self.type_)
        self.assertEqual(code, self.code)
        self.assertEqual(csum, echo_csum)
        self.assertEqual(id_, self.id_)
        self.assertEqual(seq, self.seq)
        self.assertEqual(data, echo_data)

    def test_serialize_without_data(self):
        self._test_serialize()

    def test_serialize_with_data(self):
        self._test_serialize(self.data)

    def test_to_string(self):
        ec = icmpv6.echo(self.id_, self.seq, self.data)
        ic = icmpv6.icmpv6(self.type_, self.code, self.csum, ec)

        echo_values = {'id': self.id_,
                       'seq': self.seq,
                       'data': self.data}
        _echo_str = ','.join(['%s=%s' % (k, repr(echo_values[k]))
                              for k, v in inspect.getmembers(ec)
                              if k in echo_values])
        echo_str = '%s(%s)' % (icmpv6.echo.__name__, _echo_str)

        icmp_values = {'type_': repr(self.type_),
                       'code': repr(self.code),
                       'csum': repr(self.csum),
                       'data': echo_str}
        _ic_str = ','.join(['%s=%s' % (k, icmp_values[k])
                            for k, v in inspect.getmembers(ic)
                            if k in icmp_values])
        ic_str = '%s(%s)' % (icmpv6.icmpv6.__name__, _ic_str)

        self.assertEqual(str(ic), ic_str)
        self.assertEqual(repr(ic), ic_str)

    def test_default_args(self):
        prev = ipv6(nxt=inet.IPPROTO_ICMPV6)
        ic = icmpv6.icmpv6(
            type_=icmpv6.ICMPV6_ECHO_REQUEST, data=icmpv6.echo())
        prev.serialize(ic, None)
        buf = ic.serialize(bytearray(), prev)
        res = struct.unpack(icmpv6.icmpv6._PACK_STR, bytes(buf[:4]))

        self.assertEqual(res[0], icmpv6.ICMPV6_ECHO_REQUEST)
        self.assertEqual(res[1], 0)
        self.assertEqual(res[2], icmpv6_csum(prev, buf))

        res = struct.unpack(icmpv6.echo._PACK_STR, bytes(buf[4:]))

        self.assertEqual(res[0], 0)
        self.assertEqual(res[1], 0)

    def test_json(self):
        ec = icmpv6.echo(self.id_, self.seq, self.data)
        ic1 = icmpv6.icmpv6(self.type_, self.code, self.csum, ec)
        jsondict = ic1.to_jsondict()
        ic2 = icmpv6.icmpv6.from_jsondict(jsondict['icmpv6'])
        self.assertEqual(str(ic1), str(ic2))


class Test_icmpv6_echo_reply(Test_icmpv6_echo_request):
    def setUp(self):
        self.type_ = 129
        self.csum = 0xa472
        self.buf = b'\x81\x00\xa4\x72\x76\x20\x00\x00'

    def test_default_args(self):
        prev = ipv6(nxt=inet.IPPROTO_ICMPV6)
        ic = icmpv6.icmpv6(
            type_=icmpv6.ICMPV6_ECHO_REPLY, data=icmpv6.echo())
        prev.serialize(ic, None)
        buf = ic.serialize(bytearray(), prev)
        res = struct.unpack(icmpv6.icmpv6._PACK_STR, bytes(buf[:4]))

        self.assertEqual(res[0], icmpv6.ICMPV6_ECHO_REPLY)
        self.assertEqual(res[1], 0)
        self.assertEqual(res[2], icmpv6_csum(prev, buf))

        res = struct.unpack(icmpv6.echo._PACK_STR, bytes(buf[4:]))

        self.assertEqual(res[0], 0)
        self.assertEqual(res[1], 0)


class Test_icmpv6_neighbor_solicit(unittest.TestCase):
    type_ = 135
    code = 0
    csum = 0x952d
    res = 0
    dst = '3ffe:507:0:1:200:86ff:fe05:80da'
    nd_type = 1
    nd_length = 1
    nd_hw_src = '00:60:97:07:69:ea'
    data = b'\x01\x01\x00\x60\x97\x07\x69\xea'
    buf = b'\x87\x00\x95\x2d\x00\x00\x00\x00' \
        + b'\x3f\xfe\x05\x07\x00\x00\x00\x01' \
        + b'\x02\x00\x86\xff\xfe\x05\x80\xda'
    src_ipv6 = '3ffe:507:0:1:200:86ff:fe05:80da'
    dst_ipv6 = '3ffe:501:0:1001::2'

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        nd = icmpv6.nd_neighbor(self.res, self.dst)
        self.assertEqual(nd.res, self.res)
        self.assertEqual(nd.dst, self.dst)
        self.assertEqual(nd.option, None)

    def _test_parser(self, data=None):
        buf = self.buf + (data or b'')
        msg, n, _ = icmpv6.icmpv6.parser(buf)

        self.assertEqual(msg.type_, self.type_)
        self.assertEqual(msg.code, self.code)
        self.assertEqual(msg.csum, self.csum)
        self.assertEqual(msg.data.res, self.res)
        self.assertEqual(addrconv.ipv6.text_to_bin(msg.data.dst),
            addrconv.ipv6.text_to_bin(self.dst))
        self.assertEqual(n, None)
        if data:
            nd = msg.data.option
            self.assertEqual(nd.length, self.nd_length)
            self.assertEqual(nd.hw_src, self.nd_hw_src)
            self.assertEqual(nd.data, None)

    def test_parser_without_data(self):
        self._test_parser()

    def test_parser_with_data(self):
        self._test_parser(self.data)

    def test_serialize_without_data(self):
        nd = icmpv6.nd_neighbor(self.res, self.dst)
        prev = ipv6(6, 0, 0, 24, 64, 255, self.src_ipv6, self.dst_ipv6)
        nd_csum = icmpv6_csum(prev, self.buf)

        icmp = icmpv6.icmpv6(self.type_, self.code, 0, nd)
        buf = bytes(icmp.serialize(bytearray(), prev))

        (type_, code, csum) = struct.unpack_from(icmp._PACK_STR, buf, 0)
        (res, dst) = struct.unpack_from(nd._PACK_STR, buf, icmp._MIN_LEN)
        data = buf[(icmp._MIN_LEN + nd._MIN_LEN):]

        self.assertEqual(type_, self.type_)
        self.assertEqual(code, self.code)
        self.assertEqual(csum, nd_csum)
        self.assertEqual(res >> 29, self.res)
        self.assertEqual(dst, addrconv.ipv6.text_to_bin(self.dst))
        self.assertEqual(data, b'')

    def test_serialize_with_data(self):
        nd_opt = icmpv6.nd_option_sla(self.nd_length, self.nd_hw_src)
        nd = icmpv6.nd_neighbor(self.res, self.dst, nd_opt)
        prev = ipv6(6, 0, 0, 32, 64, 255, self.src_ipv6, self.dst_ipv6)
        nd_csum = icmpv6_csum(prev, self.buf + self.data)

        icmp = icmpv6.icmpv6(self.type_, self.code, 0, nd)
        buf = bytes(icmp.serialize(bytearray(), prev))

        (type_, code, csum) = struct.unpack_from(icmp._PACK_STR, buf, 0)
        (res, dst) = struct.unpack_from(nd._PACK_STR, buf, icmp._MIN_LEN)
        (nd_type, nd_length, nd_hw_src) = struct.unpack_from(
            nd_opt._PACK_STR, buf, icmp._MIN_LEN + nd._MIN_LEN)
        data = buf[(icmp._MIN_LEN + nd._MIN_LEN + 8):]

        self.assertEqual(type_, self.type_)
        self.assertEqual(code, self.code)
        self.assertEqual(csum, nd_csum)
        self.assertEqual(res >> 29, self.res)
        self.assertEqual(dst, addrconv.ipv6.text_to_bin(self.dst))
        self.assertEqual(nd_type, self.nd_type)
        self.assertEqual(nd_length, self.nd_length)
        self.assertEqual(nd_hw_src, addrconv.mac.text_to_bin(self.nd_hw_src))

    def test_to_string(self):
        nd_opt = icmpv6.nd_option_sla(self.nd_length, self.nd_hw_src)
        nd = icmpv6.nd_neighbor(self.res, self.dst, nd_opt)
        ic = icmpv6.icmpv6(self.type_, self.code, self.csum, nd)

        nd_opt_values = {'length': self.nd_length,
                         'hw_src': self.nd_hw_src,
                         'data': None}
        _nd_opt_str = ','.join(['%s=%s' % (k, repr(nd_opt_values[k]))
                                for k, v in inspect.getmembers(nd_opt)
                                if k in nd_opt_values])
        nd_opt_str = '%s(%s)' % (icmpv6.nd_option_sla.__name__, _nd_opt_str)

        nd_values = {'res': repr(nd.res),
                     'dst': repr(self.dst),
                     'option': nd_opt_str}
        _nd_str = ','.join(['%s=%s' % (k, nd_values[k])
                            for k, v in inspect.getmembers(nd)
                            if k in nd_values])
        nd_str = '%s(%s)' % (icmpv6.nd_neighbor.__name__, _nd_str)

        icmp_values = {'type_': repr(self.type_),
                       'code': repr(self.code),
                       'csum': repr(self.csum),
                       'data': nd_str}
        _ic_str = ','.join(['%s=%s' % (k, icmp_values[k])
                            for k, v in inspect.getmembers(ic)
                            if k in icmp_values])
        ic_str = '%s(%s)' % (icmpv6.icmpv6.__name__, _ic_str)

        self.assertEqual(str(ic), ic_str)
        self.assertEqual(repr(ic), ic_str)

    def test_default_args(self):
        prev = ipv6(nxt=inet.IPPROTO_ICMPV6)
        ic = icmpv6.icmpv6(
            type_=icmpv6.ND_NEIGHBOR_SOLICIT, data=icmpv6.nd_neighbor())
        prev.serialize(ic, None)
        buf = ic.serialize(bytearray(), prev)
        res = struct.unpack(icmpv6.icmpv6._PACK_STR, bytes(buf[:4]))

        self.assertEqual(res[0], icmpv6.ND_NEIGHBOR_SOLICIT)
        self.assertEqual(res[1], 0)
        self.assertEqual(res[2], icmpv6_csum(prev, buf))

        res = struct.unpack(icmpv6.nd_neighbor._PACK_STR, bytes(buf[4:]))

        self.assertEqual(res[0], 0)
        self.assertEqual(res[1], addrconv.ipv6.text_to_bin('::'))

        # with nd_option_sla
        prev = ipv6(nxt=inet.IPPROTO_ICMPV6)
        ic = icmpv6.icmpv6(
            type_=icmpv6.ND_NEIGHBOR_SOLICIT,
            data=icmpv6.nd_neighbor(
                option=icmpv6.nd_option_sla()))
        prev.serialize(ic, None)
        buf = ic.serialize(bytearray(), prev)
        res = struct.unpack(icmpv6.icmpv6._PACK_STR, bytes(buf[:4]))

        self.assertEqual(res[0], icmpv6.ND_NEIGHBOR_SOLICIT)
        self.assertEqual(res[1], 0)
        self.assertEqual(res[2], icmpv6_csum(prev, buf))

        res = struct.unpack(icmpv6.nd_neighbor._PACK_STR,
                            bytes(buf[4:24]))

        self.assertEqual(res[0], 0)
        self.assertEqual(res[1], addrconv.ipv6.text_to_bin('::'))

        res = struct.unpack(icmpv6.nd_option_sla._PACK_STR,
                            bytes(buf[24:]))

        self.assertEqual(res[0], icmpv6.ND_OPTION_SLA)
        self.assertEqual(res[1], len(icmpv6.nd_option_sla()) // 8)
        self.assertEqual(res[2], addrconv.mac.text_to_bin('00:00:00:00:00:00'))

    def test_json(self):
        nd_opt = icmpv6.nd_option_sla(self.nd_length, self.nd_hw_src)
        nd = icmpv6.nd_neighbor(self.res, self.dst, nd_opt)
        ic1 = icmpv6.icmpv6(self.type_, self.code, self.csum, nd)
        jsondict = ic1.to_jsondict()
        ic2 = icmpv6.icmpv6.from_jsondict(jsondict['icmpv6'])
        self.assertEqual(str(ic1), str(ic2))


class Test_icmpv6_neighbor_advert(Test_icmpv6_neighbor_solicit):
    def setUp(self):
        self.type_ = 136
        self.csum = 0xb8ba
        self.res = 7
        self.dst = '3ffe:507:0:1:260:97ff:fe07:69ea'
        self.nd_type = 2
        self.nd_length = 1
        self.nd_data = None
        self.nd_hw_src = '00:60:97:07:69:ea'
        self.data = b'\x02\x01\x00\x60\x97\x07\x69\xea'
        self.buf = b'\x88\x00\xb8\xba\xe0\x00\x00\x00' \
            + b'\x3f\xfe\x05\x07\x00\x00\x00\x01' \
            + b'\x02\x60\x97\xff\xfe\x07\x69\xea'

    def test_serialize_with_data(self):
        nd_opt = icmpv6.nd_option_tla(self.nd_length, self.nd_hw_src)
        nd = icmpv6.nd_neighbor(self.res, self.dst, nd_opt)
        prev = ipv6(6, 0, 0, 32, 64, 255, self.src_ipv6, self.dst_ipv6)
        nd_csum = icmpv6_csum(prev, self.buf + self.data)

        icmp = icmpv6.icmpv6(self.type_, self.code, 0, nd)
        buf = bytes(icmp.serialize(bytearray(), prev))

        (type_, code, csum) = struct.unpack_from(icmp._PACK_STR, buf, 0)
        (res, dst) = struct.unpack_from(nd._PACK_STR, buf, icmp._MIN_LEN)
        (nd_type, nd_length, nd_hw_src) = struct.unpack_from(
            nd_opt._PACK_STR, buf, icmp._MIN_LEN + nd._MIN_LEN)
        data = buf[(icmp._MIN_LEN + nd._MIN_LEN + 8):]

        self.assertEqual(type_, self.type_)
        self.assertEqual(code, self.code)
        self.assertEqual(csum, nd_csum)
        self.assertEqual(res >> 29, self.res)
        self.assertEqual(dst, addrconv.ipv6.text_to_bin(self.dst))
        self.assertEqual(nd_type, self.nd_type)
        self.assertEqual(nd_length, self.nd_length)
        self.assertEqual(nd_hw_src, addrconv.mac.text_to_bin(self.nd_hw_src))

    def test_to_string(self):
        nd_opt = icmpv6.nd_option_tla(self.nd_length, self.nd_hw_src)
        nd = icmpv6.nd_neighbor(self.res, self.dst, nd_opt)
        ic = icmpv6.icmpv6(self.type_, self.code, self.csum, nd)

        nd_opt_values = {'length': self.nd_length,
                         'hw_src': self.nd_hw_src,
                         'data': None}
        _nd_opt_str = ','.join(['%s=%s' % (k, repr(nd_opt_values[k]))
                                for k, v in inspect.getmembers(nd_opt)
                                if k in nd_opt_values])
        nd_opt_str = '%s(%s)' % (icmpv6.nd_option_tla.__name__, _nd_opt_str)

        nd_values = {'res': repr(nd.res),
                     'dst': repr(self.dst),
                     'option': nd_opt_str}
        _nd_str = ','.join(['%s=%s' % (k, nd_values[k])
                            for k, v in inspect.getmembers(nd)
                            if k in nd_values])
        nd_str = '%s(%s)' % (icmpv6.nd_neighbor.__name__, _nd_str)

        icmp_values = {'type_': repr(self.type_),
                       'code': repr(self.code),
                       'csum': repr(self.csum),
                       'data': nd_str}
        _ic_str = ','.join(['%s=%s' % (k, icmp_values[k])
                            for k, v in inspect.getmembers(ic)
                            if k in icmp_values])
        ic_str = '%s(%s)' % (icmpv6.icmpv6.__name__, _ic_str)

        self.assertEqual(str(ic), ic_str)
        self.assertEqual(repr(ic), ic_str)

    def test_default_args(self):
        prev = ipv6(nxt=inet.IPPROTO_ICMPV6)
        ic = icmpv6.icmpv6(
            type_=icmpv6.ND_NEIGHBOR_ADVERT, data=icmpv6.nd_neighbor())
        prev.serialize(ic, None)
        buf = ic.serialize(bytearray(), prev)
        res = struct.unpack(icmpv6.icmpv6._PACK_STR, bytes(buf[:4]))

        self.assertEqual(res[0], icmpv6.ND_NEIGHBOR_ADVERT)
        self.assertEqual(res[1], 0)
        self.assertEqual(res[2], icmpv6_csum(prev, buf))

        res = struct.unpack(icmpv6.nd_neighbor._PACK_STR, bytes(buf[4:]))

        self.assertEqual(res[0], 0)
        self.assertEqual(res[1], addrconv.ipv6.text_to_bin('::'))

        # with nd_option_tla
        prev = ipv6(nxt=inet.IPPROTO_ICMPV6)
        ic = icmpv6.icmpv6(
            type_=icmpv6.ND_NEIGHBOR_ADVERT,
            data=icmpv6.nd_neighbor(
                option=icmpv6.nd_option_tla()))
        prev.serialize(ic, None)
        buf = ic.serialize(bytearray(), prev)
        res = struct.unpack(icmpv6.icmpv6._PACK_STR, bytes(buf[:4]))

        self.assertEqual(res[0], icmpv6.ND_NEIGHBOR_ADVERT)
        self.assertEqual(res[1], 0)
        self.assertEqual(res[2], icmpv6_csum(prev, buf))

        res = struct.unpack(icmpv6.nd_neighbor._PACK_STR,
                            bytes(buf[4:24]))

        self.assertEqual(res[0], 0)
        self.assertEqual(res[1], addrconv.ipv6.text_to_bin('::'))

        res = struct.unpack(icmpv6.nd_option_tla._PACK_STR,
                            bytes(buf[24:]))

        self.assertEqual(res[0], icmpv6.ND_OPTION_TLA)
        self.assertEqual(res[1], len(icmpv6.nd_option_tla()) // 8)
        self.assertEqual(res[2], addrconv.mac.text_to_bin('00:00:00:00:00:00'))


class Test_icmpv6_router_solicit(unittest.TestCase):
    type_ = 133
    code = 0
    csum = 0x97d9
    res = 0
    nd_type = 1
    nd_length = 1
    nd_hw_src = '12:2d:a5:6d:bc:0f'
    data = b'\x00\x00\x00\x00\x01\x01\x12\x2d\xa5\x6d\xbc\x0f'
    buf = b'\x85\x00\x97\xd9'
    src_ipv6 = '3ffe:507:0:1:200:86ff:fe05:80da'
    dst_ipv6 = '3ffe:501:0:1001::2'

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        rs = icmpv6.nd_router_solicit(self.res)
        self.assertEqual(rs.res, self.res)
        self.assertEqual(rs.option, None)

    def _test_parser(self, data=None):
        buf = self.buf + (data or b'')
        msg, n, _ = icmpv6.icmpv6.parser(buf)

        self.assertEqual(msg.type_, self.type_)
        self.assertEqual(msg.code, self.code)
        self.assertEqual(msg.csum, self.csum)
        if data is not None:
            self.assertEqual(msg.data.res, self.res)
        self.assertEqual(n, None)
        if data:
            rs = msg.data.option
            self.assertEqual(rs.length, self.nd_length)
            self.assertEqual(rs.hw_src, self.nd_hw_src)
            self.assertEqual(rs.data, None)

    def test_parser_without_data(self):
        self._test_parser()

    def test_parser_with_data(self):
        self._test_parser(self.data)

    def test_serialize_without_data(self):
        rs = icmpv6.nd_router_solicit(self.res)
        prev = ipv6(6, 0, 0, 8, 64, 255, self.src_ipv6, self.dst_ipv6)
        rs_csum = icmpv6_csum(prev, self.buf)

        icmp = icmpv6.icmpv6(self.type_, self.code, 0, rs)
        buf = bytes(icmp.serialize(bytearray(), prev))

        (type_, code, csum) = struct.unpack_from(icmp._PACK_STR, buf, 0)
        res = struct.unpack_from(rs._PACK_STR, buf, icmp._MIN_LEN)
        data = buf[(icmp._MIN_LEN + rs._MIN_LEN):]

        self.assertEqual(type_, self.type_)
        self.assertEqual(code, self.code)
        self.assertEqual(csum, rs_csum)
        self.assertEqual(res[0], self.res)
        self.assertEqual(data, b'')

    def test_serialize_with_data(self):
        nd_opt = icmpv6.nd_option_sla(self.nd_length, self.nd_hw_src)
        rs = icmpv6.nd_router_solicit(self.res, nd_opt)
        prev = ipv6(6, 0, 0, 16, 64, 255, self.src_ipv6, self.dst_ipv6)
        rs_csum = icmpv6_csum(prev, self.buf + self.data)

        icmp = icmpv6.icmpv6(self.type_, self.code, 0, rs)
        buf = bytes(icmp.serialize(bytearray(), prev))

        (type_, code, csum) = struct.unpack_from(icmp._PACK_STR, buf, 0)
        res = struct.unpack_from(rs._PACK_STR, buf, icmp._MIN_LEN)
        (nd_type, nd_length, nd_hw_src) = struct.unpack_from(
            nd_opt._PACK_STR, buf, icmp._MIN_LEN + rs._MIN_LEN)
        data = buf[(icmp._MIN_LEN + rs._MIN_LEN + 8):]

        self.assertEqual(type_, self.type_)
        self.assertEqual(code, self.code)
        self.assertEqual(csum, rs_csum)
        self.assertEqual(res[0], self.res)
        self.assertEqual(nd_type, self.nd_type)
        self.assertEqual(nd_length, self.nd_length)
        self.assertEqual(nd_hw_src, addrconv.mac.text_to_bin(self.nd_hw_src))

    def test_to_string(self):
        nd_opt = icmpv6.nd_option_sla(self.nd_length, self.nd_hw_src)
        rs = icmpv6.nd_router_solicit(self.res, nd_opt)
        ic = icmpv6.icmpv6(self.type_, self.code, self.csum, rs)

        nd_opt_values = {'length': self.nd_length,
                         'hw_src': self.nd_hw_src,
                         'data': None}
        _nd_opt_str = ','.join(['%s=%s' % (k, repr(nd_opt_values[k]))
                                for k, v in inspect.getmembers(nd_opt)
                                if k in nd_opt_values])
        nd_opt_str = '%s(%s)' % (icmpv6.nd_option_sla.__name__, _nd_opt_str)

        rs_values = {'res': repr(rs.res),
                     'option': nd_opt_str}
        _rs_str = ','.join(['%s=%s' % (k, rs_values[k])
                            for k, v in inspect.getmembers(rs)
                            if k in rs_values])
        rs_str = '%s(%s)' % (icmpv6.nd_router_solicit.__name__, _rs_str)

        icmp_values = {'type_': repr(self.type_),
                       'code': repr(self.code),
                       'csum': repr(self.csum),
                       'data': rs_str}
        _ic_str = ','.join(['%s=%s' % (k, icmp_values[k])
                            for k, v in inspect.getmembers(ic)
                            if k in icmp_values])
        ic_str = '%s(%s)' % (icmpv6.icmpv6.__name__, _ic_str)

        self.assertEqual(str(ic), ic_str)
        self.assertEqual(repr(ic), ic_str)

    def test_default_args(self):
        prev = ipv6(nxt=inet.IPPROTO_ICMPV6)
        ic = icmpv6.icmpv6(
            type_=icmpv6.ND_ROUTER_SOLICIT, data=icmpv6.nd_router_solicit())
        prev.serialize(ic, None)
        buf = ic.serialize(bytearray(), prev)
        res = struct.unpack(icmpv6.icmpv6._PACK_STR, bytes(buf[:4]))

        self.assertEqual(res[0], icmpv6.ND_ROUTER_SOLICIT)
        self.assertEqual(res[1], 0)
        self.assertEqual(res[2], icmpv6_csum(prev, buf))

        res = struct.unpack(icmpv6.nd_router_solicit._PACK_STR,
                            bytes(buf[4:]))

        self.assertEqual(res[0], 0)

        # with nd_option_sla
        prev = ipv6(nxt=inet.IPPROTO_ICMPV6)
        ic = icmpv6.icmpv6(
            type_=icmpv6.ND_ROUTER_SOLICIT,
            data=icmpv6.nd_router_solicit(
                option=icmpv6.nd_option_sla()))
        prev.serialize(ic, None)
        buf = ic.serialize(bytearray(), prev)
        res = struct.unpack(icmpv6.icmpv6._PACK_STR, bytes(buf[:4]))

        self.assertEqual(res[0], icmpv6.ND_ROUTER_SOLICIT)
        self.assertEqual(res[1], 0)
        self.assertEqual(res[2], icmpv6_csum(prev, buf))

        res = struct.unpack(icmpv6.nd_router_solicit._PACK_STR,
                            bytes(buf[4:8]))

        self.assertEqual(res[0], 0)

        res = struct.unpack(icmpv6.nd_option_sla._PACK_STR,
                            bytes(buf[8:]))

        self.assertEqual(res[0], icmpv6.ND_OPTION_SLA)
        self.assertEqual(res[1], len(icmpv6.nd_option_sla()) // 8)
        self.assertEqual(res[2], addrconv.mac.text_to_bin('00:00:00:00:00:00'))

    def test_json(self):
        nd_opt = icmpv6.nd_option_sla(self.nd_length, self.nd_hw_src)
        rs = icmpv6.nd_router_solicit(self.res, nd_opt)
        ic1 = icmpv6.icmpv6(self.type_, self.code, self.csum, rs)
        jsondict = ic1.to_jsondict()
        ic2 = icmpv6.icmpv6.from_jsondict(jsondict['icmpv6'])
        self.assertEqual(str(ic1), str(ic2))


class Test_icmpv6_router_advert(unittest.TestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_default_args(self):
        prev = ipv6(nxt=inet.IPPROTO_ICMPV6)
        ic = icmpv6.icmpv6(
            type_=icmpv6.ND_ROUTER_ADVERT, data=icmpv6.nd_router_advert())
        prev.serialize(ic, None)
        buf = ic.serialize(bytearray(), prev)
        res = struct.unpack(icmpv6.icmpv6._PACK_STR, bytes(buf[:4]))

        self.assertEqual(res[0], icmpv6.ND_ROUTER_ADVERT)
        self.assertEqual(res[1], 0)
        self.assertEqual(res[2], icmpv6_csum(prev, buf))

        res = struct.unpack(icmpv6.nd_router_advert._PACK_STR,
                            bytes(buf[4:]))

        self.assertEqual(res[0], 0)
        self.assertEqual(res[1], 0)
        self.assertEqual(res[2], 0)
        self.assertEqual(res[3], 0)
        self.assertEqual(res[4], 0)

        # with nd_option_sla
        prev = ipv6(nxt=inet.IPPROTO_ICMPV6)
        ic = icmpv6.icmpv6(
            type_=icmpv6.ND_ROUTER_ADVERT,
            data=icmpv6.nd_router_advert(
                options=[icmpv6.nd_option_sla()]))
        prev.serialize(ic, None)
        buf = ic.serialize(bytearray(), prev)
        res = struct.unpack(icmpv6.icmpv6._PACK_STR, bytes(buf[:4]))

        self.assertEqual(res[0], icmpv6.ND_ROUTER_ADVERT)
        self.assertEqual(res[1], 0)
        self.assertEqual(res[2], icmpv6_csum(prev, buf))

        res = struct.unpack(icmpv6.nd_router_advert._PACK_STR,
                            bytes(buf[4:16]))

        self.assertEqual(res[0], 0)
        self.assertEqual(res[1], 0)
        self.assertEqual(res[2], 0)
        self.assertEqual(res[3], 0)
        self.assertEqual(res[4], 0)

        res = struct.unpack(icmpv6.nd_option_sla._PACK_STR,
                            bytes(buf[16:]))

        self.assertEqual(res[0], icmpv6.ND_OPTION_SLA)
        self.assertEqual(res[1], len(icmpv6.nd_option_sla()) // 8)
        self.assertEqual(res[2], addrconv.mac.text_to_bin('00:00:00:00:00:00'))

        # with nd_option_pi
        prev = ipv6(nxt=inet.IPPROTO_ICMPV6)
        ic = icmpv6.icmpv6(
            type_=icmpv6.ND_ROUTER_ADVERT,
            data=icmpv6.nd_router_advert(
                options=[icmpv6.nd_option_pi()]))
        prev.serialize(ic, None)
        buf = ic.serialize(bytearray(), prev)
        res = struct.unpack(icmpv6.icmpv6._PACK_STR, bytes(buf[:4]))

        self.assertEqual(res[0], icmpv6.ND_ROUTER_ADVERT)
        self.assertEqual(res[1], 0)
        self.assertEqual(res[2], icmpv6_csum(prev, buf))

        res = struct.unpack(icmpv6.nd_router_advert._PACK_STR,
                            bytes(buf[4:16]))

        self.assertEqual(res[0], 0)
        self.assertEqual(res[1], 0)
        self.assertEqual(res[2], 0)
        self.assertEqual(res[3], 0)
        self.assertEqual(res[4], 0)

        res = struct.unpack(icmpv6.nd_option_pi._PACK_STR,
                            bytes(buf[16:]))

        self.assertEqual(res[0], icmpv6.ND_OPTION_PI)
        self.assertEqual(res[1], 4)
        self.assertEqual(res[2], 0)
        self.assertEqual(res[3], 0)
        self.assertEqual(res[4], 0)
        self.assertEqual(res[5], 0)
        self.assertEqual(res[6], 0)
        self.assertEqual(res[7], addrconv.ipv6.text_to_bin('::'))

        # with nd_option_sla and nd_option_pi
        prev = ipv6(nxt=inet.IPPROTO_ICMPV6)
        ic = icmpv6.icmpv6(
            type_=icmpv6.ND_ROUTER_ADVERT,
            data=icmpv6.nd_router_advert(
                options=[icmpv6.nd_option_sla(), icmpv6.nd_option_pi()]))
        prev.serialize(ic, None)
        buf = ic.serialize(bytearray(), prev)
        res = struct.unpack(icmpv6.icmpv6._PACK_STR, bytes(buf[:4]))

        self.assertEqual(res[0], icmpv6.ND_ROUTER_ADVERT)
        self.assertEqual(res[1], 0)
        self.assertEqual(res[2], icmpv6_csum(prev, buf))

        res = struct.unpack(icmpv6.nd_router_advert._PACK_STR,
                            bytes(buf[4:16]))

        self.assertEqual(res[0], 0)
        self.assertEqual(res[1], 0)
        self.assertEqual(res[2], 0)
        self.assertEqual(res[3], 0)
        self.assertEqual(res[4], 0)

        res = struct.unpack(icmpv6.nd_option_sla._PACK_STR,
                            bytes(buf[16:24]))

        self.assertEqual(res[0], icmpv6.ND_OPTION_SLA)
        self.assertEqual(res[1], len(icmpv6.nd_option_sla()) // 8)
        self.assertEqual(res[2], addrconv.mac.text_to_bin('00:00:00:00:00:00'))

        res = struct.unpack(icmpv6.nd_option_pi._PACK_STR,
                            bytes(buf[24:]))

        self.assertEqual(res[0], icmpv6.ND_OPTION_PI)
        self.assertEqual(res[1], len(icmpv6.nd_option_pi()) // 8)
        self.assertEqual(res[2], 0)
        self.assertEqual(res[3], 0)
        self.assertEqual(res[4], 0)
        self.assertEqual(res[5], 0)
        self.assertEqual(res[6], 0)
        self.assertEqual(res[7], addrconv.ipv6.text_to_bin('::'))

    def test_json(self):
        ic1 = icmpv6.icmpv6(
            type_=icmpv6.ND_ROUTER_ADVERT,
            data=icmpv6.nd_router_advert(
                options=[icmpv6.nd_option_sla(), icmpv6.nd_option_pi()]))
        jsondict = ic1.to_jsondict()
        ic2 = icmpv6.icmpv6.from_jsondict(jsondict['icmpv6'])
        self.assertEqual(str(ic1), str(ic2))


class Test_icmpv6_nd_option_la(unittest.TestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_default_args(self):
        la = icmpv6.nd_option_sla()
        buf = la.serialize()
        res = struct.unpack(icmpv6.nd_option_sla._PACK_STR, bytes(buf))

        self.assertEqual(res[0], icmpv6.ND_OPTION_SLA)
        self.assertEqual(res[1], len(icmpv6.nd_option_sla()) // 8)
        self.assertEqual(res[2], addrconv.mac.text_to_bin('00:00:00:00:00:00'))

        # with nd_neighbor
        prev = ipv6(nxt=inet.IPPROTO_ICMPV6)
        ic = icmpv6.icmpv6(
            type_=icmpv6.ND_NEIGHBOR_ADVERT,
            data=icmpv6.nd_neighbor(
                option=icmpv6.nd_option_tla()))
        prev.serialize(ic, None)
        buf = ic.serialize(bytearray(), prev)
        res = struct.unpack(icmpv6.icmpv6._PACK_STR, bytes(buf[:4]))

        self.assertEqual(res[0], icmpv6.ND_NEIGHBOR_ADVERT)
        self.assertEqual(res[1], 0)
        self.assertEqual(res[2], icmpv6_csum(prev, buf))

        res = struct.unpack(icmpv6.nd_neighbor._PACK_STR,
                            bytes(buf[4:24]))

        self.assertEqual(res[0], 0)
        self.assertEqual(res[1], addrconv.ipv6.text_to_bin('::'))

        res = struct.unpack(icmpv6.nd_option_tla._PACK_STR,
                            bytes(buf[24:]))

        self.assertEqual(res[0], icmpv6.ND_OPTION_TLA)
        self.assertEqual(res[1], len(icmpv6.nd_option_tla()) // 8)
        self.assertEqual(res[2], addrconv.mac.text_to_bin('00:00:00:00:00:00'))

        # with nd_router_solicit
        prev = ipv6(nxt=inet.IPPROTO_ICMPV6)
        ic = icmpv6.icmpv6(
            type_=icmpv6.ND_ROUTER_SOLICIT,
            data=icmpv6.nd_router_solicit(
                option=icmpv6.nd_option_sla()))
        prev.serialize(ic, None)
        buf = ic.serialize(bytearray(), prev)
        res = struct.unpack(icmpv6.icmpv6._PACK_STR, bytes(buf[:4]))

        self.assertEqual(res[0], icmpv6.ND_ROUTER_SOLICIT)
        self.assertEqual(res[1], 0)
        self.assertEqual(res[2], icmpv6_csum(prev, buf))

        res = struct.unpack(icmpv6.nd_router_solicit._PACK_STR,
                            bytes(buf[4:8]))

        self.assertEqual(res[0], 0)

        res = struct.unpack(icmpv6.nd_option_sla._PACK_STR,
                            bytes(buf[8:]))

        self.assertEqual(res[0], icmpv6.ND_OPTION_SLA)
        self.assertEqual(res[1], len(icmpv6.nd_option_sla()) // 8)
        self.assertEqual(res[2], addrconv.mac.text_to_bin('00:00:00:00:00:00'))


class Test_icmpv6_nd_option_pi(unittest.TestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_default_args(self):
        pi = icmpv6.nd_option_pi()
        buf = pi.serialize()
        res = struct.unpack(icmpv6.nd_option_pi._PACK_STR, bytes(buf))

        self.assertEqual(res[0], icmpv6.ND_OPTION_PI)
        self.assertEqual(res[1], len(icmpv6.nd_option_pi()) // 8)
        self.assertEqual(res[2], 0)
        self.assertEqual(res[3], 0)
        self.assertEqual(res[4], 0)
        self.assertEqual(res[5], 0)
        self.assertEqual(res[6], 0)
        self.assertEqual(res[7], addrconv.ipv6.text_to_bin('::'))

        # with nd_router_advert
        prev = ipv6(nxt=inet.IPPROTO_ICMPV6)
        ic = icmpv6.icmpv6(
            type_=icmpv6.ND_ROUTER_ADVERT,
            data=icmpv6.nd_router_advert(
                options=[icmpv6.nd_option_pi()]))
        prev.serialize(ic, None)
        buf = ic.serialize(bytearray(), prev)
        res = struct.unpack(icmpv6.icmpv6._PACK_STR, bytes(buf[:4]))

        self.assertEqual(res[0], icmpv6.ND_ROUTER_ADVERT)
        self.assertEqual(res[1], 0)
        self.assertEqual(res[2], icmpv6_csum(prev, buf))

        res = struct.unpack(icmpv6.nd_router_advert._PACK_STR,
                            bytes(buf[4:16]))

        self.assertEqual(res[0], 0)
        self.assertEqual(res[1], 0)
        self.assertEqual(res[2], 0)
        self.assertEqual(res[3], 0)
        self.assertEqual(res[4], 0)

        res = struct.unpack(icmpv6.nd_option_pi._PACK_STR,
                            bytes(buf[16:]))

        self.assertEqual(res[0], icmpv6.ND_OPTION_PI)
        self.assertEqual(res[1], 4)
        self.assertEqual(res[2], 0)
        self.assertEqual(res[3], 0)
        self.assertEqual(res[4], 0)
        self.assertEqual(res[5], 0)
        self.assertEqual(res[6], 0)
        self.assertEqual(res[7], addrconv.ipv6.text_to_bin('::'))


class Test_icmpv6_membership_query(unittest.TestCase):
    type_ = 130
    code = 0
    csum = 0xb5a4
    maxresp = 10000
    address = 'ff08::1'
    buf = b'\x82\x00\xb5\xa4\x27\x10\x00\x00' \
        + b'\xff\x08\x00\x00\x00\x00\x00\x00' \
        + b'\x00\x00\x00\x00\x00\x00\x00\x01'

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        mld = icmpv6.mld(self.maxresp, self.address)
        self.assertEqual(mld.maxresp, self.maxresp)
        self.assertEqual(mld.address, self.address)

    def test_parser(self):
        msg, n, _ = icmpv6.icmpv6.parser(self.buf)

        self.assertEqual(msg.type_, self.type_)
        self.assertEqual(msg.code, self.code)
        self.assertEqual(msg.csum, self.csum)
        self.assertEqual(msg.data.maxresp, self.maxresp)
        self.assertEqual(msg.data.address, self.address)
        self.assertEqual(n, None)

    def test_serialize(self):
        src_ipv6 = '3ffe:507:0:1:200:86ff:fe05:80da'
        dst_ipv6 = '3ffe:501:0:1001::2'
        prev = ipv6(6, 0, 0, len(self.buf), 64, 255, src_ipv6, dst_ipv6)
        mld_csum = icmpv6_csum(prev, self.buf)

        mld = icmpv6.mld(self.maxresp, self.address)
        icmp = icmpv6.icmpv6(self.type_, self.code, 0, mld)
        buf = bytes(icmp.serialize(bytearray(), prev))

        (type_, code, csum) = struct.unpack_from(icmp._PACK_STR, buf, 0)
        (maxresp, address) = struct.unpack_from(
            mld._PACK_STR, buf, icmp._MIN_LEN)

        self.assertEqual(type_, self.type_)
        self.assertEqual(code, self.code)
        self.assertEqual(csum, mld_csum)
        self.assertEqual(maxresp, self.maxresp)
        self.assertEqual(address, addrconv.ipv6.text_to_bin(self.address))

    def test_to_string(self):
        ml = icmpv6.mld(self.maxresp, self.address)
        ic = icmpv6.icmpv6(self.type_, self.code, self.csum, ml)

        mld_values = {'maxresp': self.maxresp,
                      'address': self.address}
        _mld_str = ','.join(['%s=%s' % (k, repr(mld_values[k]))
                             for k, v in inspect.getmembers(ml)
                             if k in mld_values])
        mld_str = '%s(%s)' % (icmpv6.mld.__name__, _mld_str)

        icmp_values = {'type_': repr(self.type_),
                       'code': repr(self.code),
                       'csum': repr(self.csum),
                       'data': mld_str}
        _ic_str = ','.join(['%s=%s' % (k, icmp_values[k])
                            for k, v in inspect.getmembers(ic)
                            if k in icmp_values])
        ic_str = '%s(%s)' % (icmpv6.icmpv6.__name__, _ic_str)

        self.assertEqual(str(ic), ic_str)
        self.assertEqual(repr(ic), ic_str)

    def test_default_args(self):
        prev = ipv6(nxt=inet.IPPROTO_ICMPV6)
        ic = icmpv6.icmpv6(
            type_=icmpv6.MLD_LISTENER_QUERY, data=icmpv6.mld())
        prev.serialize(ic, None)
        buf = ic.serialize(bytearray(), prev)
        res = struct.unpack(icmpv6.icmpv6._PACK_STR, bytes(buf[:4]))

        self.assertEqual(res[0], icmpv6.MLD_LISTENER_QUERY)
        self.assertEqual(res[1], 0)
        self.assertEqual(res[2], icmpv6_csum(prev, buf))

        res = struct.unpack(icmpv6.mld._PACK_STR, bytes(buf[4:]))

        self.assertEqual(res[0], 0)
        self.assertEqual(res[1], addrconv.ipv6.text_to_bin('::'))

    def test_json(self):
        ic1 = icmpv6.icmpv6(
            type_=icmpv6.MLD_LISTENER_QUERY,
            data=icmpv6.mld())
        jsondict = ic1.to_jsondict()
        ic2 = icmpv6.icmpv6.from_jsondict(jsondict['icmpv6'])
        self.assertEqual(str(ic1), str(ic2))


class Test_icmpv6_membership_report(Test_icmpv6_membership_query):
    type_ = 131
    code = 0
    csum = 0xb4a4
    maxresp = 10000
    address = 'ff08::1'
    buf = b'\x83\x00\xb4\xa4\x27\x10\x00\x00' \
        + b'\xff\x08\x00\x00\x00\x00\x00\x00' \
        + b'\x00\x00\x00\x00\x00\x00\x00\x01'

    def test_json(self):
        ic1 = icmpv6.icmpv6(
            type_=icmpv6.MLD_LISTENER_REPOR,
            data=icmpv6.mld())
        jsondict = ic1.to_jsondict()
        ic2 = icmpv6.icmpv6.from_jsondict(jsondict['icmpv6'])
        self.assertEqual(str(ic1), str(ic2))


class Test_icmpv6_membership_done(Test_icmpv6_membership_query):
    type_ = 132
    code = 0
    csum = 0xb3a4
    maxresp = 10000
    address = 'ff08::1'
    buf = b'\x84\x00\xb3\xa4\x27\x10\x00\x00' \
        + b'\xff\x08\x00\x00\x00\x00\x00\x00' \
        + b'\x00\x00\x00\x00\x00\x00\x00\x01'

    def test_json(self):
        ic1 = icmpv6.icmpv6(
            type_=icmpv6.MLD_LISTENER_DONE,
            data=icmpv6.mld())
        jsondict = ic1.to_jsondict()
        ic2 = icmpv6.icmpv6.from_jsondict(jsondict['icmpv6'])
        self.assertEqual(str(ic1), str(ic2))


class Test_mldv2_query(unittest.TestCase):
    type_ = 130
    code = 0
    csum = 0xb5a4
    maxresp = 10000
    address = 'ff08::1'
    s_flg = 0
    qrv = 2
    s_qrv = s_flg << 3 | qrv
    qqic = 10
    num = 0
    srcs = []

    mld = icmpv6.mldv2_query(
        maxresp, address, s_flg, qrv, qqic, num, srcs)

    buf = b'\x82\x00\xb5\xa4\x27\x10\x00\x00' \
        + b'\xff\x08\x00\x00\x00\x00\x00\x00' \
        + b'\x00\x00\x00\x00\x00\x00\x00\x01' \
        + b'\x02\x0a\x00\x00'

    def setUp(self):
        pass

    def setUp_with_srcs(self):
        self.num = 2
        self.srcs = ['ff80::1', 'ff80::2']
        self.mld = icmpv6.mldv2_query(
            self.maxresp, self.address, self.s_flg, self.qrv, self.qqic,
            self.num, self.srcs)
        self.buf = b'\x82\x00\xb5\xa4\x27\x10\x00\x00' \
            + b'\xff\x08\x00\x00\x00\x00\x00\x00' \
            + b'\x00\x00\x00\x00\x00\x00\x00\x01' \
            + b'\x02\x0a\x00\x02' \
            + b'\xff\x80\x00\x00\x00\x00\x00\x00' \
            + b'\x00\x00\x00\x00\x00\x00\x00\x01' \
            + b'\xff\x80\x00\x00\x00\x00\x00\x00' \
            + b'\x00\x00\x00\x00\x00\x00\x00\x02'

    def tearDown(self):
        pass

    def find_protocol(self, pkt, name):
        for p in pkt.protocols:
            if p.protocol_name == name:
                return p

    def test_init(self):
        self.assertEqual(self.mld.maxresp, self.maxresp)
        self.assertEqual(self.mld.address, self.address)
        self.assertEqual(self.mld.s_flg, self.s_flg)
        self.assertEqual(self.mld.qrv, self.qrv)
        self.assertEqual(self.mld.qqic, self.qqic)
        self.assertEqual(self.mld.num, self.num)
        self.assertEqual(self.mld.srcs, self.srcs)

    def test_init_with_srcs(self):
        self.setUp_with_srcs()
        self.test_init()

    def test_parser(self):
        msg, n, _ = icmpv6.icmpv6.parser(self.buf)

        self.assertEqual(msg.type_, self.type_)
        self.assertEqual(msg.code, self.code)
        self.assertEqual(msg.csum, self.csum)
        self.assertEqual(msg.data.maxresp, self.maxresp)
        self.assertEqual(msg.data.address, self.address)
        self.assertEqual(msg.data.s_flg, self.s_flg)
        self.assertEqual(msg.data.qrv, self.qrv)
        self.assertEqual(msg.data.qqic, self.qqic)
        self.assertEqual(msg.data.num, self.num)
        self.assertEqual(msg.data.srcs, self.srcs)
        self.assertEqual(n, None)

    def test_parser_with_srcs(self):
        self.setUp_with_srcs()
        self.test_parser()

    def test_serialize(self):
        src_ipv6 = '3ffe:507:0:1:200:86ff:fe05:80da'
        dst_ipv6 = '3ffe:501:0:1001::2'
        prev = ipv6(6, 0, 0, len(self.buf), 64, 255, src_ipv6, dst_ipv6)
        mld_csum = icmpv6_csum(prev, self.buf)

        icmp = icmpv6.icmpv6(self.type_, self.code, 0, self.mld)
        buf = icmp.serialize(bytearray(), prev)

        (type_, code, csum) = struct.unpack_from(icmp._PACK_STR,
                                                 bytes(buf))
        (maxresp, address, s_qrv, qqic, num) = struct.unpack_from(
            self.mld._PACK_STR, bytes(buf), icmp._MIN_LEN)

        self.assertEqual(type_, self.type_)
        self.assertEqual(code, self.code)
        self.assertEqual(csum, mld_csum)
        self.assertEqual(maxresp, self.maxresp)
        self.assertEqual(address, addrconv.ipv6.text_to_bin(self.address))
        s_flg = (s_qrv >> 3) & 0b1
        qrv = s_qrv & 0b111
        self.assertEqual(s_flg, self.s_flg)
        self.assertEqual(qrv, self.qrv)
        self.assertEqual(qqic, self.qqic)
        self.assertEqual(num, self.num)

    def test_serialize_with_srcs(self):
        self.setUp_with_srcs()
        src_ipv6 = '3ffe:507:0:1:200:86ff:fe05:80da'
        dst_ipv6 = '3ffe:501:0:1001::2'
        prev = ipv6(6, 0, 0, len(self.buf), 64, 255, src_ipv6, dst_ipv6)
        mld_csum = icmpv6_csum(prev, self.buf)

        icmp = icmpv6.icmpv6(self.type_, self.code, 0, self.mld)
        buf = icmp.serialize(bytearray(), prev)

        (type_, code, csum) = struct.unpack_from(icmp._PACK_STR,
                                                 bytes(buf))
        (maxresp, address, s_qrv, qqic, num) = struct.unpack_from(
            self.mld._PACK_STR, bytes(buf), icmp._MIN_LEN)
        (addr1, addr2) = struct.unpack_from(
            '!16s16s', bytes(buf), icmp._MIN_LEN + self.mld._MIN_LEN)

        self.assertEqual(type_, self.type_)
        self.assertEqual(code, self.code)
        self.assertEqual(csum, mld_csum)
        self.assertEqual(maxresp, self.maxresp)
        self.assertEqual(address, addrconv.ipv6.text_to_bin(self.address))
        s_flg = (s_qrv >> 3) & 0b1
        qrv = s_qrv & 0b111
        self.assertEqual(s_flg, self.s_flg)
        self.assertEqual(qrv, self.qrv)
        self.assertEqual(qqic, self.qqic)
        self.assertEqual(num, self.num)
        self.assertEqual(addr1, addrconv.ipv6.text_to_bin(self.srcs[0]))
        self.assertEqual(addr2, addrconv.ipv6.text_to_bin(self.srcs[1]))

    def _build_mldv2_query(self):
        e = ethernet(ethertype=ether.ETH_TYPE_IPV6)
        i = ipv6(nxt=inet.IPPROTO_ICMPV6)
        ic = icmpv6.icmpv6(type_=icmpv6.MLD_LISTENER_QUERY,
                           data=self.mld)
        p = e / i / ic
        return p

    def test_build_mldv2_query(self):
        p = self._build_mldv2_query()

        e = self.find_protocol(p, "ethernet")
        self.assertTrue(e)
        self.assertEqual(e.ethertype, ether.ETH_TYPE_IPV6)

        i = self.find_protocol(p, "ipv6")
        self.assertTrue(i)
        self.assertEqual(i.nxt, inet.IPPROTO_ICMPV6)

        ic = self.find_protocol(p, "icmpv6")
        self.assertTrue(ic)
        self.assertEqual(ic.type_, icmpv6.MLD_LISTENER_QUERY)

        self.assertEqual(ic.data.maxresp, self.maxresp)
        self.assertEqual(ic.data.address, self.address)
        self.assertEqual(ic.data.s_flg, self.s_flg)
        self.assertEqual(ic.data.qrv, self.qrv)
        self.assertEqual(ic.data.num, self.num)
        self.assertEqual(ic.data.srcs, self.srcs)

    def test_build_mldv2_query_with_srcs(self):
        self.setUp_with_srcs()
        self.test_build_mldv2_query()

    def test_to_string(self):
        ic = icmpv6.icmpv6(self.type_, self.code, self.csum, self.mld)

        mld_values = {'maxresp': self.maxresp,
                      'address': self.address,
                      's_flg': self.s_flg,
                      'qrv': self.qrv,
                      'qqic': self.qqic,
                      'num': self.num,
                      'srcs': self.srcs}
        _mld_str = ','.join(['%s=%s' % (k, repr(mld_values[k]))
                             for k, v in inspect.getmembers(self.mld)
                             if k in mld_values])
        mld_str = '%s(%s)' % (icmpv6.mldv2_query.__name__, _mld_str)

        icmp_values = {'type_': repr(self.type_),
                       'code': repr(self.code),
                       'csum': repr(self.csum),
                       'data': mld_str}
        _ic_str = ','.join(['%s=%s' % (k, icmp_values[k])
                            for k, v in inspect.getmembers(ic)
                            if k in icmp_values])
        ic_str = '%s(%s)' % (icmpv6.icmpv6.__name__, _ic_str)

        self.assertEqual(str(ic), ic_str)
        self.assertEqual(repr(ic), ic_str)

    def test_to_string_with_srcs(self):
        self.setUp_with_srcs()
        self.test_to_string()

    def test_num_larger_than_srcs(self):
        self.srcs = ['ff80::1', 'ff80::2', 'ff80::3']
        self.num = len(self.srcs) + 1
        self.buf = struct.pack(
            icmpv6.mldv2_query._PACK_STR,
            self.maxresp, addrconv.ipv6.text_to_bin(self.address),
            self.s_qrv, self.qqic, self.num)
        for src in self.srcs:
            self.buf += struct.pack('16s', addrconv.ipv6.text_to_bin(src))
        self.mld = icmpv6.mldv2_query(
            self.maxresp, self.address, self.s_flg, self.qrv, self.qqic,
            self.num, self.srcs)
        self.assertRaises(AssertionError, self.test_parser)

    def test_num_smaller_than_srcs(self):
        self.srcs = ['ff80::1', 'ff80::2', 'ff80::3']
        self.num = len(self.srcs) - 1
        self.buf = struct.pack(
            icmpv6.mldv2_query._PACK_STR,
            self.maxresp, addrconv.ipv6.text_to_bin(self.address),
            self.s_qrv, self.qqic, self.num)
        for src in self.srcs:
            self.buf += struct.pack('16s', addrconv.ipv6.text_to_bin(src))
        self.mld = icmpv6.mldv2_query(
            self.maxresp, self.address, self.s_flg, self.qrv, self.qqic,
            self.num, self.srcs)
        self.assertRaises(AssertionError, self.test_parser)

    def test_default_args(self):
        prev = ipv6(nxt=inet.IPPROTO_ICMPV6)
        ic = icmpv6.icmpv6(
            type_=icmpv6.MLD_LISTENER_QUERY, data=icmpv6.mldv2_query())
        prev.serialize(ic, None)
        buf = ic.serialize(bytearray(), prev)
        res = struct.unpack(icmpv6.icmpv6._PACK_STR, bytes(buf[:4]))

        self.assertEqual(res[0], icmpv6.MLD_LISTENER_QUERY)
        self.assertEqual(res[1], 0)
        self.assertEqual(res[2], icmpv6_csum(prev, buf))

        res = struct.unpack(icmpv6.mldv2_query._PACK_STR, bytes(buf[4:]))

        self.assertEqual(res[0], 0)
        self.assertEqual(res[1], addrconv.ipv6.text_to_bin('::'))
        self.assertEqual(res[2], 2)
        self.assertEqual(res[3], 0)
        self.assertEqual(res[4], 0)

        # srcs without num
        srcs = ['ff80::1', 'ff80::2', 'ff80::3']
        que = icmpv6.mldv2_query(srcs=srcs)
        buf = que.serialize()
        res = struct.unpack_from(
            icmpv6.mldv2_query._PACK_STR, bytes(buf))

        self.assertEqual(res[0], 0)
        self.assertEqual(res[1], addrconv.ipv6.text_to_bin('::'))
        self.assertEqual(res[2], 2)
        self.assertEqual(res[3], 0)
        self.assertEqual(res[4], len(srcs))

        (src1, src2, src3) = struct.unpack_from(
            '16s16s16s', bytes(buf), icmpv6.mldv2_query._MIN_LEN)

        self.assertEqual(src1, addrconv.ipv6.text_to_bin(srcs[0]))
        self.assertEqual(src2, addrconv.ipv6.text_to_bin(srcs[1]))
        self.assertEqual(src3, addrconv.ipv6.text_to_bin(srcs[2]))

    def test_json(self):
        jsondict = self.mld.to_jsondict()
        mld = icmpv6.mldv2_query.from_jsondict(jsondict['mldv2_query'])
        self.assertEqual(str(self.mld), str(mld))

    def test_json_with_srcs(self):
        self.setUp_with_srcs()
        self.test_json()


class Test_mldv2_report(unittest.TestCase):
    type_ = 143
    code = 0
    csum = 0xb5a4
    record_num = 0
    records = []

    mld = icmpv6.mldv2_report(record_num, records)

    buf = b'\x8f\x00\xb5\xa4\x00\x00\x00\x00'

    def setUp(self):
        pass

    def setUp_with_records(self):
        self.record1 = icmpv6.mldv2_report_group(
            icmpv6.MODE_IS_INCLUDE, 0, 0, 'ff00::1')
        self.record2 = icmpv6.mldv2_report_group(
            icmpv6.MODE_IS_INCLUDE, 0, 2, 'ff00::2',
            ['fe80::1', 'fe80::2'])
        self.record3 = icmpv6.mldv2_report_group(
            icmpv6.MODE_IS_INCLUDE, 1, 0, 'ff00::3', [], b'abc\x00')
        self.record4 = icmpv6.mldv2_report_group(
            icmpv6.MODE_IS_INCLUDE, 2, 2, 'ff00::4',
            ['fe80::1', 'fe80::2'], b'abcde\x00\x00\x00')
        self.records = [self.record1, self.record2, self.record3,
                        self.record4]
        self.record_num = len(self.records)
        self.mld = icmpv6.mldv2_report(self.record_num, self.records)
        self.buf = b'\x8f\x00\xb5\xa4\x00\x00\x00\x04' \
            + b'\x01\x00\x00\x00' \
            + b'\xff\x00\x00\x00\x00\x00\x00\x00' \
            + b'\x00\x00\x00\x00\x00\x00\x00\x01' \
            + b'\x01\x00\x00\x02' \
            + b'\xff\x00\x00\x00\x00\x00\x00\x00' \
            + b'\x00\x00\x00\x00\x00\x00\x00\x02' \
            + b'\xfe\x80\x00\x00\x00\x00\x00\x00' \
            + b'\x00\x00\x00\x00\x00\x00\x00\x01' \
            + b'\xfe\x80\x00\x00\x00\x00\x00\x00' \
            + b'\x00\x00\x00\x00\x00\x00\x00\x02' \
            + b'\x01\x01\x00\x00' \
            + b'\xff\x00\x00\x00\x00\x00\x00\x00' \
            + b'\x00\x00\x00\x00\x00\x00\x00\x03' \
            + b'\x61\x62\x63\x00' \
            + b'\x01\x02\x00\x02' \
            + b'\xff\x00\x00\x00\x00\x00\x00\x00' \
            + b'\x00\x00\x00\x00\x00\x00\x00\x04' \
            + b'\xfe\x80\x00\x00\x00\x00\x00\x00' \
            + b'\x00\x00\x00\x00\x00\x00\x00\x01' \
            + b'\xfe\x80\x00\x00\x00\x00\x00\x00' \
            + b'\x00\x00\x00\x00\x00\x00\x00\x02' \
            + b'\x61\x62\x63\x64\x65\x00\x00\x00'

    def tearDown(self):
        pass

    def find_protocol(self, pkt, name):
        for p in pkt.protocols:
            if p.protocol_name == name:
                return p

    def test_init(self):
        self.assertEqual(self.mld.record_num, self.record_num)
        self.assertEqual(self.mld.records, self.records)

    def test_init_with_records(self):
        self.setUp_with_records()
        self.test_init()

    def test_parser(self):
        msg, n, _ = icmpv6.icmpv6.parser(self.buf)

        self.assertEqual(msg.type_, self.type_)
        self.assertEqual(msg.code, self.code)
        self.assertEqual(msg.csum, self.csum)
        self.assertEqual(msg.data.record_num, self.record_num)
        self.assertEqual(repr(msg.data.records), repr(self.records))

    def test_parser_with_records(self):
        self.setUp_with_records()
        self.test_parser()

    def test_serialize(self):
        src_ipv6 = '3ffe:507:0:1:200:86ff:fe05:80da'
        dst_ipv6 = '3ffe:501:0:1001::2'
        prev = ipv6(6, 0, 0, len(self.buf), 64, 255, src_ipv6, dst_ipv6)
        mld_csum = icmpv6_csum(prev, self.buf)

        icmp = icmpv6.icmpv6(self.type_, self.code, 0, self.mld)
        buf = icmp.serialize(bytearray(), prev)

        (type_, code, csum) = struct.unpack_from(icmp._PACK_STR,
                                                 bytes(buf))
        (record_num, ) = struct.unpack_from(
            self.mld._PACK_STR, bytes(buf), icmp._MIN_LEN)

        self.assertEqual(type_, self.type_)
        self.assertEqual(code, self.code)
        self.assertEqual(csum, mld_csum)
        self.assertEqual(record_num, self.record_num)

    def test_serialize_with_records(self):
        self.setUp_with_records()
        src_ipv6 = '3ffe:507:0:1:200:86ff:fe05:80da'
        dst_ipv6 = '3ffe:501:0:1001::2'
        prev = ipv6(6, 0, 0, len(self.buf), 64, 255, src_ipv6, dst_ipv6)
        mld_csum = icmpv6_csum(prev, self.buf)

        icmp = icmpv6.icmpv6(self.type_, self.code, 0, self.mld)
        buf = bytes(icmp.serialize(bytearray(), prev))

        (type_, code, csum) = struct.unpack_from(icmp._PACK_STR,
                                                 bytes(buf))
        (record_num, ) = struct.unpack_from(
            self.mld._PACK_STR, bytes(buf), icmp._MIN_LEN)
        offset = icmp._MIN_LEN + self.mld._MIN_LEN
        rec1 = icmpv6.mldv2_report_group.parser(buf[offset:])
        offset += len(rec1)
        rec2 = icmpv6.mldv2_report_group.parser(buf[offset:])
        offset += len(rec2)
        rec3 = icmpv6.mldv2_report_group.parser(buf[offset:])
        offset += len(rec3)
        rec4 = icmpv6.mldv2_report_group.parser(buf[offset:])

        self.assertEqual(type_, self.type_)
        self.assertEqual(code, self.code)
        self.assertEqual(csum, mld_csum)
        self.assertEqual(record_num, self.record_num)
        self.assertEqual(repr(rec1), repr(self.record1))
        self.assertEqual(repr(rec2), repr(self.record2))
        self.assertEqual(repr(rec3), repr(self.record3))
        self.assertEqual(repr(rec4), repr(self.record4))

    def _build_mldv2_report(self):
        e = ethernet(ethertype=ether.ETH_TYPE_IPV6)
        i = ipv6(nxt=inet.IPPROTO_ICMPV6)
        ic = icmpv6.icmpv6(type_=icmpv6.MLDV2_LISTENER_REPORT,
                           data=self.mld)
        p = e / i / ic
        return p

    def test_build_mldv2_report(self):
        p = self._build_mldv2_report()

        e = self.find_protocol(p, "ethernet")
        self.assertTrue(e)
        self.assertEqual(e.ethertype, ether.ETH_TYPE_IPV6)

        i = self.find_protocol(p, "ipv6")
        self.assertTrue(i)
        self.assertEqual(i.nxt, inet.IPPROTO_ICMPV6)

        ic = self.find_protocol(p, "icmpv6")
        self.assertTrue(ic)
        self.assertEqual(ic.type_, icmpv6.MLDV2_LISTENER_REPORT)

        self.assertEqual(ic.data.record_num, self.record_num)
        self.assertEqual(ic.data.records, self.records)

    def test_build_mldv2_report_with_records(self):
        self.setUp_with_records()
        self.test_build_mldv2_report()

    def test_to_string(self):
        ic = icmpv6.icmpv6(self.type_, self.code, self.csum, self.mld)

        mld_values = {'record_num': self.record_num,
                      'records': self.records}
        _mld_str = ','.join(['%s=%s' % (k, repr(mld_values[k]))
                             for k, v in inspect.getmembers(self.mld)
                             if k in mld_values])
        mld_str = '%s(%s)' % (icmpv6.mldv2_report.__name__, _mld_str)

        icmp_values = {'type_': repr(self.type_),
                       'code': repr(self.code),
                       'csum': repr(self.csum),
                       'data': mld_str}
        _ic_str = ','.join(['%s=%s' % (k, icmp_values[k])
                            for k, v in inspect.getmembers(ic)
                            if k in icmp_values])
        ic_str = '%s(%s)' % (icmpv6.icmpv6.__name__, _ic_str)

        self.assertEqual(str(ic), ic_str)
        self.assertEqual(repr(ic), ic_str)

    def test_to_string_with_records(self):
        self.setUp_with_records()
        self.test_to_string()

    def test_record_num_larger_than_records(self):
        self.record1 = icmpv6.mldv2_report_group(
            icmpv6.MODE_IS_INCLUDE, 0, 0, 'ff00::1')
        self.record2 = icmpv6.mldv2_report_group(
            icmpv6.MODE_IS_INCLUDE, 0, 2, 'ff00::2',
            ['fe80::1', 'fe80::2'])
        self.record3 = icmpv6.mldv2_report_group(
            icmpv6.MODE_IS_INCLUDE, 1, 0, 'ff00::3', [], b'abc\x00')
        self.record4 = icmpv6.mldv2_report_group(
            icmpv6.MODE_IS_INCLUDE, 2, 2, 'ff00::4',
            ['fe80::1', 'fe80::2'], b'abcde\x00\x00\x00')
        self.records = [self.record1, self.record2, self.record3,
                        self.record4]
        self.record_num = len(self.records) + 1
        self.buf = struct.pack(
            icmpv6.mldv2_report._PACK_STR, self.record_num)
        self.buf += self.record1.serialize()
        self.buf += self.record2.serialize()
        self.buf += self.record3.serialize()
        self.buf += self.record4.serialize()
        self.mld = icmpv6.mldv2_report(self.record_num, self.records)
        self.assertRaises(AssertionError, self.test_parser)

    def test_record_num_smaller_than_records(self):
        self.record1 = icmpv6.mldv2_report_group(
            icmpv6.MODE_IS_INCLUDE, 0, 0, 'ff00::1')
        self.record2 = icmpv6.mldv2_report_group(
            icmpv6.MODE_IS_INCLUDE, 0, 2, 'ff00::2',
            ['fe80::1', 'fe80::2'])
        self.record3 = icmpv6.mldv2_report_group(
            icmpv6.MODE_IS_INCLUDE, 1, 0, 'ff00::3', [], b'abc\x00')
        self.record4 = icmpv6.mldv2_report_group(
            icmpv6.MODE_IS_INCLUDE, 2, 2, 'ff00::4',
            ['fe80::1', 'fe80::2'], b'abcde\x00\x00\x00')
        self.records = [self.record1, self.record2, self.record3,
                        self.record4]
        self.record_num = len(self.records) - 1
        self.buf = struct.pack(
            icmpv6.mldv2_report._PACK_STR, self.record_num)
        self.buf += self.record1.serialize()
        self.buf += self.record2.serialize()
        self.buf += self.record3.serialize()
        self.buf += self.record4.serialize()
        self.mld = icmpv6.mldv2_report(self.record_num, self.records)
        self.assertRaises(AssertionError, self.test_parser)

    def test_default_args(self):
        prev = ipv6(nxt=inet.IPPROTO_ICMPV6)
        ic = icmpv6.icmpv6(
            type_=icmpv6.MLDV2_LISTENER_REPORT, data=icmpv6.mldv2_report())
        prev.serialize(ic, None)
        buf = ic.serialize(bytearray(), prev)
        res = struct.unpack(icmpv6.icmpv6._PACK_STR, bytes(buf[:4]))

        self.assertEqual(res[0], icmpv6.MLDV2_LISTENER_REPORT)
        self.assertEqual(res[1], 0)
        self.assertEqual(res[2], icmpv6_csum(prev, buf))

        res = struct.unpack(icmpv6.mldv2_report._PACK_STR, bytes(buf[4:]))

        self.assertEqual(res[0], 0)

        # records without record_num
        record1 = icmpv6.mldv2_report_group(
            icmpv6.MODE_IS_INCLUDE, 0, 0, 'ff00::1')
        record2 = icmpv6.mldv2_report_group(
            icmpv6.MODE_IS_INCLUDE, 0, 2, 'ff00::2',
            ['fe80::1', 'fe80::2'])
        records = [record1, record2]
        rep = icmpv6.mldv2_report(records=records)
        buf = rep.serialize()
        res = struct.unpack_from(
            icmpv6.mldv2_report._PACK_STR, bytes(buf))

        self.assertEqual(res[0], len(records))

        res = struct.unpack_from(
            icmpv6.mldv2_report_group._PACK_STR, bytes(buf),
            icmpv6.mldv2_report._MIN_LEN)

        self.assertEqual(res[0], icmpv6.MODE_IS_INCLUDE)
        self.assertEqual(res[1], 0)
        self.assertEqual(res[2], 0)
        self.assertEqual(res[3], addrconv.ipv6.text_to_bin('ff00::1'))

        res = struct.unpack_from(
            icmpv6.mldv2_report_group._PACK_STR, bytes(buf),
            icmpv6.mldv2_report._MIN_LEN +
            icmpv6.mldv2_report_group._MIN_LEN)

        self.assertEqual(res[0], icmpv6.MODE_IS_INCLUDE)
        self.assertEqual(res[1], 0)
        self.assertEqual(res[2], 2)
        self.assertEqual(res[3], addrconv.ipv6.text_to_bin('ff00::2'))

        res = struct.unpack_from(
            '16s16s', bytes(buf),
            icmpv6.mldv2_report._MIN_LEN +
            icmpv6.mldv2_report_group._MIN_LEN +
            icmpv6.mldv2_report_group._MIN_LEN)

        self.assertEqual(res[0], addrconv.ipv6.text_to_bin('fe80::1'))
        self.assertEqual(res[1], addrconv.ipv6.text_to_bin('fe80::2'))

    def test_json(self):
        jsondict = self.mld.to_jsondict()
        mld = icmpv6.mldv2_report.from_jsondict(jsondict['mldv2_report'])
        self.assertEqual(str(self.mld), str(mld))

    def test_json_with_records(self):
        self.setUp_with_records()
        self.test_json()


class Test_mldv2_report_group(unittest.TestCase):
    type_ = icmpv6.MODE_IS_INCLUDE
    aux_len = 0
    num = 0
    address = 'ff00::1'
    srcs = []
    aux = None
    mld = icmpv6.mldv2_report_group(
        type_, aux_len, num, address, srcs, aux)
    buf = b'\x01\x00\x00\x00' \
        + b'\xff\x00\x00\x00\x00\x00\x00\x00' \
        + b'\x00\x00\x00\x00\x00\x00\x00\x01'

    def setUp(self):
        pass

    def setUp_with_srcs(self):
        self.srcs = ['fe80::1', 'fe80::2', 'fe80::3']
        self.num = len(self.srcs)
        self.mld = icmpv6.mldv2_report_group(
            self.type_, self.aux_len, self.num, self.address, self.srcs,
            self.aux)
        self.buf = b'\x01\x00\x00\x03' \
            + b'\xff\x00\x00\x00\x00\x00\x00\x00' \
            + b'\x00\x00\x00\x00\x00\x00\x00\x01' \
            + b'\xfe\x80\x00\x00\x00\x00\x00\x00' \
            + b'\x00\x00\x00\x00\x00\x00\x00\x01' \
            + b'\xfe\x80\x00\x00\x00\x00\x00\x00' \
            + b'\x00\x00\x00\x00\x00\x00\x00\x02' \
            + b'\xfe\x80\x00\x00\x00\x00\x00\x00' \
            + b'\x00\x00\x00\x00\x00\x00\x00\x03'

    def setUp_with_aux(self):
        self.aux = b'\x01\x02\x03\x04\x05\x06\x07\x08'
        self.aux_len = len(self.aux) // 4
        self.mld = icmpv6.mldv2_report_group(
            self.type_, self.aux_len, self.num, self.address, self.srcs,
            self.aux)
        self.buf = b'\x01\x02\x00\x00' \
            + b'\xff\x00\x00\x00\x00\x00\x00\x00' \
            + b'\x00\x00\x00\x00\x00\x00\x00\x01' \
            + b'\x01\x02\x03\x04\x05\x06\x07\x08'

    def setUp_with_srcs_and_aux(self):
        self.srcs = ['fe80::1', 'fe80::2', 'fe80::3']
        self.num = len(self.srcs)
        self.aux = b'\x01\x02\x03\x04\x05\x06\x07\x08'
        self.aux_len = len(self.aux) // 4
        self.mld = icmpv6.mldv2_report_group(
            self.type_, self.aux_len, self.num, self.address, self.srcs,
            self.aux)
        self.buf = b'\x01\x02\x00\x03' \
            + b'\xff\x00\x00\x00\x00\x00\x00\x00' \
            + b'\x00\x00\x00\x00\x00\x00\x00\x01' \
            + b'\xfe\x80\x00\x00\x00\x00\x00\x00' \
            + b'\x00\x00\x00\x00\x00\x00\x00\x01' \
            + b'\xfe\x80\x00\x00\x00\x00\x00\x00' \
            + b'\x00\x00\x00\x00\x00\x00\x00\x02' \
            + b'\xfe\x80\x00\x00\x00\x00\x00\x00' \
            + b'\x00\x00\x00\x00\x00\x00\x00\x03' \
            + b'\x01\x02\x03\x04\x05\x06\x07\x08'

    def tearDown(self):
        pass

    def test_init(self):
        self.assertEqual(self.mld.type_, self.type_)
        self.assertEqual(self.mld.aux_len, self.aux_len)
        self.assertEqual(self.mld.num, self.num)
        self.assertEqual(self.mld.address, self.address)
        self.assertEqual(self.mld.srcs, self.srcs)
        self.assertEqual(self.mld.aux, self.aux)

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
        _res = icmpv6.mldv2_report_group.parser(self.buf)
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
        buf = self.mld.serialize()
        res = struct.unpack_from(
            icmpv6.mldv2_report_group._PACK_STR, bytes(buf))

        self.assertEqual(res[0], self.type_)
        self.assertEqual(res[1], self.aux_len)
        self.assertEqual(res[2], self.num)
        self.assertEqual(res[3], addrconv.ipv6.text_to_bin(self.address))

    def test_serialize_with_srcs(self):
        self.setUp_with_srcs()
        buf = self.mld.serialize()
        res = struct.unpack_from(
            icmpv6.mldv2_report_group._PACK_STR, bytes(buf))
        (src1, src2, src3) = struct.unpack_from(
            '16s16s16s', bytes(buf), icmpv6.mldv2_report_group._MIN_LEN)
        self.assertEqual(res[0], self.type_)
        self.assertEqual(res[1], self.aux_len)
        self.assertEqual(res[2], self.num)
        self.assertEqual(res[3], addrconv.ipv6.text_to_bin(self.address))
        self.assertEqual(src1, addrconv.ipv6.text_to_bin(self.srcs[0]))
        self.assertEqual(src2, addrconv.ipv6.text_to_bin(self.srcs[1]))
        self.assertEqual(src3, addrconv.ipv6.text_to_bin(self.srcs[2]))

    def test_serialize_with_aux(self):
        self.setUp_with_aux()
        buf = self.mld.serialize()
        res = struct.unpack_from(
            icmpv6.mldv2_report_group._PACK_STR, bytes(buf))
        (aux, ) = struct.unpack_from(
            '%ds' % (self.aux_len * 4), bytes(buf),
            icmpv6.mldv2_report_group._MIN_LEN)
        self.assertEqual(res[0], self.type_)
        self.assertEqual(res[1], self.aux_len)
        self.assertEqual(res[2], self.num)
        self.assertEqual(res[3], addrconv.ipv6.text_to_bin(self.address))
        self.assertEqual(aux, self.aux)

    def test_serialize_with_srcs_and_aux(self):
        self.setUp_with_srcs_and_aux()
        buf = self.mld.serialize()
        res = struct.unpack_from(
            icmpv6.mldv2_report_group._PACK_STR, bytes(buf))
        (src1, src2, src3) = struct.unpack_from(
            '16s16s16s', bytes(buf), icmpv6.mldv2_report_group._MIN_LEN)
        (aux, ) = struct.unpack_from(
            '%ds' % (self.aux_len * 4), bytes(buf),
            icmpv6.mldv2_report_group._MIN_LEN + 16 * 3)
        self.assertEqual(res[0], self.type_)
        self.assertEqual(res[1], self.aux_len)
        self.assertEqual(res[2], self.num)
        self.assertEqual(res[3], addrconv.ipv6.text_to_bin(self.address))
        self.assertEqual(src1, addrconv.ipv6.text_to_bin(self.srcs[0]))
        self.assertEqual(src2, addrconv.ipv6.text_to_bin(self.srcs[1]))
        self.assertEqual(src3, addrconv.ipv6.text_to_bin(self.srcs[2]))
        self.assertEqual(aux, self.aux)

    def test_to_string(self):
        igmp_values = {'type_': repr(self.type_),
                       'aux_len': repr(self.aux_len),
                       'num': repr(self.num),
                       'address': repr(self.address),
                       'srcs': repr(self.srcs),
                       'aux': repr(self.aux)}
        _g_str = ','.join(['%s=%s' % (k, igmp_values[k])
                           for k, v in inspect.getmembers(self.mld)
                           if k in igmp_values])
        g_str = '%s(%s)' % (icmpv6.mldv2_report_group.__name__, _g_str)

        self.assertEqual(str(self.mld), g_str)
        self.assertEqual(repr(self.mld), g_str)

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
        self.assertEqual(len(self.mld), 20)

    def test_len_with_srcs(self):
        self.setUp_with_srcs()
        self.assertEqual(len(self.mld), 68)

    def test_len_with_aux(self):
        self.setUp_with_aux()
        self.assertEqual(len(self.mld), 28)

    def test_len_with_srcs_and_aux(self):
        self.setUp_with_srcs_and_aux()
        self.assertEqual(len(self.mld), 76)

    def test_num_larger_than_srcs(self):
        self.srcs = ['fe80::1', 'fe80::2', 'fe80::3']
        self.num = len(self.srcs) + 1
        self.buf = struct.pack(
            icmpv6.mldv2_report_group._PACK_STR, self.type_, self.aux_len,
            self.num, addrconv.ipv6.text_to_bin(self.address))
        for src in self.srcs:
            self.buf += struct.pack('16s', addrconv.ipv6.text_to_bin(src))
        self.mld = icmpv6.mldv2_report_group(
            self.type_, self.aux_len, self.num, self.address,
            self.srcs, self.aux)
        self.assertRaises(AssertionError, self.test_parser)

    def test_num_smaller_than_srcs(self):
        self.srcs = ['fe80::1', 'fe80::2', 'fe80::3']
        self.num = len(self.srcs) - 1
        self.buf = struct.pack(
            icmpv6.mldv2_report_group._PACK_STR, self.type_, self.aux_len,
            self.num, addrconv.ipv6.text_to_bin(self.address))
        for src in self.srcs:
            self.buf += struct.pack('16s', addrconv.ipv6.text_to_bin(src))
        self.mld = icmpv6.mldv2_report_group(
            self.type_, self.aux_len, self.num, self.address,
            self.srcs, self.aux)
        self.assertRaises(AssertionError, self.test_parser)

    def test_aux_len_larger_than_aux(self):
        self.aux = b'\x01\x02\x03\x04\x05\x06\x07\x08'
        self.aux_len = len(self.aux) // 4 + 1
        self.buf = struct.pack(
            icmpv6.mldv2_report_group._PACK_STR, self.type_, self.aux_len,
            self.num, addrconv.ipv6.text_to_bin(self.address))
        self.buf += self.aux
        self.mld = icmpv6.mldv2_report_group(
            self.type_, self.aux_len, self.num, self.address,
            self.srcs, self.aux)
        self.assertRaises(struct.error, self.test_parser)

    def test_aux_len_smaller_than_aux(self):
        self.aux = b'\x01\x02\x03\x04\x05\x06\x07\x08'
        self.aux_len = len(self.aux) // 4 - 1
        self.buf = struct.pack(
            icmpv6.mldv2_report_group._PACK_STR, self.type_, self.aux_len,
            self.num, addrconv.ipv6.text_to_bin(self.address))
        self.buf += self.aux
        self.mld = icmpv6.mldv2_report_group(
            self.type_, self.aux_len, self.num, self.address,
            self.srcs, self.aux)
        self.assertRaises(AssertionError, self.test_parser)

    def test_default_args(self):
        rep = icmpv6.mldv2_report_group()
        buf = rep.serialize()
        res = struct.unpack_from(
            icmpv6.mldv2_report_group._PACK_STR, bytes(buf))

        self.assertEqual(res[0], 0)
        self.assertEqual(res[1], 0)
        self.assertEqual(res[2], 0)
        self.assertEqual(res[3], addrconv.ipv6.text_to_bin('::'))

        # srcs without num
        srcs = ['fe80::1', 'fe80::2', 'fe80::3']
        rep = icmpv6.mldv2_report_group(srcs=srcs)
        buf = rep.serialize()
        LOG.info(repr(buf))
        res = struct.unpack_from(
            icmpv6.mldv2_report_group._PACK_STR, bytes(buf))

        self.assertEqual(res[0], 0)
        self.assertEqual(res[1], 0)
        self.assertEqual(res[2], len(srcs))
        self.assertEqual(res[3], addrconv.ipv6.text_to_bin('::'))

        (src1, src2, src3) = struct.unpack_from(
            '16s16s16s', bytes(buf), icmpv6.mldv2_report_group._MIN_LEN)

        self.assertEqual(src1, addrconv.ipv6.text_to_bin(srcs[0]))
        self.assertEqual(src2, addrconv.ipv6.text_to_bin(srcs[1]))
        self.assertEqual(src3, addrconv.ipv6.text_to_bin(srcs[2]))

        # aux without aux_len
        rep = icmpv6.mldv2_report_group(aux=b'\x01\x02\x03')
        buf = rep.serialize()
        res = struct.unpack_from(
            icmpv6.mldv2_report_group._PACK_STR, bytes(buf))

        self.assertEqual(res[0], 0)
        self.assertEqual(res[1], 1)
        self.assertEqual(res[2], 0)
        self.assertEqual(res[3], addrconv.ipv6.text_to_bin('::'))
        self.assertEqual(buf[icmpv6.mldv2_report_group._MIN_LEN:], b'\x01\x02\x03\x00')

    def test_json(self):
        jsondict = self.mld.to_jsondict()
        mld = icmpv6.mldv2_report_group.from_jsondict(
            jsondict['mldv2_report_group'])
        self.assertEqual(str(self.mld), str(mld))

    def test_json_with_srcs(self):
        self.setUp_with_srcs()
        self.test_json()

    def test_json_with_aux(self):
        self.setUp_with_aux()
        self.test_json()

    def test_json_with_srcs_and_aux(self):
        self.setUp_with_srcs_and_aux()
        self.test_json()
