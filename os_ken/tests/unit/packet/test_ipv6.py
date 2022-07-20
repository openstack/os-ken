# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import unittest
import logging
import inspect
import six
import struct

from os_ken.lib import addrconv
from os_ken.lib import ip
from os_ken.lib.packet import ipv6


LOG = logging.getLogger(__name__)


class Test_ipv6(unittest.TestCase):

    def setUp(self):
        self.version = 6
        self.traffic_class = 0
        self.flow_label = 0
        self.payload_length = 817
        self.nxt = 6
        self.hop_limit = 128
        self.src = '2002:4637:d5d3::4637:d5d3'
        self.dst = '2001:4860:0:2001::68'
        self.ext_hdrs = []
        self.ip = ipv6.ipv6(
            self.version, self.traffic_class, self.flow_label,
            self.payload_length, self.nxt, self.hop_limit, self.src,
            self.dst, self.ext_hdrs)

        self.v_tc_flow = (
            self.version << 28 | self.traffic_class << 20 |
            self.flow_label << 12)
        self.buf = struct.pack(
            ipv6.ipv6._PACK_STR, self.v_tc_flow,
            self.payload_length, self.nxt, self.hop_limit,
            addrconv.ipv6.text_to_bin(self.src),
            addrconv.ipv6.text_to_bin(self.dst))

    def setUp_with_hop_opts(self):
        self.opt1_type = 5
        self.opt1_len = 2
        self.opt1_data = b'\x00\x00'
        self.opt2_type = 1
        self.opt2_len = 0
        self.opt2_data = None
        self.options = [
            ipv6.option(self.opt1_type, self.opt1_len, self.opt1_data),
            ipv6.option(self.opt2_type, self.opt2_len, self.opt2_data),
        ]
        self.hop_opts_nxt = 6
        self.hop_opts_size = 0
        self.hop_opts = ipv6.hop_opts(
            self.hop_opts_nxt, self.hop_opts_size, self.options)
        self.ext_hdrs = [self.hop_opts]
        self.payload_length += len(self.hop_opts)
        self.nxt = ipv6.hop_opts.TYPE
        self.ip = ipv6.ipv6(
            self.version, self.traffic_class, self.flow_label,
            self.payload_length, self.nxt, self.hop_limit, self.src,
            self.dst, self.ext_hdrs)
        self.buf = struct.pack(
            ipv6.ipv6._PACK_STR, self.v_tc_flow,
            self.payload_length, self.nxt, self.hop_limit,
            addrconv.ipv6.text_to_bin(self.src),
            addrconv.ipv6.text_to_bin(self.dst))
        self.buf += self.hop_opts.serialize()

    def setUp_with_dst_opts(self):
        self.opt1_type = 5
        self.opt1_len = 2
        self.opt1_data = b'\x00\x00'
        self.opt2_type = 1
        self.opt2_len = 0
        self.opt2_data = None
        self.options = [
            ipv6.option(self.opt1_type, self.opt1_len, self.opt1_data),
            ipv6.option(self.opt2_type, self.opt2_len, self.opt2_data),
        ]
        self.dst_opts_nxt = 6
        self.dst_opts_size = 0
        self.dst_opts = ipv6.dst_opts(
            self.dst_opts_nxt, self.dst_opts_size, self.options)
        self.ext_hdrs = [self.dst_opts]
        self.payload_length += len(self.dst_opts)
        self.nxt = ipv6.dst_opts.TYPE
        self.ip = ipv6.ipv6(
            self.version, self.traffic_class, self.flow_label,
            self.payload_length, self.nxt, self.hop_limit, self.src,
            self.dst, self.ext_hdrs)
        self.buf = struct.pack(
            ipv6.ipv6._PACK_STR, self.v_tc_flow,
            self.payload_length, self.nxt, self.hop_limit,
            addrconv.ipv6.text_to_bin(self.src),
            addrconv.ipv6.text_to_bin(self.dst))
        self.buf += self.dst_opts.serialize()

    def setUp_with_routing_type3(self):
        self.routing_nxt = 6
        self.routing_size = 6
        self.routing_type = 3
        self.routing_seg = 2
        self.routing_cmpi = 0
        self.routing_cmpe = 0
        self.routing_adrs = ["2001:db8:dead::1", "2001:db8:dead::2",
                             "2001:db8:dead::3"]
        self.routing = ipv6.routing_type3(
            self.routing_nxt, self.routing_size,
            self.routing_type, self.routing_seg,
            self.routing_cmpi, self.routing_cmpe,
            self.routing_adrs)
        self.ext_hdrs = [self.routing]
        self.payload_length += len(self.routing)
        self.nxt = ipv6.routing.TYPE
        self.ip = ipv6.ipv6(
            self.version, self.traffic_class, self.flow_label,
            self.payload_length, self.nxt, self.hop_limit, self.src,
            self.dst, self.ext_hdrs)
        self.buf = struct.pack(
            ipv6.ipv6._PACK_STR, self.v_tc_flow,
            self.payload_length, self.nxt, self.hop_limit,
            addrconv.ipv6.text_to_bin(self.src),
            addrconv.ipv6.text_to_bin(self.dst))
        self.buf += self.routing.serialize()

    def setUp_with_fragment(self):
        self.fragment_nxt = 6
        self.fragment_offset = 50
        self.fragment_more = 1
        self.fragment_id = 123
        self.fragment = ipv6.fragment(
            self.fragment_nxt, self.fragment_offset, self.fragment_more,
            self.fragment_id)
        self.ext_hdrs = [self.fragment]
        self.payload_length += len(self.fragment)
        self.nxt = ipv6.fragment.TYPE
        self.ip = ipv6.ipv6(
            self.version, self.traffic_class, self.flow_label,
            self.payload_length, self.nxt, self.hop_limit, self.src,
            self.dst, self.ext_hdrs)
        self.buf = struct.pack(
            ipv6.ipv6._PACK_STR, self.v_tc_flow,
            self.payload_length, self.nxt, self.hop_limit,
            addrconv.ipv6.text_to_bin(self.src),
            addrconv.ipv6.text_to_bin(self.dst))
        self.buf += self.fragment.serialize()

    def setUp_with_auth(self):
        self.auth_nxt = 6
        self.auth_size = 4
        self.auth_spi = 256
        self.auth_seq = 1
        self.auth_data = b'\xa0\xe7\xf8\xab\xf9\x69\x1a\x8b\xf3\x9f\x7c\xae'
        self.auth = ipv6.auth(
            self.auth_nxt, self.auth_size, self.auth_spi, self.auth_seq,
            self.auth_data)
        self.ext_hdrs = [self.auth]
        self.payload_length += len(self.auth)
        self.nxt = ipv6.auth.TYPE
        self.ip = ipv6.ipv6(
            self.version, self.traffic_class, self.flow_label,
            self.payload_length, self.nxt, self.hop_limit, self.src,
            self.dst, self.ext_hdrs)
        self.buf = struct.pack(
            ipv6.ipv6._PACK_STR, self.v_tc_flow,
            self.payload_length, self.nxt, self.hop_limit,
            addrconv.ipv6.text_to_bin(self.src),
            addrconv.ipv6.text_to_bin(self.dst))
        self.buf += self.auth.serialize()

    def setUp_with_multi_headers(self):
        self.opt1_type = 5
        self.opt1_len = 2
        self.opt1_data = b'\x00\x00'
        self.opt2_type = 1
        self.opt2_len = 0
        self.opt2_data = None
        self.options = [
            ipv6.option(self.opt1_type, self.opt1_len, self.opt1_data),
            ipv6.option(self.opt2_type, self.opt2_len, self.opt2_data),
        ]
        self.hop_opts_nxt = ipv6.auth.TYPE
        self.hop_opts_size = 0
        self.hop_opts = ipv6.hop_opts(
            self.hop_opts_nxt, self.hop_opts_size, self.options)
        self.auth_nxt = 6
        self.auth_size = 4
        self.auth_spi = 256
        self.auth_seq = 1
        self.auth_data = b'\xa0\xe7\xf8\xab\xf9\x69\x1a\x8b\xf3\x9f\x7c\xae'
        self.auth = ipv6.auth(
            self.auth_nxt, self.auth_size, self.auth_spi, self.auth_seq,
            self.auth_data)
        self.ext_hdrs = [self.hop_opts, self.auth]
        self.payload_length += len(self.hop_opts) + len(self.auth)
        self.nxt = ipv6.hop_opts.TYPE
        self.ip = ipv6.ipv6(
            self.version, self.traffic_class, self.flow_label,
            self.payload_length, self.nxt, self.hop_limit, self.src,
            self.dst, self.ext_hdrs)
        self.buf = struct.pack(
            ipv6.ipv6._PACK_STR, self.v_tc_flow,
            self.payload_length, self.nxt, self.hop_limit,
            addrconv.ipv6.text_to_bin(self.src),
            addrconv.ipv6.text_to_bin(self.dst))
        self.buf += self.hop_opts.serialize()
        self.buf += self.auth.serialize()

    def tearDown(self):
        pass

    def test_init(self):
        self.assertEqual(self.version, self.ip.version)
        self.assertEqual(self.traffic_class, self.ip.traffic_class)
        self.assertEqual(self.flow_label, self.ip.flow_label)
        self.assertEqual(self.payload_length, self.ip.payload_length)
        self.assertEqual(self.nxt, self.ip.nxt)
        self.assertEqual(self.hop_limit, self.ip.hop_limit)
        self.assertEqual(self.src, self.ip.src)
        self.assertEqual(self.dst, self.ip.dst)
        self.assertEqual(str(self.ext_hdrs), str(self.ip.ext_hdrs))

    def test_init_with_hop_opts(self):
        self.setUp_with_hop_opts()
        self.test_init()

    def test_init_with_dst_opts(self):
        self.setUp_with_dst_opts()
        self.test_init()

    def test_init_with_routing_type3(self):
        self.setUp_with_routing_type3()
        self.test_init()

    def test_init_with_fragment(self):
        self.setUp_with_fragment()
        self.test_init()

    def test_init_with_auth(self):
        self.setUp_with_auth()
        self.test_init()

    def test_init_with_multi_headers(self):
        self.setUp_with_multi_headers()
        self.test_init()

    def test_parser(self):
        _res = self.ip.parser(six.binary_type(self.buf))
        if type(_res) is tuple:
            res = _res[0]
        else:
            res = _res

        self.assertEqual(self.version, res.version)
        self.assertEqual(self.traffic_class, res.traffic_class)
        self.assertEqual(self.flow_label, res.flow_label)
        self.assertEqual(self.payload_length, res.payload_length)
        self.assertEqual(self.nxt, res.nxt)
        self.assertEqual(self.hop_limit, res.hop_limit)
        self.assertEqual(self.src, res.src)
        self.assertEqual(self.dst, res.dst)
        self.assertEqual(str(self.ext_hdrs), str(res.ext_hdrs))

    def test_parser_with_hop_opts(self):
        self.setUp_with_hop_opts()
        self.test_parser()

    def test_parser_with_dst_opts(self):
        self.setUp_with_dst_opts()
        self.test_parser()

    def test_parser_with_routing_type3(self):
        self.setUp_with_routing_type3()
        self.test_parser()

    def test_parser_with_fragment(self):
        self.setUp_with_fragment()
        self.test_parser()

    def test_parser_with_auth(self):
        self.setUp_with_auth()
        self.test_parser()

    def test_parser_with_multi_headers(self):
        self.setUp_with_multi_headers()
        self.test_parser()

    def test_serialize(self):
        data = bytearray()
        prev = None
        buf = self.ip.serialize(data, prev)

        res = struct.unpack_from(ipv6.ipv6._PACK_STR, six.binary_type(buf))

        self.assertEqual(self.v_tc_flow, res[0])
        self.assertEqual(self.payload_length, res[1])
        self.assertEqual(self.nxt, res[2])
        self.assertEqual(self.hop_limit, res[3])
        self.assertEqual(self.src, addrconv.ipv6.bin_to_text(res[4]))
        self.assertEqual(self.dst, addrconv.ipv6.bin_to_text(res[5]))

    def test_serialize_with_hop_opts(self):
        self.setUp_with_hop_opts()
        self.test_serialize()

        data = bytearray()
        prev = None
        buf = self.ip.serialize(data, prev)
        hop_opts = ipv6.hop_opts.parser(six.binary_type(buf[ipv6.ipv6._MIN_LEN:]))
        self.assertEqual(repr(self.hop_opts), repr(hop_opts))

    def test_serialize_with_dst_opts(self):
        self.setUp_with_dst_opts()
        self.test_serialize()

        data = bytearray()
        prev = None
        buf = self.ip.serialize(data, prev)
        dst_opts = ipv6.dst_opts.parser(six.binary_type(buf[ipv6.ipv6._MIN_LEN:]))
        self.assertEqual(repr(self.dst_opts), repr(dst_opts))

    def test_serialize_with_routing_type3(self):
        self.setUp_with_routing_type3()
        self.test_serialize()

        data = bytearray()
        prev = None
        buf = self.ip.serialize(data, prev)
        routing = ipv6.routing.parser(six.binary_type(buf[ipv6.ipv6._MIN_LEN:]))
        self.assertEqual(repr(self.routing), repr(routing))

    def test_serialize_with_fragment(self):
        self.setUp_with_fragment()
        self.test_serialize()

        data = bytearray()
        prev = None
        buf = self.ip.serialize(data, prev)
        fragment = ipv6.fragment.parser(six.binary_type(buf[ipv6.ipv6._MIN_LEN:]))
        self.assertEqual(repr(self.fragment), repr(fragment))

    def test_serialize_with_auth(self):
        self.setUp_with_auth()
        self.test_serialize()

        data = bytearray()
        prev = None
        buf = self.ip.serialize(data, prev)
        auth = ipv6.auth.parser(six.binary_type(buf[ipv6.ipv6._MIN_LEN:]))
        self.assertEqual(repr(self.auth), repr(auth))

    def test_serialize_with_multi_headers(self):
        self.setUp_with_multi_headers()
        self.test_serialize()

        data = bytearray()
        prev = None
        buf = self.ip.serialize(data, prev)
        offset = ipv6.ipv6._MIN_LEN
        hop_opts = ipv6.hop_opts.parser(six.binary_type(buf[offset:]))
        offset += len(hop_opts)
        auth = ipv6.auth.parser(six.binary_type(buf[offset:]))
        self.assertEqual(repr(self.hop_opts), repr(hop_opts))
        self.assertEqual(repr(self.auth), repr(auth))

    def test_to_string(self):
        ipv6_values = {'version': self.version,
                       'traffic_class': self.traffic_class,
                       'flow_label': self.flow_label,
                       'payload_length': self.payload_length,
                       'nxt': self.nxt,
                       'hop_limit': self.hop_limit,
                       'src': repr(self.src),
                       'dst': repr(self.dst),
                       'ext_hdrs': self.ext_hdrs}
        _ipv6_str = ','.join(['%s=%s' % (k, ipv6_values[k])
                              for k, v in inspect.getmembers(self.ip)
                              if k in ipv6_values])
        ipv6_str = '%s(%s)' % (ipv6.ipv6.__name__, _ipv6_str)

        self.assertEqual(str(self.ip), ipv6_str)
        self.assertEqual(repr(self.ip), ipv6_str)

    def test_to_string_with_hop_opts(self):
        self.setUp_with_hop_opts()
        self.test_to_string()

    def test_to_string_with_dst_opts(self):
        self.setUp_with_dst_opts()
        self.test_to_string()

    def test_to_string_with_fragment(self):
        self.setUp_with_fragment()
        self.test_to_string()

    def test_to_string_with_auth(self):
        self.setUp_with_auth()
        self.test_to_string()

    def test_to_string_with_multi_headers(self):
        self.setUp_with_multi_headers()
        self.test_to_string()

    def test_len(self):
        self.assertEqual(len(self.ip), 40)

    def test_len_with_hop_opts(self):
        self.setUp_with_hop_opts()
        self.assertEqual(len(self.ip), 40 + len(self.hop_opts))

    def test_len_with_dst_opts(self):
        self.setUp_with_dst_opts()
        self.assertEqual(len(self.ip), 40 + len(self.dst_opts))

    def test_len_with_routing_type3(self):
        self.setUp_with_routing_type3()
        self.assertEqual(len(self.ip), 40 + len(self.routing))

    def test_len_with_fragment(self):
        self.setUp_with_fragment()
        self.assertEqual(len(self.ip), 40 + len(self.fragment))

    def test_len_with_auth(self):
        self.setUp_with_auth()
        self.assertEqual(len(self.ip), 40 + len(self.auth))

    def test_len_with_multi_headers(self):
        self.setUp_with_multi_headers()
        self.assertEqual(len(self.ip), 40 + len(self.hop_opts) + len(self.auth))

    def test_default_args(self):
        ip = ipv6.ipv6()
        buf = ip.serialize(bytearray(), None)
        res = struct.unpack(ipv6.ipv6._PACK_STR, six.binary_type(buf))

        self.assertEqual(res[0], 6 << 28)
        self.assertEqual(res[1], 0)
        self.assertEqual(res[2], 6)
        self.assertEqual(res[3], 255)
        self.assertEqual(res[4], addrconv.ipv6.text_to_bin('10::10'))
        self.assertEqual(res[5], addrconv.ipv6.text_to_bin('20::20'))

        # with extension header
        ip = ipv6.ipv6(
            nxt=0, ext_hdrs=[
                ipv6.hop_opts(58, 0, [
                    ipv6.option(5, 2, b'\x00\x00'),
                    ipv6.option(1, 0, None)])])
        buf = ip.serialize(bytearray(), None)
        res = struct.unpack(ipv6.ipv6._PACK_STR + '8s', six.binary_type(buf))

        self.assertEqual(res[0], 6 << 28)
        self.assertEqual(res[1], 8)
        self.assertEqual(res[2], 0)
        self.assertEqual(res[3], 255)
        self.assertEqual(res[4], addrconv.ipv6.text_to_bin('10::10'))
        self.assertEqual(res[5], addrconv.ipv6.text_to_bin('20::20'))
        self.assertEqual(res[6], b'\x3a\x00\x05\x02\x00\x00\x01\x00')

    def test_json(self):
        jsondict = self.ip.to_jsondict()
        ip = ipv6.ipv6.from_jsondict(jsondict['ipv6'])
        self.assertEqual(str(self.ip), str(ip))

    def test_json_with_hop_opts(self):
        self.setUp_with_hop_opts()
        self.test_json()

    def test_json_with_dst_opts(self):
        self.setUp_with_dst_opts()
        self.test_json()

    def test_json_with_routing_type3(self):
        self.setUp_with_routing_type3()
        self.test_json()

    def test_json_with_fragment(self):
        self.setUp_with_fragment()
        self.test_json()

    def test_json_with_auth(self):
        self.setUp_with_auth()
        self.test_json()

    def test_json_with_multi_headers(self):
        self.setUp_with_multi_headers()
        self.test_json()


class Test_hop_opts(unittest.TestCase):

    def setUp(self):
        self.nxt = 0
        self.size = 8
        self.data = [
            ipv6.option(5, 2, b'\x00\x00'),
            ipv6.option(1, 0, None),
            ipv6.option(0xc2, 4, b'\x00\x01\x00\x00'),
            ipv6.option(1, 0, None),
        ]
        self.hop = ipv6.hop_opts(self.nxt, self.size, self.data)
        self.form = '!BB'
        self.buf = struct.pack(self.form, self.nxt, self.size) \
            + self.data[0].serialize() \
            + self.data[1].serialize() \
            + self.data[2].serialize() \
            + self.data[3].serialize()

    def tearDown(self):
        pass

    def test_init(self):
        self.assertEqual(self.nxt, self.hop.nxt)
        self.assertEqual(self.size, self.hop.size)
        self.assertEqual(self.data, self.hop.data)

    def test_invalid_size(self):
        self.assertRaises(Exception, ipv6.hop_opts, self.nxt, 1, self.data)

    def test_parser(self):
        _res = ipv6.hop_opts.parser(self.buf)
        if type(_res) is tuple:
            res = _res[0]
        else:
            res = _res
        self.assertEqual(self.nxt, res.nxt)
        self.assertEqual(self.size, res.size)
        self.assertEqual(str(self.data), str(res.data))

    def test_serialize(self):
        buf = self.hop.serialize()
        res = struct.unpack_from(self.form, six.binary_type(buf))
        self.assertEqual(self.nxt, res[0])
        self.assertEqual(self.size, res[1])
        offset = struct.calcsize(self.form)
        opt1 = ipv6.option.parser(six.binary_type(buf[offset:]))
        offset += len(opt1)
        opt2 = ipv6.option.parser(six.binary_type(buf[offset:]))
        offset += len(opt2)
        opt3 = ipv6.option.parser(six.binary_type(buf[offset:]))
        offset += len(opt3)
        opt4 = ipv6.option.parser(six.binary_type(buf[offset:]))
        self.assertEqual(5, opt1.type_)
        self.assertEqual(2, opt1.len_)
        self.assertEqual(b'\x00\x00', opt1.data)
        self.assertEqual(1, opt2.type_)
        self.assertEqual(0, opt2.len_)
        self.assertEqual(None, opt2.data)
        self.assertEqual(0xc2, opt3.type_)
        self.assertEqual(4, opt3.len_)
        self.assertEqual(b'\x00\x01\x00\x00', opt3.data)
        self.assertEqual(1, opt4.type_)
        self.assertEqual(0, opt4.len_)
        self.assertEqual(None, opt4.data)

    def test_len(self):
        self.assertEqual(16, len(self.hop))

    def test_default_args(self):
        hdr = ipv6.hop_opts()
        buf = hdr.serialize()
        res = struct.unpack('!BB', six.binary_type(buf[:2]))

        self.assertEqual(res[0], 6)
        self.assertEqual(res[1], 0)
        opt = ipv6.option(type_=1, len_=4, data=b'\x00\x00\x00\x00')
        self.assertEqual(six.binary_type(buf[2:]), opt.serialize())


class Test_dst_opts(unittest.TestCase):

    def setUp(self):
        self.nxt = 60
        self.size = 8
        self.data = [
            ipv6.option(5, 2, b'\x00\x00'),
            ipv6.option(1, 0, None),
            ipv6.option(0xc2, 4, b'\x00\x01\x00\x00'),
            ipv6.option(1, 0, None),
        ]
        self.dst = ipv6.dst_opts(self.nxt, self.size, self.data)
        self.form = '!BB'
        self.buf = struct.pack(self.form, self.nxt, self.size) \
            + self.data[0].serialize() \
            + self.data[1].serialize() \
            + self.data[2].serialize() \
            + self.data[3].serialize()

    def tearDown(self):
        pass

    def test_init(self):
        self.assertEqual(self.nxt, self.dst.nxt)
        self.assertEqual(self.size, self.dst.size)
        self.assertEqual(self.data, self.dst.data)

    def test_invalid_size(self):
        self.assertRaises(Exception, ipv6.dst_opts, self.nxt, 1, self.data)

    def test_parser(self):
        _res = ipv6.dst_opts.parser(self.buf)
        if type(_res) is tuple:
            res = _res[0]
        else:
            res = _res
        self.assertEqual(self.nxt, res.nxt)
        self.assertEqual(self.size, res.size)
        self.assertEqual(str(self.data), str(res.data))

    def test_serialize(self):
        buf = self.dst.serialize()
        res = struct.unpack_from(self.form, six.binary_type(buf))
        self.assertEqual(self.nxt, res[0])
        self.assertEqual(self.size, res[1])
        offset = struct.calcsize(self.form)
        opt1 = ipv6.option.parser(six.binary_type(buf[offset:]))
        offset += len(opt1)
        opt2 = ipv6.option.parser(six.binary_type(buf[offset:]))
        offset += len(opt2)
        opt3 = ipv6.option.parser(six.binary_type(buf[offset:]))
        offset += len(opt3)
        opt4 = ipv6.option.parser(six.binary_type(buf[offset:]))
        self.assertEqual(5, opt1.type_)
        self.assertEqual(2, opt1.len_)
        self.assertEqual(b'\x00\x00', opt1.data)
        self.assertEqual(1, opt2.type_)
        self.assertEqual(0, opt2.len_)
        self.assertEqual(None, opt2.data)
        self.assertEqual(0xc2, opt3.type_)
        self.assertEqual(4, opt3.len_)
        self.assertEqual(b'\x00\x01\x00\x00', opt3.data)
        self.assertEqual(1, opt4.type_)
        self.assertEqual(0, opt4.len_)
        self.assertEqual(None, opt4.data)

    def test_len(self):
        self.assertEqual(16, len(self.dst))

    def test_default_args(self):
        hdr = ipv6.dst_opts()
        buf = hdr.serialize()
        res = struct.unpack('!BB', six.binary_type(buf[:2]))

        self.assertEqual(res[0], 6)
        self.assertEqual(res[1], 0)
        opt = ipv6.option(type_=1, len_=4, data=b'\x00\x00\x00\x00')
        self.assertEqual(six.binary_type(buf[2:]), opt.serialize())


class Test_option(unittest.TestCase):

    def setUp(self):
        self.type_ = 5
        self.data = b'\x00\x00'
        self.len_ = len(self.data)
        self.opt = ipv6.option(self.type_, self.len_, self.data)
        self.form = '!BB%ds' % self.len_
        self.buf = struct.pack(self.form, self.type_, self.len_, self.data)

    def tearDown(self):
        pass

    def test_init(self):
        self.assertEqual(self.type_, self.opt.type_)
        self.assertEqual(self.len_, self.opt.len_)
        self.assertEqual(self.data, self.opt.data)

    def test_parser(self):
        _res = ipv6.option.parser(self.buf)
        if type(_res) is tuple:
            res = _res[0]
        else:
            res = _res
        self.assertEqual(self.type_, res.type_)
        self.assertEqual(self.len_, res.len_)
        self.assertEqual(self.data, res.data)

    def test_serialize(self):
        buf = self.opt.serialize()
        res = struct.unpack_from(self.form, buf)
        self.assertEqual(self.type_, res[0])
        self.assertEqual(self.len_, res[1])
        self.assertEqual(self.data, res[2])

    def test_len(self):
        self.assertEqual(len(self.opt), 2 + self.len_)


class Test_option_pad1(Test_option):

    def setUp(self):
        self.type_ = 0
        self.len_ = -1
        self.data = None
        self.opt = ipv6.option(self.type_, self.len_, self.data)
        self.form = '!B'
        self.buf = struct.pack(self.form, self.type_)

    def test_serialize(self):
        buf = self.opt.serialize()
        res = struct.unpack_from(self.form, buf)
        self.assertEqual(self.type_, res[0])

    def test_default_args(self):
        opt = ipv6.option()
        buf = opt.serialize()
        res = struct.unpack('!B', buf)

        self.assertEqual(res[0], 0)


class Test_option_padN(Test_option):

    def setUp(self):
        self.type_ = 1
        self.len_ = 0
        self.data = None
        self.opt = ipv6.option(self.type_, self.len_, self.data)
        self.form = '!BB'
        self.buf = struct.pack(self.form, self.type_, self.len_)

    def test_serialize(self):
        buf = self.opt.serialize()
        res = struct.unpack_from(self.form, buf)
        self.assertEqual(self.type_, res[0])
        self.assertEqual(self.len_, res[1])


class Test_routing(unittest.TestCase):

    def setUp(self):
        self.nxt = 0
        self.size = 6
        self.type_ = ipv6.routing.ROUTING_TYPE_3
        self.seg = 0
        self.cmpi = 0
        self.cmpe = 0
        self.adrs = ["2001:db8:dead::1",
                     "2001:db8:dead::2",
                     "2001:db8:dead::3"]
        # calculate pad
        self.pad = (8 - ((len(self.adrs) - 1) * (16 - self.cmpi) +
                         (16 - self.cmpe) % 8)) % 8
        # create buf
        self.form = '!BBBBBB2x16s16s16s'
        self.buf = struct.pack(self.form, self.nxt, self.size,
                               self.type_, self.seg,
                               (self.cmpi << 4) | self.cmpe,
                               self.pad << 4,
                               addrconv.ipv6.text_to_bin(self.adrs[0]),
                               addrconv.ipv6.text_to_bin(self.adrs[1]),
                               addrconv.ipv6.text_to_bin(self.adrs[2]))

    def tearDown(self):
        pass

    def test_parser(self):
        _res = ipv6.routing.parser(self.buf)
        if type(_res) is tuple:
            res = _res[0]
        else:
            res = _res
        self.assertEqual(self.nxt, res.nxt)
        self.assertEqual(self.size, res.size)
        self.assertEqual(self.type_, res.type_)
        self.assertEqual(self.seg, res.seg)
        self.assertEqual(self.cmpi, res.cmpi)
        self.assertEqual(self.cmpe, res.cmpe)
        self.assertEqual(self.pad, res._pad)
        self.assertEqual(self.adrs[0], res.adrs[0])
        self.assertEqual(self.adrs[1], res.adrs[1])
        self.assertEqual(self.adrs[2], res.adrs[2])

    def test_not_implemented_type(self):
        not_implemented_buf = struct.pack(
            '!BBBBBB2x', 0, 6, ipv6.routing.ROUTING_TYPE_2, 0, 0, 0)
        instance = ipv6.routing.parser(not_implemented_buf)
        assert None is instance

    def test_invalid_type(self):
        invalid_type = 99
        invalid_buf = struct.pack('!BBBBBB2x', 0, 6, invalid_type, 0, 0, 0)
        instance = ipv6.routing.parser(invalid_buf)
        assert None is instance


class Test_routing_type3(unittest.TestCase):

    def setUp(self):
        self.nxt = 0
        self.size = 6
        self.type_ = 3
        self.seg = 0
        self.cmpi = 0
        self.cmpe = 0
        self.adrs = ["2001:db8:dead::1",
                     "2001:db8:dead::2",
                     "2001:db8:dead::3"]
        # calculate pad
        self.pad = (8 - ((len(self.adrs) - 1) * (16 - self.cmpi) +
                         (16 - self.cmpe) % 8)) % 8

        self.routing = ipv6.routing_type3(
            self.nxt, self.size, self.type_, self.seg, self.cmpi,
            self.cmpe, self.adrs)
        self.form = '!BBBBBB2x16s16s16s'
        self.buf = struct.pack(self.form, self.nxt, self.size,
                               self.type_, self.seg,
                               (self.cmpi << 4) | self.cmpe,
                               self.pad << 4,
                               addrconv.ipv6.text_to_bin(self.adrs[0]),
                               addrconv.ipv6.text_to_bin(self.adrs[1]),
                               addrconv.ipv6.text_to_bin(self.adrs[2]))

    def test_init(self):
        self.assertEqual(self.nxt, self.routing.nxt)
        self.assertEqual(self.size, self.routing.size)
        self.assertEqual(self.type_, self.routing.type_)
        self.assertEqual(self.seg, self.routing.seg)
        self.assertEqual(self.cmpi, self.routing.cmpi)
        self.assertEqual(self.cmpe, self.routing.cmpe)
        self.assertEqual(self.pad, self.routing._pad)
        self.assertEqual(self.adrs[0], self.routing.adrs[0])
        self.assertEqual(self.adrs[1], self.routing.adrs[1])
        self.assertEqual(self.adrs[2], self.routing.adrs[2])

    def test_parser(self):
        _res = ipv6.routing.parser(self.buf)
        if type(_res) is tuple:
            res = _res[0]
        else:
            res = _res
        self.assertEqual(self.nxt, res.nxt)
        self.assertEqual(self.size, res.size)
        self.assertEqual(self.type_, res.type_)
        self.assertEqual(self.seg, res.seg)
        self.assertEqual(self.cmpi, res.cmpi)
        self.assertEqual(self.cmpe, res.cmpe)
        self.assertEqual(self.pad, res._pad)
        self.assertEqual(self.adrs[0], res.adrs[0])
        self.assertEqual(self.adrs[1], res.adrs[1])
        self.assertEqual(self.adrs[2], res.adrs[2])

    def test_serialize(self):
        buf = self.routing.serialize()
        res = struct.unpack_from(self.form, six.binary_type(buf))
        self.assertEqual(self.nxt, res[0])
        self.assertEqual(self.size, res[1])
        self.assertEqual(self.type_, res[2])
        self.assertEqual(self.seg, res[3])
        self.assertEqual(self.cmpi, res[4] >> 4)
        self.assertEqual(self.cmpe, res[4] & 0xf)
        self.assertEqual(self.pad, res[5])
        self.assertEqual(addrconv.ipv6.text_to_bin(self.adrs[0]), res[6])
        self.assertEqual(addrconv.ipv6.text_to_bin(self.adrs[1]), res[7])
        self.assertEqual(addrconv.ipv6.text_to_bin(self.adrs[2]), res[8])

    def test_parser_with_adrs_zero(self):
        nxt = 0
        size = 0
        type_ = 3
        seg = 0
        cmpi = 0
        cmpe = 0
        adrs = []
        # calculate pad
        pad = (8 - ((len(adrs) - 1) * (16 - cmpi) + (16 - cmpe) % 8)) % 8

        form = '!BBBBBB2x'
        buf = struct.pack(form, nxt, size, type_, seg,
                          (cmpi << 4) | cmpe, pad << 4)
        _res = ipv6.routing.parser(buf)
        if type(_res) is tuple:
            res = _res[0]
        else:
            res = _res
        self.assertEqual(nxt, res.nxt)
        self.assertEqual(size, res.size)
        self.assertEqual(type_, res.type_)
        self.assertEqual(seg, res.seg)
        self.assertEqual(cmpi, res.cmpi)
        self.assertEqual(cmpe, res.cmpe)
        self.assertEqual(pad, res._pad)

    def test_serialize_with_adrs_zero(self):
        nxt = 0
        size = 0
        type_ = 3
        seg = 0
        cmpi = 0
        cmpe = 0
        adrs = []
        # calculate pad
        pad = (8 - ((len(adrs) - 1) * (16 - cmpi) + (16 - cmpe) % 8)) % 8
        routing = ipv6.routing_type3(
            nxt, size, type_, seg, cmpi,
            cmpe, pad)
        buf = routing.serialize()
        form = '!BBBBBB2x'
        res = struct.unpack_from(form, six.binary_type(buf))
        self.assertEqual(nxt, res[0])
        self.assertEqual(size, res[1])
        self.assertEqual(type_, res[2])
        self.assertEqual(seg, res[3])
        self.assertEqual(cmpi, res[4] >> 4)
        self.assertEqual(cmpe, res[4] & 0xf)
        self.assertEqual(pad, res[5])

    def test_parser_with_compression(self):
        pass
        nxt = 0
        size = 3
        type_ = 3
        seg = 0
        cmpi = 8
        cmpe = 12
        adrs = ["2001:0db8:dead:0123:4567:89ab:cdef:0001",
                "2001:0db8:dead:0123:4567:89ab:cdef:0002",
                "2001:0db8:dead:0123:4567:89ab:cdef:0003"]
        # calculate pad
        pad = (8 - ((len(adrs) - 1) * (16 - cmpi) + (16 - cmpe) % 8)) % 8
        form = '!BBBBBB2x%ds%ds%ds' % (16 - cmpi, 16 - cmpi, 16 - cmpe)
        slice_i = slice(cmpi, 16)
        slice_e = slice(cmpe, 16)
        buf = struct.pack(form, nxt, size, type_, seg,
                          (cmpi << 4) | cmpe, pad << 4,
                          addrconv.ipv6.text_to_bin(adrs[0])[slice_i],
                          addrconv.ipv6.text_to_bin(adrs[1])[slice_i],
                          addrconv.ipv6.text_to_bin(adrs[2])[slice_e])
        _res = ipv6.routing.parser(buf)
        if type(_res) is tuple:
            res = _res[0]
        else:
            res = _res
        self.assertEqual(nxt, res.nxt)
        self.assertEqual(size, res.size)
        self.assertEqual(type_, res.type_)
        self.assertEqual(seg, res.seg)
        self.assertEqual(cmpi, res.cmpi)
        self.assertEqual(cmpe, res.cmpe)
        self.assertEqual(pad, res._pad)
        self.assertEqual("::4567:89ab:cdef:1", res.adrs[0])
        self.assertEqual("::4567:89ab:cdef:2", res.adrs[1])
        self.assertEqual("::205.239.0.3", res.adrs[2])

    def test_serialize_with_compression(self):
        nxt = 0
        size = 3
        type_ = 3
        seg = 0
        cmpi = 8
        cmpe = 8
        adrs = ["2001:db8:dead::1",
                "2001:db8:dead::2",
                "2001:db8:dead::3"]
        # calculate pad
        pad = (8 - ((len(adrs) - 1) * (16 - cmpi) + (16 - cmpe) % 8)) % 8
        slice_i = slice(cmpi, 16)
        slice_e = slice(cmpe, 16)
        routing = ipv6.routing_type3(
            nxt, size, type_, seg, cmpi, cmpe, adrs)
        buf = routing.serialize()
        form = '!BBBBBB2x8s8s8s'
        res = struct.unpack_from(form, six.binary_type(buf))
        self.assertEqual(nxt, res[0])
        self.assertEqual(size, res[1])
        self.assertEqual(type_, res[2])
        self.assertEqual(seg, res[3])
        self.assertEqual(cmpi, res[4] >> 4)
        self.assertEqual(cmpe, res[4] & 0xf)
        self.assertEqual(pad, res[5])
        self.assertEqual(addrconv.ipv6.text_to_bin(adrs[0])[slice_i], res[6])
        self.assertEqual(addrconv.ipv6.text_to_bin(adrs[1])[slice_i], res[7])
        self.assertEqual(addrconv.ipv6.text_to_bin(adrs[2])[slice_e], res[8])

    def test_len(self):
        self.assertEqual((6 + 1) * 8, len(self.routing))

    def test_default_args(self):
        hdr = ipv6.routing_type3()
        buf = hdr.serialize()
        LOG.info(repr(buf))
        res = struct.unpack_from(ipv6.routing_type3._PACK_STR, six.binary_type(buf))
        LOG.info(res)

        self.assertEqual(res[0], 6)
        self.assertEqual(res[1], 0)
        self.assertEqual(res[2], 3)
        self.assertEqual(res[3], 0)
        self.assertEqual(res[4], (0 << 4) | 0)
        self.assertEqual(res[5], 0)


class Test_fragment(unittest.TestCase):

    def setUp(self):
        self.nxt = 44
        self.offset = 50
        self.more = 1
        self.id_ = 123
        self.fragment = ipv6.fragment(
            self.nxt, self.offset, self.more, self.id_)

        self.off_m = (self.offset << 3 | self.more)
        self.form = '!BxHI'
        self.buf = struct.pack(self.form, self.nxt, self.off_m, self.id_)

    def test_init(self):
        self.assertEqual(self.nxt, self.fragment.nxt)
        self.assertEqual(self.offset, self.fragment.offset)
        self.assertEqual(self.more, self.fragment.more)
        self.assertEqual(self.id_, self.fragment.id_)

    def test_parser(self):
        _res = ipv6.fragment.parser(self.buf)
        if type(_res) is tuple:
            res = _res[0]
        else:
            res = _res
        self.assertEqual(self.nxt, res.nxt)
        self.assertEqual(self.offset, res.offset)
        self.assertEqual(self.more, res.more)
        self.assertEqual(self.id_, res.id_)

    def test_serialize(self):
        buf = self.fragment.serialize()
        res = struct.unpack_from(self.form, six.binary_type(buf))
        self.assertEqual(self.nxt, res[0])
        self.assertEqual(self.off_m, res[1])
        self.assertEqual(self.id_, res[2])

    def test_len(self):
        self.assertEqual(8, len(self.fragment))

    def test_default_args(self):
        hdr = ipv6.fragment()
        buf = hdr.serialize()
        res = struct.unpack_from(ipv6.fragment._PACK_STR, buf)

        self.assertEqual(res[0], 6)
        self.assertEqual(res[1], 0)
        self.assertEqual(res[2], 0)


class Test_auth(unittest.TestCase):

    def setUp(self):
        self.nxt = 0
        self.size = 4
        self.spi = 256
        self.seq = 1
        self.data = b'\x21\xd3\xa9\x5c\x5f\xfd\x4d\x18\x46\x22\xb9\xf8'
        self.auth = ipv6.auth(
            self.nxt, self.size, self.spi, self.seq, self.data)
        self.form = '!BB2xII12s'
        self.buf = struct.pack(self.form, self.nxt, self.size, self.spi,
                               self.seq, self.data)

    def test_init(self):
        self.assertEqual(self.nxt, self.auth.nxt)
        self.assertEqual(self.size, self.auth.size)
        self.assertEqual(self.spi, self.auth.spi)
        self.assertEqual(self.seq, self.auth.seq)
        self.assertEqual(self.data, self.auth.data)

    def test_parser(self):
        _res = ipv6.auth.parser(self.buf)
        if type(_res) is tuple:
            res = _res[0]
        else:
            res = _res
        self.assertEqual(self.nxt, res.nxt)
        self.assertEqual(self.size, res.size)
        self.assertEqual(self.spi, res.spi)
        self.assertEqual(self.seq, res.seq)
        self.assertEqual(self.data, res.data)

    def test_serialize(self):
        buf = self.auth.serialize()
        res = struct.unpack_from(self.form, six.binary_type(buf))
        self.assertEqual(self.nxt, res[0])
        self.assertEqual(self.size, res[1])
        self.assertEqual(self.spi, res[2])
        self.assertEqual(self.seq, res[3])
        self.assertEqual(self.data, res[4])

    def test_len(self):
        self.assertEqual((4 + 2) * 4, len(self.auth))

    def test_len_re(self):
        size = 5
        auth = ipv6.auth(
            0, size, 256, 1,
            b'\x21\xd3\xa9\x5c\x5f\xfd\x4d\x18\x46\x22\xb9\xf8\xf8\xf8\xf8\xf8')
        self.assertEqual((size + 2) * 4, len(auth))

    def test_default_args(self):
        hdr = ipv6.auth()
        buf = hdr.serialize()
        LOG.info(repr(buf))
        res = struct.unpack_from(ipv6.auth._PACK_STR, six.binary_type(buf))
        LOG.info(res)

        self.assertEqual(res[0], 6)
        self.assertEqual(res[1], 2)
        self.assertEqual(res[2], 0)
        self.assertEqual(res[3], 0)
        self.assertEqual(buf[ipv6.auth._MIN_LEN:], b'\x00\x00\x00\x00')
