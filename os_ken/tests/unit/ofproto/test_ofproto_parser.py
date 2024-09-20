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

import binascii
import unittest
import struct
from os_ken import exception

from os_ken.ofproto import ofproto_common, ofproto_parser
from os_ken.ofproto import ofproto_v1_0, ofproto_v1_0_parser

import logging
LOG = logging.getLogger(__name__)


class TestOfproto_Parser(unittest.TestCase):
    def setUp(self):
        LOG.debug('setUp')
        self.bufHello = binascii.unhexlify('0100000800000001')

        fr = '010600b0000000020000000000000abc' \
            + '00000100010000000000008700000fff' \
            + '0002aefa39d2b9177472656d61302d30' \
            + '00000000000000000000000000000000' \
            + '000000c0000000000000000000000000' \
            + 'fffe723f9a764cc87673775f30786162' \
            + '63000000000000000000000100000001' \
            + '00000082000000000000000000000000' \
            + '00012200d6c5a1947472656d61312d30' \
            + '00000000000000000000000000000000' \
            + '000000c0000000000000000000000000'
        self.bufFeaturesReply = binascii.unhexlify(fr)

        pi = '010a005200000000000001010040' \
            + '00020000000000000002000000000001' \
            + '080045000032000000004011f967c0a8' \
            + '0001c0a8000200010001001e00000000' \
            + '00000000000000000000000000000000' \
            + '00000000'
        self.bufPacketIn = binascii.unhexlify(pi)

    def tearDown(self):
        LOG.debug('tearDown')
        pass

    def testHello(self):
        (version,
         msg_type,
         msg_len,
         xid) = ofproto_parser.header(self.bufHello)
        self.assertEqual(version, 1)
        self.assertEqual(msg_type, 0)
        self.assertEqual(msg_len, 8)
        self.assertEqual(xid, 1)

    def testFeaturesReply(self):
        (version,
         msg_type,
         msg_len,
         xid) = ofproto_parser.header(self.bufFeaturesReply)

        msg = ofproto_parser.msg(self,
                                 version,
                                 msg_type,
                                 msg_len,
                                 xid,
                                 self.bufFeaturesReply)
        LOG.debug(msg)

        self.assertIsInstance(msg, ofproto_v1_0_parser.OFPSwitchFeatures)
        LOG.debug(msg.ports[65534])
        self.assertIsInstance(msg.ports[1], ofproto_v1_0_parser.OFPPhyPort)
        self.assertIsInstance(msg.ports[2], ofproto_v1_0_parser.OFPPhyPort)
        self.assertIsInstance(msg.ports[65534], ofproto_v1_0_parser.OFPPhyPort)

    def testPacketIn(self):
        (version,
         msg_type,
         msg_len,
         xid) = ofproto_parser.header(self.bufPacketIn)

        msg = ofproto_parser.msg(self,
                                 version,
                                 msg_type,
                                 msg_len,
                                 xid,
                                 self.bufPacketIn)
        LOG.debug(msg)
        self.assertIsInstance(msg, ofproto_v1_0_parser.OFPPacketIn)

    def test_check_msg_len(self):
        (version,
         msg_type,
         msg_len,
         xid) = ofproto_parser.header(self.bufPacketIn)

        msg_len = len(self.bufPacketIn) + 1
        self.assertRaises(AssertionError, ofproto_parser.msg, self, version,
                          msg_type, msg_len, xid, self.bufPacketIn)

    def test_check_msg_parser(self):
        (version,
         msg_type,
         msg_len,
         xid) = ofproto_parser.header(self.bufPacketIn)

        version = 0xff
        self.assertRaises(exception.OFPUnknownVersion, ofproto_parser.msg,
                          self, version, msg_type, msg_len, xid,
                          self.bufPacketIn)


class TestMsgBase(unittest.TestCase):
    """ Test case for ofproto_parser.MsgBase
    """

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_init(self):
        pass

    def test_set_xid(self):
        xid = 3841413783
        c = ofproto_parser.MsgBase(object)
        c.set_xid(xid)
        self.assertEqual(xid, c.xid)

    def test_set_xid_check_xid(self):
        xid = 2160492514
        c = ofproto_parser.MsgBase(object)
        c.xid = xid
        self.assertRaises(AssertionError, c.set_xid, xid)

    def _test_parser(self, msg_type=ofproto_v1_0.OFPT_HELLO):
        version = ofproto_v1_0.OFP_VERSION
        msg_len = ofproto_v1_0.OFP_HEADER_SIZE
        xid = 2183948390
        data = b'\x00\x01\x02\x03'

        fmt = ofproto_v1_0.OFP_HEADER_PACK_STR
        buf = struct.pack(fmt, version, msg_type, msg_len, xid) \
            + data

        res = ofproto_v1_0_parser.OFPHello.parser(
            object, version, msg_type, msg_len, xid, bytearray(buf))

        self.assertEqual(version, res.version)
        self.assertEqual(msg_type, res.msg_type)
        self.assertEqual(msg_len, res.msg_len)
        self.assertEqual(xid, res.xid)
        self.assertEqual(bytes(buf), res.buf)

        # test __str__()
        list_ = ('version', 'msg_type', 'msg_len', 'xid')
        check = {}
        for s in str(res).rsplit(','):
            if '=' in s:
                (k, v,) = s.rsplit('=')
                if k in list_:
                    check[k] = v

        self.assertEqual(hex(ofproto_v1_0.OFP_VERSION), check['version'])
        self.assertEqual(hex(ofproto_v1_0.OFPT_HELLO), check['msg_type'])
        self.assertEqual(hex(msg_len), check['msg_len'])
        self.assertEqual(hex(xid), check['xid'])

        return True

    def test_parser(self):
        self.assertTrue(self._test_parser())

    def test_parser_check_msg_type(self):
        self.assertRaises(AssertionError, self._test_parser,
                          ofproto_v1_0.OFPT_ERROR)

    def _test_serialize(self):

        class Datapath(object):
            ofproto = ofproto_v1_0
            ofproto_parser = ofproto_v1_0_parser

        c = ofproto_v1_0_parser.OFPHello(Datapath)

        c.serialize()
        self.assertEqual(ofproto_v1_0.OFP_VERSION, c.version)
        self.assertEqual(ofproto_v1_0.OFPT_HELLO, c.msg_type)
        self.assertEqual(0, c.xid)

        return True

    def test_serialize(self):
        self.assertTrue(self._test_serialize())


class TestMsgStrAttr(unittest.TestCase):
    """ Test case for ofproto_parser.msg_str_attr
    """

    def test_msg_str_attr(self):
        class Check(object):
            check = 'msg_str_attr_test'

        c = Check()
        buf = ''

        res = ofproto_parser.msg_str_attr(c, buf, ('check',))
        str_ = str(res)
        str_ = str_.rsplit()
        self.assertEqual('check', str_[0])
        self.assertEqual('msg_str_attr_test', str_[1])
