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

# vim: tabstop=4 shiftwidth=4 softtabstop=4

import unittest
import logging
import struct

from os_ken.lib.packet import bpdu


LOG = logging.getLogger(__name__)


class Test_ConfigurationBPDUs(unittest.TestCase):
    """ Test case for ConfigurationBPDUs
    """

    def setUp(self):
        self.protocol_id = bpdu.PROTOCOL_IDENTIFIER
        self.version_id = bpdu.ConfigurationBPDUs.VERSION_ID
        self.bpdu_type = bpdu.ConfigurationBPDUs.BPDU_TYPE
        self.flags = 0b00000001
        self.root_priority = 4096
        self.root_system_id_extension = 1
        self.root_mac_address = '12:34:56:78:9a:bc'
        self.root_path_cost = 2
        self.bridge_priority = 8192
        self.bridge_system_id_extension = 3
        self.bridge_mac_address = 'aa:aa:aa:aa:aa:aa'
        self.port_priority = 16
        self.port_number = 4
        self.message_age = 5
        self.max_age = 6
        self.hello_time = 7
        self.forward_delay = 8

        self.msg = bpdu.ConfigurationBPDUs(
            flags=self.flags,
            root_priority=self.root_priority,
            root_system_id_extension=self.root_system_id_extension,
            root_mac_address=self.root_mac_address,
            root_path_cost=self.root_path_cost,
            bridge_priority=self.bridge_priority,
            bridge_system_id_extension=self.bridge_system_id_extension,
            bridge_mac_address=self.bridge_mac_address,
            port_priority=self.port_priority,
            port_number=self.port_number,
            message_age=self.message_age,
            max_age=self.max_age,
            hello_time=self.hello_time,
            forward_delay=self.forward_delay)

        self.fmt = (bpdu.bpdu._PACK_STR
                    + bpdu.ConfigurationBPDUs._PACK_STR[1:])
        self.buf = struct.pack(self.fmt,
                               self.protocol_id, self.version_id,
                               self.bpdu_type, self.flags,
                               bpdu.ConfigurationBPDUs.encode_bridge_id(
                                   self.root_priority,
                                   self.root_system_id_extension,
                                   self.root_mac_address),
                               self.root_path_cost,
                               bpdu.ConfigurationBPDUs.encode_bridge_id(
                                   self.bridge_priority,
                                   self.bridge_system_id_extension,
                                   self.bridge_mac_address),
                               bpdu.ConfigurationBPDUs.encode_port_id(
                                   self.port_priority,
                                   self.port_number),
                               bpdu.ConfigurationBPDUs._encode_timer(
                                   self.message_age),
                               bpdu.ConfigurationBPDUs._encode_timer(
                                   self.max_age),
                               bpdu.ConfigurationBPDUs._encode_timer(
                                   self.hello_time),
                               bpdu.ConfigurationBPDUs._encode_timer(
                                   self.forward_delay))

    def test_init(self):
        self.assertEqual(self.protocol_id, self.msg._protocol_id)
        self.assertEqual(self.version_id, self.msg._version_id)
        self.assertEqual(self.bpdu_type, self.msg._bpdu_type)
        self.assertEqual(self.flags, self.msg.flags)
        self.assertEqual(self.root_priority, self.msg.root_priority)
        self.assertEqual(self.root_system_id_extension,
            self.msg.root_system_id_extension)
        self.assertEqual(self.root_mac_address, self.msg.root_mac_address)
        self.assertEqual(self.root_path_cost, self.msg.root_path_cost)
        self.assertEqual(self.bridge_priority, self.msg.bridge_priority)
        self.assertEqual(self.bridge_system_id_extension,
            self.msg.bridge_system_id_extension)
        self.assertEqual(self.bridge_mac_address, self.msg.bridge_mac_address)
        self.assertEqual(self.port_priority, self.msg.port_priority)
        self.assertEqual(self.port_number, self.msg.port_number)
        self.assertEqual(self.message_age, self.msg.message_age)
        self.assertEqual(self.max_age, self.msg.max_age)
        self.assertEqual(self.hello_time, self.msg.hello_time)
        self.assertEqual(self.forward_delay, self.msg.forward_delay)

    def test_parser(self):
        r1, r2, _ = bpdu.bpdu.parser(self.buf)

        self.assertEqual(type(r1), type(self.msg))
        self.assertEqual(r1._protocol_id, self.protocol_id)
        self.assertEqual(r1._version_id, self.version_id)
        self.assertEqual(r1._bpdu_type, self.bpdu_type)
        self.assertEqual(r1.flags, self.flags)
        self.assertEqual(r1.root_priority, self.root_priority)
        self.assertEqual(r1.root_system_id_extension, self.root_system_id_extension)
        self.assertEqual(r1.root_mac_address, self.root_mac_address)
        self.assertEqual(r1.root_path_cost, self.root_path_cost)
        self.assertEqual(r1.bridge_priority, self.bridge_priority)
        self.assertEqual(r1.bridge_system_id_extension, self.bridge_system_id_extension)
        self.assertEqual(r1.bridge_mac_address, self.bridge_mac_address)
        self.assertEqual(r1.port_priority, self.port_priority)
        self.assertEqual(r1.port_number, self.port_number)
        self.assertEqual(r1.message_age, self.message_age)
        self.assertEqual(r1.max_age, self.max_age)
        self.assertEqual(r1.hello_time, self.hello_time)
        self.assertEqual(r1.forward_delay, self.forward_delay)
        self.assertEqual(r2, None)

    def test_serialize(self):
        data = bytearray()
        prev = None
        buf = self.msg.serialize(data, prev)
        res = struct.unpack(self.fmt, buf)

        self.assertEqual(res[0], self.protocol_id)
        self.assertEqual(res[1], self.version_id)
        self.assertEqual(res[2], self.bpdu_type)
        self.assertEqual(res[3], self.flags)
        self.assertEqual(bpdu.ConfigurationBPDUs._decode_bridge_id(res[4]),
            (self.root_priority,
             self.root_system_id_extension,
             self.root_mac_address))
        self.assertEqual(res[5], self.root_path_cost)
        self.assertEqual(bpdu.ConfigurationBPDUs._decode_bridge_id(res[6]),
            (self.bridge_priority,
             self.bridge_system_id_extension,
             self.bridge_mac_address))
        self.assertEqual(bpdu.ConfigurationBPDUs._decode_port_id(res[7]),
            (self.port_priority,
             self.port_number))
        self.assertEqual(bpdu.ConfigurationBPDUs._decode_timer(res[8]), self.message_age)
        self.assertEqual(bpdu.ConfigurationBPDUs._decode_timer(res[9]), self.max_age)
        self.assertEqual(bpdu.ConfigurationBPDUs._decode_timer(res[10]), self.hello_time)
        self.assertEqual(bpdu.ConfigurationBPDUs._decode_timer(res[11]), self.forward_delay)

    def test_json(self):
        jsondict = self.msg.to_jsondict()
        msg = bpdu.ConfigurationBPDUs.from_jsondict(
            jsondict['ConfigurationBPDUs'])
        self.assertEqual(str(self.msg), str(msg))


class Test_TopologyChangeNotificationBPDUs(unittest.TestCase):
    """ Test case for TopologyChangeNotificationBPDUs
    """

    def setUp(self):
        self.protocol_id = bpdu.PROTOCOL_IDENTIFIER
        self.version_id = bpdu.TopologyChangeNotificationBPDUs.VERSION_ID
        self.bpdu_type = bpdu.TopologyChangeNotificationBPDUs.BPDU_TYPE

        self.msg = bpdu.TopologyChangeNotificationBPDUs()

        self.fmt = bpdu.bpdu._PACK_STR
        self.buf = struct.pack(self.fmt,
                               self.protocol_id,
                               self.version_id,
                               self.bpdu_type)

    def test_init(self):
        self.assertEqual(self.protocol_id, self.msg._protocol_id)
        self.assertEqual(self.version_id, self.msg._version_id)
        self.assertEqual(self.bpdu_type, self.msg._bpdu_type)

    def test_parser(self):
        r1, r2, _ = bpdu.bpdu.parser(self.buf)

        self.assertEqual(type(r1), type(self.msg))
        self.assertEqual(r1._protocol_id, self.protocol_id)
        self.assertEqual(r1._version_id, self.version_id)
        self.assertEqual(r1._bpdu_type, self.bpdu_type)
        self.assertEqual(r2, None)

    def test_serialize(self):
        data = bytearray()
        prev = None
        buf = self.msg.serialize(data, prev)
        res = struct.unpack(self.fmt, buf)

        self.assertEqual(res[0], self.protocol_id)
        self.assertEqual(res[1], self.version_id)
        self.assertEqual(res[2], self.bpdu_type)

    def test_json(self):
        jsondict = self.msg.to_jsondict()
        msg = bpdu.TopologyChangeNotificationBPDUs.from_jsondict(
            jsondict['TopologyChangeNotificationBPDUs'])
        self.assertEqual(str(self.msg), str(msg))


class Test_RstBPDUs(unittest.TestCase):
    """ Test case for RstBPDUs
    """

    def setUp(self):
        self.protocol_id = bpdu.PROTOCOL_IDENTIFIER
        self.version_id = bpdu.RstBPDUs.VERSION_ID
        self.bpdu_type = bpdu.RstBPDUs.BPDU_TYPE
        self.flags = 0b01111110
        self.root_priority = 4096
        self.root_system_id_extension = 1
        self.root_mac_address = '12:34:56:78:9a:bc'
        self.root_path_cost = 2
        self.bridge_priority = 8192
        self.bridge_system_id_extension = 3
        self.bridge_mac_address = 'aa:aa:aa:aa:aa:aa'
        self.port_priority = 16
        self.port_number = 4
        self.message_age = 5
        self.max_age = 6
        self.hello_time = 7
        self.forward_delay = 8
        self.version_1_length = bpdu.VERSION_1_LENGTH

        self.msg = bpdu.RstBPDUs(
            flags=self.flags,
            root_priority=self.root_priority,
            root_system_id_extension=self.root_system_id_extension,
            root_mac_address=self.root_mac_address,
            root_path_cost=self.root_path_cost,
            bridge_priority=self.bridge_priority,
            bridge_system_id_extension=self.bridge_system_id_extension,
            bridge_mac_address=self.bridge_mac_address,
            port_priority=self.port_priority,
            port_number=self.port_number,
            message_age=self.message_age,
            max_age=self.max_age,
            hello_time=self.hello_time,
            forward_delay=self.forward_delay)

        self.fmt = (bpdu.bpdu._PACK_STR
                    + bpdu.ConfigurationBPDUs._PACK_STR[1:]
                    + bpdu.RstBPDUs._PACK_STR[1:])
        self.buf = struct.pack(self.fmt,
                               self.protocol_id, self.version_id,
                               self.bpdu_type, self.flags,
                               bpdu.RstBPDUs.encode_bridge_id(
                                   self.root_priority,
                                   self.root_system_id_extension,
                                   self.root_mac_address),
                               self.root_path_cost,
                               bpdu.RstBPDUs.encode_bridge_id(
                                   self.bridge_priority,
                                   self.bridge_system_id_extension,
                                   self.bridge_mac_address),
                               bpdu.RstBPDUs.encode_port_id(
                                   self.port_priority,
                                   self.port_number),
                               bpdu.RstBPDUs._encode_timer(self.message_age),
                               bpdu.RstBPDUs._encode_timer(self.max_age),
                               bpdu.RstBPDUs._encode_timer(self.hello_time),
                               bpdu.RstBPDUs._encode_timer(self.forward_delay),
                               self.version_1_length)

    def test_init(self):
        self.assertEqual(self.protocol_id, self.msg._protocol_id)
        self.assertEqual(self.version_id, self.msg._version_id)
        self.assertEqual(self.bpdu_type, self.msg._bpdu_type)
        self.assertEqual(self.flags, self.msg.flags)
        self.assertEqual(self.root_priority, self.msg.root_priority)
        self.assertEqual(self.root_system_id_extension,
            self.msg.root_system_id_extension)
        self.assertEqual(self.root_mac_address, self.msg.root_mac_address)
        self.assertEqual(self.root_path_cost, self.msg.root_path_cost)
        self.assertEqual(self.bridge_priority, self.msg.bridge_priority)
        self.assertEqual(self.bridge_system_id_extension,
            self.msg.bridge_system_id_extension)
        self.assertEqual(self.bridge_mac_address, self.msg.bridge_mac_address)
        self.assertEqual(self.port_priority, self.msg.port_priority)
        self.assertEqual(self.port_number, self.msg.port_number)
        self.assertEqual(self.message_age, self.msg.message_age)
        self.assertEqual(self.max_age, self.msg.max_age)
        self.assertEqual(self.hello_time, self.msg.hello_time)
        self.assertEqual(self.forward_delay, self.msg.forward_delay)
        self.assertEqual(self.version_1_length, self.msg._version_1_length)

    def test_parser(self):
        r1, r2, _ = bpdu.bpdu.parser(self.buf)

        self.assertEqual(type(r1), type(self.msg))
        self.assertEqual(r1._protocol_id, self.protocol_id)
        self.assertEqual(r1._version_id, self.version_id)
        self.assertEqual(r1._bpdu_type, self.bpdu_type)
        self.assertEqual(r1.flags, self.flags)
        self.assertEqual(r1.root_priority, self.root_priority)
        self.assertEqual(r1.root_system_id_extension, self.root_system_id_extension)
        self.assertEqual(r1.root_mac_address, self.root_mac_address)
        self.assertEqual(r1.root_path_cost, self.root_path_cost)
        self.assertEqual(r1.bridge_priority, self.bridge_priority)
        self.assertEqual(r1.bridge_system_id_extension, self.bridge_system_id_extension)
        self.assertEqual(r1.bridge_mac_address, self.bridge_mac_address)
        self.assertEqual(r1.port_priority, self.port_priority)
        self.assertEqual(r1.port_number, self.port_number)
        self.assertEqual(r1.message_age, self.message_age)
        self.assertEqual(r1.max_age, self.max_age)
        self.assertEqual(r1.hello_time, self.hello_time)
        self.assertEqual(r1.forward_delay, self.forward_delay)
        self.assertEqual(r1._version_1_length, self.version_1_length)
        self.assertEqual(r2, None)

    def test_serialize(self):
        data = bytearray()
        prev = None
        buf = self.msg.serialize(data, prev)
        res = struct.unpack(self.fmt, buf)

        self.assertEqual(res[0], self.protocol_id)
        self.assertEqual(res[1], self.version_id)
        self.assertEqual(res[2], self.bpdu_type)
        self.assertEqual(res[3], self.flags)
        self.assertEqual(bpdu.RstBPDUs._decode_bridge_id(res[4]),
            (self.root_priority,
             self.root_system_id_extension,
             self.root_mac_address))
        self.assertEqual(res[5], self.root_path_cost)
        self.assertEqual(bpdu.RstBPDUs._decode_bridge_id(res[6]),
            (self.bridge_priority,
             self.bridge_system_id_extension,
             self.bridge_mac_address))
        self.assertEqual(bpdu.RstBPDUs._decode_port_id(res[7]),
            (self.port_priority,
             self.port_number))
        self.assertEqual(bpdu.RstBPDUs._decode_timer(res[8]), self.message_age)
        self.assertEqual(bpdu.RstBPDUs._decode_timer(res[9]), self.max_age)
        self.assertEqual(bpdu.RstBPDUs._decode_timer(res[10]), self.hello_time)
        self.assertEqual(bpdu.RstBPDUs._decode_timer(res[11]), self.forward_delay)
        self.assertEqual(res[12], self.version_1_length)

    def test_json(self):
        jsondict = self.msg.to_jsondict()
        msg = bpdu.RstBPDUs.from_jsondict(jsondict['RstBPDUs'])
        self.assertEqual(str(self.msg), str(msg))


class Test_UnknownVersion(unittest.TestCase):
    """ Test case for unknown BPDU version
    """

    def setUp(self):
        self.protocol_id = bpdu.PROTOCOL_IDENTIFIER
        self.version_id = 111  # Unknown version
        self.bpdu_type = bpdu.RstBPDUs.BPDU_TYPE
        self.flags = 0b01111110
        self.root_priority = 4096
        self.root_system_id_extension = 1
        self.root_mac_address = '12:34:56:78:9a:bc'
        self.root_path_cost = 2
        self.bridge_priority = 8192
        self.bridge_system_id_extension = 3
        self.bridge_mac_address = 'aa:aa:aa:aa:aa:aa'
        self.port_priority = 16
        self.port_number = 4
        self.message_age = 5
        self.max_age = 6
        self.hello_time = 7
        self.forward_delay = 8
        self.version_1_length = bpdu.VERSION_1_LENGTH

        self.fmt = (bpdu.bpdu._PACK_STR
                    + bpdu.ConfigurationBPDUs._PACK_STR[1:]
                    + bpdu.RstBPDUs._PACK_STR[1:])
        self.buf = struct.pack(self.fmt,
                               self.protocol_id, self.version_id,
                               self.bpdu_type, self.flags,
                               bpdu.RstBPDUs.encode_bridge_id(
                                   self.root_priority,
                                   self.root_system_id_extension,
                                   self.root_mac_address),
                               self.root_path_cost,
                               bpdu.RstBPDUs.encode_bridge_id(
                                   self.bridge_priority,
                                   self.bridge_system_id_extension,
                                   self.bridge_mac_address),
                               bpdu.RstBPDUs.encode_port_id(
                                   self.port_priority,
                                   self.port_number),
                               bpdu.RstBPDUs._encode_timer(self.message_age),
                               bpdu.RstBPDUs._encode_timer(self.max_age),
                               bpdu.RstBPDUs._encode_timer(self.hello_time),
                               bpdu.RstBPDUs._encode_timer(self.forward_delay),
                               self.version_1_length)

    def test_parser(self):
        r1, r2, _ = bpdu.bpdu.parser(self.buf)
        self.assertEqual(r1, self.buf)
        self.assertEqual(r2, None)


class Test_UnknownType(unittest.TestCase):
    """ Test case for unknown BPDU type
    """

    def setUp(self):
        self.protocol_id = bpdu.PROTOCOL_IDENTIFIER
        self.version_id = bpdu.RstBPDUs.VERSION_ID
        self.bpdu_type = 222  # Unknown type
        self.flags = 0b01111110
        self.root_priority = 4096
        self.root_system_id_extension = 1
        self.root_mac_address = '12:34:56:78:9a:bc'
        self.root_path_cost = 2
        self.bridge_priority = 8192
        self.bridge_system_id_extension = 3
        self.bridge_mac_address = 'aa:aa:aa:aa:aa:aa'
        self.port_priority = 16
        self.port_number = 4
        self.message_age = 5
        self.max_age = 6
        self.hello_time = 7
        self.forward_delay = 8
        self.version_1_length = bpdu.VERSION_1_LENGTH

        self.fmt = (bpdu.bpdu._PACK_STR
                    + bpdu.ConfigurationBPDUs._PACK_STR[1:]
                    + bpdu.RstBPDUs._PACK_STR[1:])
        self.buf = struct.pack(self.fmt,
                               self.protocol_id, self.version_id,
                               self.bpdu_type, self.flags,
                               bpdu.RstBPDUs.encode_bridge_id(
                                   self.root_priority,
                                   self.root_system_id_extension,
                                   self.root_mac_address),
                               self.root_path_cost,
                               bpdu.RstBPDUs.encode_bridge_id(
                                   self.bridge_priority,
                                   self.bridge_system_id_extension,
                                   self.bridge_mac_address),
                               bpdu.RstBPDUs.encode_port_id(
                                   self.port_priority,
                                   self.port_number),
                               bpdu.RstBPDUs._encode_timer(self.message_age),
                               bpdu.RstBPDUs._encode_timer(self.max_age),
                               bpdu.RstBPDUs._encode_timer(self.hello_time),
                               bpdu.RstBPDUs._encode_timer(self.forward_delay),
                               self.version_1_length)

    def test_parser(self):
        r1, r2, _ = bpdu.bpdu.parser(self.buf)
        self.assertEqual(r1, self.buf)
        self.assertEqual(r2, None)
