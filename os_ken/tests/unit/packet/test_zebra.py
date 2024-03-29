# Copyright (C) 2017 Nippon Telegraph and Telephone Corporation.
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

import os
import socket
import sys
import unittest
from unittest import mock

from os_ken.lib import pcaplib
from os_ken.lib.packet import packet
from os_ken.lib.packet import zebra
from os_ken.utils import binary_str


PCAP_DATA_DIR = os.path.join(
    os.path.dirname(sys.modules[__name__].__file__),
    '../../packet_data/pcap/')


_patch_frr_v2 = mock.patch(
    'os_ken.lib.packet.zebra._is_frr_version_ge',
    mock.MagicMock(side_effect=lambda x: x == zebra._FRR_VERSION_2_0))


class Test_zebra(unittest.TestCase):
    """
    Test case for os_ken.lib.packet.zebra.
    """

    def _test_pcap_single(self, f):
        zebra_pcap_file = os.path.join(PCAP_DATA_DIR, f + '.pcap')
        # print('*** testing %s' % zebra_pcap_file)

        for _, buf in pcaplib.Reader(open(zebra_pcap_file, 'rb')):
            # Checks if Zebra message can be parsed as expected.
            pkt = packet.Packet(buf)
            zebra_pkts = pkt.get_protocols(zebra.ZebraMessage)
            for zebra_pkt in zebra_pkts:
                self.assertTrue(isinstance(zebra_pkt, zebra.ZebraMessage),
                    'Failed to parse Zebra message: %s' % pkt)
            self.assertTrue(not isinstance(pkt.protocols[-1],
                               (bytes, bytearray)),
                'Some messages could not be parsed in %s: %s' % (f, pkt))

            # Checks if Zebra message can be serialized as expected.
            pkt.serialize()
            self.assertEqual(binary_str(buf), binary_str(pkt.data))

    def test_pcap_quagga(self):
        files = [
            'zebra_v2',
            'zebra_v3',
        ]

        for f in files:
            self._test_pcap_single(f)

    @_patch_frr_v2
    def test_pcap_frr_v2(self):
        files = [
            'zebra_v4_frr_v2',  # API version 4 on FRRouting v2.0
        ]

        for f in files:
            self._test_pcap_single(f)


class TestZebraMessage(unittest.TestCase):

    def test_get_header_size(self):
        self.assertEqual(zebra.ZebraMessage.V0_HEADER_SIZE,
            zebra.ZebraMessage.get_header_size(0))
        self.assertEqual(zebra.ZebraMessage.V1_HEADER_SIZE,
            zebra.ZebraMessage.get_header_size(2))
        self.assertEqual(zebra.ZebraMessage.V3_HEADER_SIZE,
            zebra.ZebraMessage.get_header_size(3))
        self.assertEqual(zebra.ZebraMessage.V3_HEADER_SIZE,
            zebra.ZebraMessage.get_header_size(4))

    def test_get_header_size_invalid_version(self):
        self.assertRaises(ValueError, zebra.ZebraMessage.get_header_size, 0xff)


class TestZebraRedistributeAdd(unittest.TestCase):
    buf = (
        b'\x02'  # route_type
    )
    route_type = zebra.ZEBRA_ROUTE_CONNECT

    def test_parser(self):
        body = zebra.ZebraRedistributeAdd.parse(self.buf, version=3)

        self.assertEqual(self.route_type, body.route_type)

        buf = body.serialize(version=3)

        self.assertEqual(binary_str(self.buf), binary_str(buf))


class TestZebraIPv4ImportLookup(unittest.TestCase):
    buf = (
        b'\x18'
        b'\xc0\xa8\x01\x01'  # prefix
    )
    prefix = '192.168.1.1/24'
    metric = None
    nexthop_num = 0
    from_zebra = False

    def test_parser(self):
        body = zebra.ZebraIPv4ImportLookup.parse(self.buf)

        self.assertEqual(self.prefix, body.prefix)
        self.assertEqual(self.metric, body.metric)
        self.assertEqual(self.nexthop_num, len(body.nexthops))
        self.assertEqual(self.from_zebra, body.from_zebra)

        buf = body.serialize()

        self.assertEqual(binary_str(self.buf), binary_str(buf))


class TestZebraIPv4ImportLookupFromZebra(unittest.TestCase):
    buf = (
        b'\xc0\xa8\x01\x01'  # prefix
        b'\x00\x00\x00\x14'  # metric
        b'\x01'              # nexthop_num
        b'\x01'              # nexthop_type
        b'\x00\x00\x00\x02'  # ifindex
    )
    prefix = '192.168.1.1'
    metric = 0x14
    nexthop_num = 1
    nexthop_type = zebra.ZEBRA_NEXTHOP_IFINDEX
    ifindex = 2
    from_zebra = True

    def test_parser(self):
        body = zebra.ZebraIPv4ImportLookup.parse_from_zebra(self.buf)

        self.assertEqual(self.prefix, body.prefix)
        self.assertEqual(self.metric, body.metric)
        self.assertEqual(self.nexthop_num, len(body.nexthops))
        self.assertEqual(self.nexthop_type, body.nexthops[0].type)
        self.assertEqual(self.ifindex, body.nexthops[0].ifindex)
        self.assertEqual(self.from_zebra, body.from_zebra)

        buf = body.serialize()

        self.assertEqual(binary_str(self.buf), binary_str(buf))


class TestZebraIPv4NexthopLookupMRib(unittest.TestCase):
    buf = (
        b'\xc0\xa8\x01\x01'  # addr
    )
    addr = '192.168.1.1'
    distance = None
    metric = None
    nexthop_num = 0

    def test_parser(self):
        body = zebra.ZebraIPv4NexthopLookupMRib.parse(self.buf)

        self.assertEqual(self.addr, body.addr)
        self.assertEqual(self.distance, body.distance)
        self.assertEqual(self.metric, body.metric)
        self.assertEqual(self.nexthop_num, len(body.nexthops))

        buf = body.serialize()

        self.assertEqual(binary_str(self.buf), binary_str(buf))


class TestZebraIPv4NexthopLookupMRibFromZebra(unittest.TestCase):
    buf = (
        b'\xc0\xa8\x01\x01'  # addr
        b'\x01'              # distance
        b'\x00\x00\x00\x14'  # metric
        b'\x01'              # nexthop_num
        b'\x01'              # nexthop_type
        b'\x00\x00\x00\x02'  # ifindex
    )
    addr = '192.168.1.1'
    distance = 1
    metric = 0x14
    nexthop_num = 1
    nexthop_type = zebra.ZEBRA_NEXTHOP_IFINDEX
    ifindex = 2

    def test_parser(self):
        body = zebra.ZebraIPv4NexthopLookupMRib.parse(self.buf)

        self.assertEqual(self.addr, body.addr)
        self.assertEqual(self.distance, body.distance)
        self.assertEqual(self.metric, body.metric)
        self.assertEqual(self.nexthop_num, len(body.nexthops))
        self.assertEqual(self.nexthop_type, body.nexthops[0].type)
        self.assertEqual(self.ifindex, body.nexthops[0].ifindex)

        buf = body.serialize()

        self.assertEqual(binary_str(self.buf), binary_str(buf))


class TestZebraNexthopUpdateIPv6(unittest.TestCase):
    buf = (
        b'\x00\x0a'          # family
        b'\x40'              # prefix_len
        b'\x20\x01\x0d\xb8'  # prefix
        b'\x00\x00\x00\x00'
        b'\x00\x00\x00\x14'  # metric
        b'\x01'              # nexthop_num
        b'\x01'              # nexthop_type
        b'\x00\x00\x00\x02'  # ifindex
    )
    family = socket.AF_INET6
    prefix = '2001:db8::/64'
    metric = 0x14
    nexthop_num = 1
    nexthop_type = zebra.ZEBRA_NEXTHOP_IFINDEX
    ifindex = 2

    @_patch_frr_v2
    def test_parser(self):
        body = zebra.ZebraNexthopUpdate.parse(self.buf)

        self.assertEqual(self.family, body.family)
        self.assertEqual(self.prefix, body.prefix)
        self.assertEqual(self.metric, body.metric)
        self.assertEqual(self.nexthop_num, len(body.nexthops))
        self.assertEqual(self.nexthop_type, body.nexthops[0].type)
        self.assertEqual(self.ifindex, body.nexthops[0].ifindex)

        buf = body.serialize()

        self.assertEqual(binary_str(self.buf), binary_str(buf))


class TestZebraInterfaceNbrAddressAdd(unittest.TestCase):
    buf = (
        b'\x00\x00\x00\x01'  # ifindex
        b'\x02'              # family
        b'\xc0\xa8\x01\x00'  # prefix
        b'\x18'              # prefix_len
    )
    ifindex = 1
    family = socket.AF_INET
    prefix = '192.168.1.0/24'

    @_patch_frr_v2
    def test_parser(self):
        body = zebra.ZebraInterfaceNbrAddressAdd.parse(self.buf)

        self.assertEqual(self.ifindex, body.ifindex)
        self.assertEqual(self.family, body.family)
        self.assertEqual(self.prefix, body.prefix)

        buf = body.serialize()

        self.assertEqual(binary_str(self.buf), binary_str(buf))


class TestZebraInterfaceBfdDestinationUpdate(unittest.TestCase):
    buf = (
        b'\x00\x00\x00\x01'  # ifindex
        b'\x02'              # dst_family
        b'\xc0\xa8\x01\x01'  # dst_prefix
        b'\x18'              # dst_prefix_len
        b'\x04'              # status
        b'\x02'              # src_family
        b'\xc0\xa8\x01\x02'  # src_prefix
        b'\x18'              # src_prefix_len
    )
    ifindex = 1
    dst_family = socket.AF_INET
    dst_prefix = '192.168.1.1/24'
    status = zebra.BFD_STATUS_UP
    src_family = socket.AF_INET
    src_prefix = '192.168.1.2/24'

    @_patch_frr_v2
    def test_parser(self):
        body = zebra.ZebraInterfaceBfdDestinationUpdate.parse(self.buf)

        self.assertEqual(self.ifindex, body.ifindex)
        self.assertEqual(self.dst_family, body.dst_family)
        self.assertEqual(self.dst_prefix, body.dst_prefix)
        self.assertEqual(self.status, body.status)
        self.assertEqual(self.src_family, body.src_family)
        self.assertEqual(self.src_prefix, body.src_prefix)

        buf = body.serialize()

        self.assertEqual(binary_str(self.buf), binary_str(buf))


class TestZebraBfdDestinationRegisterMultiHopEnabled(unittest.TestCase):
    buf = (
        b'\x00\x00\x00\x01'  # pid
        b'\x00\x02'          # dst_family
        b'\xc0\xa8\x01\x01'  # dst_prefix
        b'\x00\x00\x00\x10'  # min_rx_timer
        b'\x00\x00\x00\x20'  # min_tx_timer
        b'\x01'              # detect_mult
        b'\x01'              # multi_hop
        b'\x00\x02'          # src_family
        b'\xc0\xa8\x01\x02'  # src_prefix
        b'\x05'              # multi_hop_count
    )
    pid = 1
    dst_family = socket.AF_INET
    dst_prefix = '192.168.1.1'
    min_rx_timer = 0x10
    min_tx_timer = 0x20
    detect_mult = 1
    multi_hop = 1
    src_family = socket.AF_INET
    src_prefix = '192.168.1.2'
    multi_hop_count = 5
    ifname = None

    @_patch_frr_v2
    def test_parser(self):
        body = zebra.ZebraBfdDestinationRegister.parse(self.buf)

        self.assertEqual(self.pid, body.pid)
        self.assertEqual(self.dst_family, body.dst_family)
        self.assertEqual(self.dst_prefix, body.dst_prefix)
        self.assertEqual(self.min_rx_timer, body.min_rx_timer)
        self.assertEqual(self.min_tx_timer, body.min_tx_timer)
        self.assertEqual(self.detect_mult, body.detect_mult)
        self.assertEqual(self.multi_hop, body.multi_hop)
        self.assertEqual(self.src_family, body.src_family)
        self.assertEqual(self.src_prefix, body.src_prefix)
        self.assertEqual(self.multi_hop_count, body.multi_hop_count)
        self.assertEqual(self.ifname, body.ifname)

        buf = body.serialize()

        self.assertEqual(binary_str(self.buf), binary_str(buf))


class TestZebraBfdDestinationRegisterMultiHopDisabled(unittest.TestCase):
    buf = (
        b'\x00\x00\x00\x01'  # pid
        b'\x00\x02'          # dst_family
        b'\xc0\xa8\x01\x01'  # dst_prefix
        b'\x00\x00\x00\x10'  # min_rx_timer
        b'\x00\x00\x00\x20'  # min_tx_timer
        b'\x01'              # detect_mult
        b'\x00'              # multi_hop
        b'\x00\x02'          # src_family
        b'\xc0\xa8\x01\x02'  # src_prefix
        b'\x04'              # ifname_len
        b'eth0'              # ifname
    )
    pid = 1
    dst_family = socket.AF_INET
    dst_prefix = '192.168.1.1'
    min_rx_timer = 0x10
    min_tx_timer = 0x20
    detect_mult = 1
    multi_hop = 0
    src_family = socket.AF_INET
    src_prefix = '192.168.1.2'
    multi_hop_count = None
    ifname = 'eth0'

    @_patch_frr_v2
    def test_parser(self):
        body = zebra.ZebraBfdDestinationRegister.parse(self.buf)

        self.assertEqual(self.pid, body.pid)
        self.assertEqual(self.dst_family, body.dst_family)
        self.assertEqual(self.dst_prefix, body.dst_prefix)
        self.assertEqual(self.min_rx_timer, body.min_rx_timer)
        self.assertEqual(self.min_tx_timer, body.min_tx_timer)
        self.assertEqual(self.detect_mult, body.detect_mult)
        self.assertEqual(self.multi_hop, body.multi_hop)
        self.assertEqual(self.src_family, body.src_family)
        self.assertEqual(self.src_prefix, body.src_prefix)
        self.assertEqual(self.multi_hop_count, body.multi_hop_count)
        self.assertEqual(self.ifname, body.ifname)

        buf = body.serialize()

        self.assertEqual(binary_str(self.buf), binary_str(buf))


class TestZebraBfdDestinationRegisterMultiHopEnabledIPv6(unittest.TestCase):
    buf = (
        b'\x00\x00\x00\x01'  # pid
        b'\x00\x0a'          # dst_family
        b'\x20\x01\x0d\xb8'  # dst_prefix
        b'\x00\x00\x00\x00'
        b'\x00\x00\x00\x00'
        b'\x00\x00\x00\x01'
        b'\x00\x00\x00\x10'  # min_rx_timer
        b'\x00\x00\x00\x20'  # min_tx_timer
        b'\x01'              # detect_mult
        b'\x01'              # multi_hop
        b'\x00\x0a'          # src_family
        b'\x20\x01\x0d\xb8'  # src_prefix
        b'\x00\x00\x00\x00'
        b'\x00\x00\x00\x00'
        b'\x00\x00\x00\x02'
        b'\x05'              # multi_hop_count
    )
    pid = 1
    dst_family = socket.AF_INET6
    dst_prefix = '2001:db8::1'
    min_rx_timer = 0x10
    min_tx_timer = 0x20
    detect_mult = 1
    multi_hop = 1
    src_family = socket.AF_INET6
    src_prefix = '2001:db8::2'
    multi_hop_count = 5
    ifname = None

    @_patch_frr_v2
    def test_parser(self):
        body = zebra.ZebraBfdDestinationRegister.parse(self.buf)

        self.assertEqual(self.pid, body.pid)
        self.assertEqual(self.dst_family, body.dst_family)
        self.assertEqual(self.dst_prefix, body.dst_prefix)
        self.assertEqual(self.min_rx_timer, body.min_rx_timer)
        self.assertEqual(self.min_tx_timer, body.min_tx_timer)
        self.assertEqual(self.detect_mult, body.detect_mult)
        self.assertEqual(self.multi_hop, body.multi_hop)
        self.assertEqual(self.src_family, body.src_family)
        self.assertEqual(self.src_prefix, body.src_prefix)
        self.assertEqual(self.multi_hop_count, body.multi_hop_count)
        self.assertEqual(self.ifname, body.ifname)

        buf = body.serialize()

        self.assertEqual(binary_str(self.buf), binary_str(buf))


class TestZebraBfdDestinationDeregisterMultiHopEnabled(unittest.TestCase):
    buf = (
        b'\x00\x00\x00\x01'  # pid
        b'\x00\x02'          # dst_family
        b'\xc0\xa8\x01\x01'  # dst_prefix
        b'\x01'              # multi_hop
        b'\x00\x02'          # src_family
        b'\xc0\xa8\x01\x02'  # src_prefix
        b'\x05'              # multi_hop_count
    )
    pid = 1
    dst_family = socket.AF_INET
    dst_prefix = '192.168.1.1'
    multi_hop = 1
    src_family = socket.AF_INET
    src_prefix = '192.168.1.2'
    multi_hop_count = 5
    ifname = None

    @_patch_frr_v2
    def test_parser(self):
        body = zebra.ZebraBfdDestinationDeregister.parse(self.buf)

        self.assertEqual(self.pid, body.pid)
        self.assertEqual(self.dst_family, body.dst_family)
        self.assertEqual(self.dst_prefix, body.dst_prefix)
        self.assertEqual(self.multi_hop, body.multi_hop)
        self.assertEqual(self.src_family, body.src_family)
        self.assertEqual(self.src_prefix, body.src_prefix)
        self.assertEqual(self.multi_hop_count, body.multi_hop_count)
        self.assertEqual(self.ifname, body.ifname)

        buf = body.serialize()

        self.assertEqual(binary_str(self.buf), binary_str(buf))


class TestZebraBfdDestinationDeregisterMultiHopDisabled(unittest.TestCase):
    buf = (
        b'\x00\x00\x00\x01'  # pid
        b'\x00\x02'          # dst_family
        b'\xc0\xa8\x01\x01'  # dst_prefix
        b'\x00'              # multi_hop
        b'\x00\x02'          # src_family
        b'\xc0\xa8\x01\x02'  # src_prefix
        b'\x04'              # ifname_len
        b'eth0'              # ifname
    )
    pid = 1
    dst_family = socket.AF_INET
    dst_prefix = '192.168.1.1'
    multi_hop = 0
    src_family = socket.AF_INET
    src_prefix = '192.168.1.2'
    multi_hop_count = None
    ifname = 'eth0'

    @_patch_frr_v2
    def test_parser(self):
        body = zebra.ZebraBfdDestinationDeregister.parse(self.buf)

        self.assertEqual(self.pid, body.pid)
        self.assertEqual(self.dst_family, body.dst_family)
        self.assertEqual(self.dst_prefix, body.dst_prefix)
        self.assertEqual(self.multi_hop, body.multi_hop)
        self.assertEqual(self.src_family, body.src_family)
        self.assertEqual(self.src_prefix, body.src_prefix)
        self.assertEqual(self.multi_hop_count, body.multi_hop_count)
        self.assertEqual(self.ifname, body.ifname)

        buf = body.serialize()

        self.assertEqual(binary_str(self.buf), binary_str(buf))


class TestZebraBfdDestinationDeregisterMultiHopEnabledIPv6(unittest.TestCase):
    buf = (
        b'\x00\x00\x00\x01'  # pid
        b'\x00\x0a'          # dst_family
        b'\x20\x01\x0d\xb8'  # dst_prefix
        b'\x00\x00\x00\x00'
        b'\x00\x00\x00\x00'
        b'\x00\x00\x00\x01'
        b'\x01'              # multi_hop
        b'\x00\x0a'          # src_family
        b'\x20\x01\x0d\xb8'  # src_prefix
        b'\x00\x00\x00\x00'
        b'\x00\x00\x00\x00'
        b'\x00\x00\x00\x02'
        b'\x05'              # multi_hop_count
    )
    pid = 1
    dst_family = socket.AF_INET6
    dst_prefix = '2001:db8::1'
    multi_hop = 1
    src_family = socket.AF_INET6
    src_prefix = '2001:db8::2'
    multi_hop_count = 5
    ifname = None

    @_patch_frr_v2
    def test_parser(self):
        body = zebra.ZebraBfdDestinationDeregister.parse(self.buf)

        self.assertEqual(self.pid, body.pid)
        self.assertEqual(self.dst_family, body.dst_family)
        self.assertEqual(self.dst_prefix, body.dst_prefix)
        self.assertEqual(self.multi_hop, body.multi_hop)
        self.assertEqual(self.src_family, body.src_family)
        self.assertEqual(self.src_prefix, body.src_prefix)
        self.assertEqual(self.multi_hop_count, body.multi_hop_count)
        self.assertEqual(self.ifname, body.ifname)

        buf = body.serialize()

        self.assertEqual(binary_str(self.buf), binary_str(buf))


class TestZebraVrfAdd(unittest.TestCase):
    buf = (
        b'VRF1'              # vrf_name
        b'\x00\x00\x00\x00'
        b'\x00\x00\x00\x00'
        b'\x00\x00\x00\x00'
        b'\x00\x00\x00\x00'
        b'\x00\x00\x00\x00'
        b'\x00\x00\x00\x00'
        b'\x00\x00\x00\x00'
        b'\x00\x00\x00\x00'
    )
    vrf_name = 'VRF1'

    @_patch_frr_v2
    def test_parser(self):
        body = zebra.ZebraVrfAdd.parse(self.buf)

        self.assertEqual(self.vrf_name, body.vrf_name)

        buf = body.serialize()

        self.assertEqual(binary_str(self.buf), binary_str(buf))


class TestZebraInterfaceVrfUpdate(unittest.TestCase):
    buf = (
        b'\x00\x00\x00\x01'  # ifindex
        b'\x00\x02'          # vrf_id
    )
    ifindex = 1
    vrf_id = 2

    @_patch_frr_v2
    def test_parser(self):
        body = zebra.ZebraInterfaceVrfUpdate.parse(self.buf)

        self.assertEqual(self.ifindex, body.ifindex)
        self.assertEqual(self.vrf_id, body.vrf_id)

        buf = body.serialize()

        self.assertEqual(binary_str(self.buf), binary_str(buf))


class TestZebraInterfaceEnableRadv(unittest.TestCase):
    buf = (
        b'\x00\x00\x00\x01'  # ifindex
        b'\x00\x00\x01\x00'  # interval
    )
    ifindex = 1
    interval = 0x100

    @_patch_frr_v2
    def test_parser(self):
        body = zebra.ZebraInterfaceEnableRadv.parse(self.buf)

        self.assertEqual(self.ifindex, body.ifindex)
        self.assertEqual(self.interval, body.interval)

        buf = body.serialize()

        self.assertEqual(binary_str(self.buf), binary_str(buf))


class TestZebraMplsLabelsAddIPv4(unittest.TestCase):
    buf = (
        b'\x09'              # route_type
        b'\x00\x00\x00\x02'  # family
        b'\xc0\xa8\x01\x00'  # prefix
        b'\x18'              # prefix_len
        b'\xc0\xa8\x01\x01'  # gate_addr
        b'\x10'              # distance
        b'\x00\x00\x00\x64'  # in_label
        b'\x00\x00\x00\x03'  # out_label
    )
    route_type = zebra.ZEBRA_ROUTE_BGP
    family = socket.AF_INET
    prefix = '192.168.1.0/24'
    gate_addr = '192.168.1.1'
    distance = 0x10
    in_label = 100
    out_label = zebra.MPLS_IMP_NULL_LABEL

    @_patch_frr_v2
    def test_parser(self):
        body = zebra.ZebraMplsLabelsAdd.parse(self.buf)

        self.assertEqual(self.route_type, body.route_type)
        self.assertEqual(self.family, body.family)
        self.assertEqual(self.prefix, body.prefix)
        self.assertEqual(self.gate_addr, body.gate_addr)
        self.assertEqual(self.distance, body.distance)
        self.assertEqual(self.in_label, body.in_label)
        self.assertEqual(self.out_label, body.out_label)

        buf = body.serialize()

        self.assertEqual(binary_str(self.buf), binary_str(buf))


class TestZebraMplsLabelsAddIPv6(unittest.TestCase):
    buf = (
        b'\x09'              # route_type
        b'\x00\x00\x00\x0a'  # family
        b'\x20\x01\x0d\xb8'  # prefix
        b'\x00\x00\x00\x00'
        b'\x00\x00\x00\x00'
        b'\x00\x00\x00\x00'
        b'\x40'              # prefix_len
        b'\x20\x01\x0d\xb8'  # gate_addr
        b'\x00\x00\x00\x00'
        b'\x00\x00\x00\x00'
        b'\x00\x00\x00\x01'
        b'\x10'              # distance
        b'\x00\x00\x00\x64'  # in_label
        b'\x00\x00\x00\x03'  # out_label
    )
    route_type = zebra.ZEBRA_ROUTE_BGP
    family = socket.AF_INET6
    prefix = '2001:db8::/64'
    gate_addr = '2001:db8::1'
    distance = 0x10
    in_label = 100
    out_label = zebra.MPLS_IMP_NULL_LABEL

    @_patch_frr_v2
    def test_parser(self):
        body = zebra.ZebraMplsLabelsAdd.parse(self.buf)

        self.assertEqual(self.route_type, body.route_type)
        self.assertEqual(self.family, body.family)
        self.assertEqual(self.prefix, body.prefix)
        self.assertEqual(self.gate_addr, body.gate_addr)
        self.assertEqual(self.distance, body.distance)
        self.assertEqual(self.in_label, body.in_label)
        self.assertEqual(self.out_label, body.out_label)

        buf = body.serialize()

        self.assertEqual(binary_str(self.buf), binary_str(buf))
