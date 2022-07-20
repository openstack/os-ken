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
import inspect
import six
from os_ken.ofproto import ether, inet
from os_ken.lib.packet import arp
from os_ken.lib.packet import bpdu
from os_ken.lib.packet import ethernet
from os_ken.lib.packet import icmp, icmpv6
from os_ken.lib.packet import ipv4, ipv6
from os_ken.lib.packet import llc
from os_ken.lib.packet import packet, packet_utils
from os_ken.lib.packet import sctp
from os_ken.lib.packet import tcp, udp
from os_ken.lib.packet import vlan
from os_ken.lib import addrconv


LOG = logging.getLogger('test_packet')


class TestPacket(unittest.TestCase):
    """ Test case for packet
    """

    dst_mac = 'aa:aa:aa:aa:aa:aa'
    src_mac = 'bb:bb:bb:bb:bb:bb'
    dst_mac_bin = addrconv.mac.text_to_bin(dst_mac)
    src_mac_bin = addrconv.mac.text_to_bin(src_mac)
    dst_ip = '192.168.128.10'
    src_ip = '192.168.122.20'
    dst_ip_bin = addrconv.ipv4.text_to_bin(dst_ip)
    src_port = 50001
    dst_port = 50002
    src_ip_bin = addrconv.ipv4.text_to_bin(src_ip)
    payload = b'\x06\x06\x47\x50\x00\x00\x00\x00' \
        + b'\xcd\xc5\x00\x00\x00\x00\x00\x00' \
        + b'\x10\x11\x12\x13\x14\x15\x16\x17' \
        + b'\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f'

    def get_protocols(self, pkt):
        protocols = {}
        for p in pkt:
            if hasattr(p, 'protocol_name'):
                protocols[p.protocol_name] = p
            else:
                protocols['payload'] = p
        return protocols

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_arp(self):
        # buid packet
        e = ethernet.ethernet(self.dst_mac, self.src_mac,
                              ether.ETH_TYPE_ARP)
        a = arp.arp(1, ether.ETH_TYPE_IP, 6, 4, 2,
                    self.src_mac, self.src_ip, self.dst_mac,
                    self.dst_ip)
        p = packet.Packet()
        p.add_protocol(e)
        p.add_protocol(a)
        p.serialize()

        # ethernet !6s6sH
        e_buf = self.dst_mac_bin \
            + self.src_mac_bin \
            + b'\x08\x06'

        # arp !HHBBH6sI6sI
        a_buf = b'\x00\x01' \
            + b'\x08\x00' \
            + b'\x06' \
            + b'\x04' \
            + b'\x00\x02' \
            + self.src_mac_bin \
            + self.src_ip_bin \
            + self.dst_mac_bin \
            + self.dst_ip_bin

        buf = e_buf + a_buf

        # Append padding if ethernet frame is less than 60 bytes length
        pad_len = 60 - len(buf)
        if pad_len > 0:
            buf += b'\x00' * pad_len
        self.assertEqual(buf, p.data)

        # parse
        pkt = packet.Packet(p.data)
        protocols = self.get_protocols(pkt)
        p_eth = protocols['ethernet']
        p_arp = protocols['arp']

        # ethernet
        self.assertTrue(p_eth)
        self.assertEqual(self.dst_mac, p_eth.dst)
        self.assertEqual(self.src_mac, p_eth.src)
        self.assertEqual(ether.ETH_TYPE_ARP, p_eth.ethertype)

        # arp
        self.assertTrue(p_arp)
        self.assertEqual(1, p_arp.hwtype)
        self.assertEqual(ether.ETH_TYPE_IP, p_arp.proto)
        self.assertEqual(6, p_arp.hlen)
        self.assertEqual(4, p_arp.plen)
        self.assertEqual(2, p_arp.opcode)
        self.assertEqual(self.src_mac, p_arp.src_mac)
        self.assertEqual(self.src_ip, p_arp.src_ip)
        self.assertEqual(self.dst_mac, p_arp.dst_mac)
        self.assertEqual(self.dst_ip, p_arp.dst_ip)

        # to string
        eth_values = {'dst': self.dst_mac,
                      'src': self.src_mac,
                      'ethertype': ether.ETH_TYPE_ARP}
        _eth_str = ','.join(['%s=%s' % (k, repr(eth_values[k]))
                             for k, v in inspect.getmembers(p_eth)
                             if k in eth_values])
        eth_str = '%s(%s)' % (ethernet.ethernet.__name__, _eth_str)

        arp_values = {'hwtype': 1,
                      'proto': ether.ETH_TYPE_IP,
                      'hlen': 6,
                      'plen': 4,
                      'opcode': 2,
                      'src_mac': self.src_mac,
                      'dst_mac': self.dst_mac,
                      'src_ip': self.src_ip,
                      'dst_ip': self.dst_ip}
        _arp_str = ','.join(['%s=%s' % (k, repr(arp_values[k]))
                             for k, v in inspect.getmembers(p_arp)
                             if k in arp_values])
        arp_str = '%s(%s)' % (arp.arp.__name__, _arp_str)

        pkt_str = '%s, %s' % (eth_str, arp_str)

        self.assertEqual(eth_str, str(p_eth))
        self.assertEqual(eth_str, repr(p_eth))

        self.assertEqual(arp_str, str(p_arp))
        self.assertEqual(arp_str, repr(p_arp))

        self.assertEqual(pkt_str, str(pkt))
        self.assertEqual(pkt_str, repr(pkt))

    def test_vlan_arp(self):
        # buid packet
        e = ethernet.ethernet(self.dst_mac, self.src_mac,
                              ether.ETH_TYPE_8021Q)
        v = vlan.vlan(0b111, 0b1, 3, ether.ETH_TYPE_ARP)
        a = arp.arp(1, ether.ETH_TYPE_IP, 6, 4, 2,
                    self.src_mac, self.src_ip, self.dst_mac,
                    self.dst_ip)
        p = packet.Packet()
        p.add_protocol(e)
        p.add_protocol(v)
        p.add_protocol(a)
        p.serialize()

        # ethernet !6s6sH
        e_buf = self.dst_mac_bin \
            + self.src_mac_bin \
            + b'\x81\x00'

        # vlan !HH
        v_buf = b'\xF0\x03' \
            + b'\x08\x06'

        # arp !HHBBH6sI6sI
        a_buf = b'\x00\x01' \
            + b'\x08\x00' \
            + b'\x06' \
            + b'\x04' \
            + b'\x00\x02' \
            + self.src_mac_bin \
            + self.src_ip_bin \
            + self.dst_mac_bin \
            + self.dst_ip_bin

        buf = e_buf + v_buf + a_buf

        # Append padding if ethernet frame is less than 60 bytes length
        pad_len = 60 - len(buf)
        if pad_len > 0:
            buf += b'\x00' * pad_len
        self.assertEqual(buf, p.data)

        # parse
        pkt = packet.Packet(p.data)
        protocols = self.get_protocols(pkt)
        p_eth = protocols['ethernet']
        p_vlan = protocols['vlan']
        p_arp = protocols['arp']

        # ethernet
        self.assertTrue(p_eth)
        self.assertEqual(self.dst_mac, p_eth.dst)
        self.assertEqual(self.src_mac, p_eth.src)
        self.assertEqual(ether.ETH_TYPE_8021Q, p_eth.ethertype)

        # vlan
        self.assertTrue(p_vlan)
        self.assertEqual(0b111, p_vlan.pcp)
        self.assertEqual(0b1, p_vlan.cfi)
        self.assertEqual(3, p_vlan.vid)
        self.assertEqual(ether.ETH_TYPE_ARP, p_vlan.ethertype)

        # arp
        self.assertTrue(p_arp)
        self.assertEqual(1, p_arp.hwtype)
        self.assertEqual(ether.ETH_TYPE_IP, p_arp.proto)
        self.assertEqual(6, p_arp.hlen)
        self.assertEqual(4, p_arp.plen)
        self.assertEqual(2, p_arp.opcode)
        self.assertEqual(self.src_mac, p_arp.src_mac)
        self.assertEqual(self.src_ip, p_arp.src_ip)
        self.assertEqual(self.dst_mac, p_arp.dst_mac)
        self.assertEqual(self.dst_ip, p_arp.dst_ip)

        # to string
        eth_values = {'dst': self.dst_mac,
                      'src': self.src_mac,
                      'ethertype': ether.ETH_TYPE_8021Q}
        _eth_str = ','.join(['%s=%s' % (k, repr(eth_values[k]))
                             for k, v in inspect.getmembers(p_eth)
                             if k in eth_values])
        eth_str = '%s(%s)' % (ethernet.ethernet.__name__, _eth_str)

        vlan_values = {'pcp': 0b111,
                       'cfi': 0b1,
                       'vid': 3,
                       'ethertype': ether.ETH_TYPE_ARP}
        _vlan_str = ','.join(['%s=%s' % (k, repr(vlan_values[k]))
                              for k, v in inspect.getmembers(p_vlan)
                              if k in vlan_values])
        vlan_str = '%s(%s)' % (vlan.vlan.__name__, _vlan_str)

        arp_values = {'hwtype': 1,
                      'proto': ether.ETH_TYPE_IP,
                      'hlen': 6,
                      'plen': 4,
                      'opcode': 2,
                      'src_mac': self.src_mac,
                      'dst_mac': self.dst_mac,
                      'src_ip': self.src_ip,
                      'dst_ip': self.dst_ip}
        _arp_str = ','.join(['%s=%s' % (k, repr(arp_values[k]))
                             for k, v in inspect.getmembers(p_arp)
                             if k in arp_values])
        arp_str = '%s(%s)' % (arp.arp.__name__, _arp_str)

        pkt_str = '%s, %s, %s' % (eth_str, vlan_str, arp_str)

        self.assertEqual(eth_str, str(p_eth))
        self.assertEqual(eth_str, repr(p_eth))

        self.assertEqual(vlan_str, str(p_vlan))
        self.assertEqual(vlan_str, repr(p_vlan))

        self.assertEqual(arp_str, str(p_arp))
        self.assertEqual(arp_str, repr(p_arp))

        self.assertEqual(pkt_str, str(pkt))
        self.assertEqual(pkt_str, repr(pkt))

    def test_ipv4_udp(self):
        # buid packet
        e = ethernet.ethernet(self.dst_mac, self.src_mac,
                              ether.ETH_TYPE_IP)
        ip = ipv4.ipv4(4, 5, 1, 0, 3, 1, 4, 64, inet.IPPROTO_UDP, 0,
                       self.src_ip, self.dst_ip)
        u = udp.udp(0x190F, 0x1F90, 0, 0)

        p = packet.Packet()
        p.add_protocol(e)
        p.add_protocol(ip)
        p.add_protocol(u)
        p.add_protocol(self.payload)
        p.serialize()

        # ethernet !6s6sH
        e_buf = self.dst_mac_bin \
            + self.src_mac_bin \
            + b'\x08\x00'

        # ipv4 !BBHHHBBHII
        ip_buf = b'\x45' \
            + b'\x01' \
            + b'\x00\x3C' \
            + b'\x00\x03' \
            + b'\x20\x04' \
            + b'\x40' \
            + b'\x11' \
            + b'\x00\x00' \
            + self.src_ip_bin \
            + self.dst_ip_bin

        # udp !HHHH
        u_buf = b'\x19\x0F' \
            + b'\x1F\x90' \
            + b'\x00\x28' \
            + b'\x00\x00'

        buf = e_buf + ip_buf + u_buf + self.payload

        # parse
        pkt = packet.Packet(p.data)
        protocols = self.get_protocols(pkt)
        p_eth = protocols['ethernet']
        p_ipv4 = protocols['ipv4']
        p_udp = protocols['udp']

        # ethernet
        self.assertTrue(p_eth)
        self.assertEqual(self.dst_mac, p_eth.dst)
        self.assertEqual(self.src_mac, p_eth.src)
        self.assertEqual(ether.ETH_TYPE_IP, p_eth.ethertype)

        # ipv4
        self.assertTrue(p_ipv4)
        self.assertEqual(4, p_ipv4.version)
        self.assertEqual(5, p_ipv4.header_length)
        self.assertEqual(1, p_ipv4.tos)
        l = len(ip_buf) + len(u_buf) + len(self.payload)
        self.assertEqual(l, p_ipv4.total_length)
        self.assertEqual(3, p_ipv4.identification)
        self.assertEqual(1, p_ipv4.flags)
        self.assertEqual(64, p_ipv4.ttl)
        self.assertEqual(inet.IPPROTO_UDP, p_ipv4.proto)
        self.assertEqual(self.src_ip, p_ipv4.src)
        self.assertEqual(self.dst_ip, p_ipv4.dst)
        t = bytearray(ip_buf)
        struct.pack_into('!H', t, 10, p_ipv4.csum)
        self.assertEqual(packet_utils.checksum(t), 0)

        # udp
        self.assertTrue(p_udp)
        self.assertEqual(0x190f, p_udp.src_port)
        self.assertEqual(0x1F90, p_udp.dst_port)
        self.assertEqual(len(u_buf) + len(self.payload), p_udp.total_length)
        self.assertEqual(0x77b2, p_udp.csum)
        t = bytearray(u_buf)
        struct.pack_into('!H', t, 6, p_udp.csum)
        ph = struct.pack('!4s4sBBH', self.src_ip_bin, self.dst_ip_bin, 0,
                         17, len(u_buf) + len(self.payload))
        t = ph + t + self.payload
        self.assertEqual(packet_utils.checksum(t), 0)

        # payload
        self.assertTrue('payload' in protocols)
        self.assertEqual(self.payload, protocols['payload'])

        # to string
        eth_values = {'dst': self.dst_mac,
                      'src': self.src_mac,
                      'ethertype': ether.ETH_TYPE_IP}
        _eth_str = ','.join(['%s=%s' % (k, repr(eth_values[k]))
                             for k, v in inspect.getmembers(p_eth)
                             if k in eth_values])
        eth_str = '%s(%s)' % (ethernet.ethernet.__name__, _eth_str)

        ipv4_values = {'version': 4,
                       'header_length': 5,
                       'tos': 1,
                       'total_length': l,
                       'identification': 3,
                       'flags': 1,
                       'offset': p_ipv4.offset,
                       'ttl': 64,
                       'proto': inet.IPPROTO_UDP,
                       'csum': p_ipv4.csum,
                       'src': self.src_ip,
                       'dst': self.dst_ip,
                       'option': None}
        _ipv4_str = ','.join(['%s=%s' % (k, repr(ipv4_values[k]))
                              for k, v in inspect.getmembers(p_ipv4)
                              if k in ipv4_values])
        ipv4_str = '%s(%s)' % (ipv4.ipv4.__name__, _ipv4_str)

        udp_values = {'src_port': 0x190f,
                      'dst_port': 0x1F90,
                      'total_length': len(u_buf) + len(self.payload),
                      'csum': 0x77b2}
        _udp_str = ','.join(['%s=%s' % (k, repr(udp_values[k]))
                             for k, v in inspect.getmembers(p_udp)
                             if k in udp_values])
        udp_str = '%s(%s)' % (udp.udp.__name__, _udp_str)

        pkt_str = '%s, %s, %s, %s' % (eth_str, ipv4_str, udp_str,
                                      repr(protocols['payload']))

        self.assertEqual(eth_str, str(p_eth))
        self.assertEqual(eth_str, repr(p_eth))

        self.assertEqual(ipv4_str, str(p_ipv4))
        self.assertEqual(ipv4_str, repr(p_ipv4))

        self.assertEqual(udp_str, str(p_udp))
        self.assertEqual(udp_str, repr(p_udp))

        self.assertEqual(pkt_str, str(pkt))
        self.assertEqual(pkt_str, repr(pkt))

    def test_ipv4_tcp(self):
        # buid packet
        e = ethernet.ethernet(self.dst_mac, self.src_mac,
                              ether.ETH_TYPE_IP)
        ip = ipv4.ipv4(4, 5, 0, 0, 0, 0, 0, 64, inet.IPPROTO_TCP, 0,
                       self.src_ip, self.dst_ip)
        t = tcp.tcp(0x190F, 0x1F90, 0x123, 1, 6, 0b101010, 2048, 0, 0x6f,
                    b'\x01\x02')

        p = packet.Packet()
        p.add_protocol(e)
        p.add_protocol(ip)
        p.add_protocol(t)
        p.add_protocol(self.payload)
        p.serialize()

        # ethernet !6s6sH
        e_buf = self.dst_mac_bin \
            + self.src_mac_bin \
            + b'\x08\x00'

        # ipv4 !BBHHHBBHII
        ip_buf = b'\x45' \
            + b'\x00' \
            + b'\x00\x4C' \
            + b'\x00\x00' \
            + b'\x00\x00' \
            + b'\x40' \
            + b'\x06' \
            + b'\x00\x00' \
            + self.src_ip_bin \
            + self.dst_ip_bin

        # tcp !HHIIBBHHH + option
        t_buf = b'\x19\x0F' \
            + b'\x1F\x90' \
            + b'\x00\x00\x01\x23' \
            + b'\x00\x00\x00\x01' \
            + b'\x60' \
            + b'\x2A' \
            + b'\x08\x00' \
            + b'\x00\x00' \
            + b'\x00\x6F' \
            + b'\x01\x02\x00\x00'

        buf = e_buf + ip_buf + t_buf + self.payload

        # parse
        pkt = packet.Packet(p.data)
        protocols = self.get_protocols(pkt)
        p_eth = protocols['ethernet']
        p_ipv4 = protocols['ipv4']
        p_tcp = protocols['tcp']

        # ethernet
        self.assertTrue(p_eth)
        self.assertEqual(self.dst_mac, p_eth.dst)
        self.assertEqual(self.src_mac, p_eth.src)
        self.assertEqual(ether.ETH_TYPE_IP, p_eth.ethertype)

        # ipv4
        self.assertTrue(p_ipv4)
        self.assertEqual(4, p_ipv4.version)
        self.assertEqual(5, p_ipv4.header_length)
        self.assertEqual(0, p_ipv4.tos)
        l = len(ip_buf) + len(t_buf) + len(self.payload)
        self.assertEqual(l, p_ipv4.total_length)
        self.assertEqual(0, p_ipv4.identification)
        self.assertEqual(0, p_ipv4.flags)
        self.assertEqual(64, p_ipv4.ttl)
        self.assertEqual(inet.IPPROTO_TCP, p_ipv4.proto)
        self.assertEqual(self.src_ip, p_ipv4.src)
        self.assertEqual(self.dst_ip, p_ipv4.dst)
        t = bytearray(ip_buf)
        struct.pack_into('!H', t, 10, p_ipv4.csum)
        self.assertEqual(packet_utils.checksum(t), 0)

        # tcp
        self.assertTrue(p_tcp)
        self.assertEqual(0x190f, p_tcp.src_port)
        self.assertEqual(0x1F90, p_tcp.dst_port)
        self.assertEqual(0x123, p_tcp.seq)
        self.assertEqual(1, p_tcp.ack)
        self.assertEqual(6, p_tcp.offset)
        self.assertEqual(0b101010, p_tcp.bits)
        self.assertEqual(2048, p_tcp.window_size)
        self.assertEqual(0x6f, p_tcp.urgent)
        self.assertEqual(len(t_buf), len(p_tcp))
        t = bytearray(t_buf)
        struct.pack_into('!H', t, 16, p_tcp.csum)
        ph = struct.pack('!4s4sBBH', self.src_ip_bin, self.dst_ip_bin, 0,
                         6, len(t_buf) + len(self.payload))
        t = ph + t + self.payload
        self.assertEqual(packet_utils.checksum(t), 0)

        # payload
        self.assertTrue('payload' in protocols)
        self.assertEqual(self.payload, protocols['payload'])

        # to string
        eth_values = {'dst': self.dst_mac,
                      'src': self.src_mac,
                      'ethertype': ether.ETH_TYPE_IP}
        _eth_str = ','.join(['%s=%s' % (k, repr(eth_values[k]))
                             for k, v in inspect.getmembers(p_eth)
                             if k in eth_values])
        eth_str = '%s(%s)' % (ethernet.ethernet.__name__, _eth_str)

        ipv4_values = {'version': 4,
                       'header_length': 5,
                       'tos': 0,
                       'total_length': l,
                       'identification': 0,
                       'flags': 0,
                       'offset': p_ipv4.offset,
                       'ttl': 64,
                       'proto': inet.IPPROTO_TCP,
                       'csum': p_ipv4.csum,
                       'src': self.src_ip,
                       'dst': self.dst_ip,
                       'option': None}
        _ipv4_str = ','.join(['%s=%s' % (k, repr(ipv4_values[k]))
                              for k, v in inspect.getmembers(p_ipv4)
                              if k in ipv4_values])
        ipv4_str = '%s(%s)' % (ipv4.ipv4.__name__, _ipv4_str)

        tcp_values = {'src_port': 0x190f,
                      'dst_port': 0x1F90,
                      'seq': 0x123,
                      'ack': 1,
                      'offset': 6,
                      'bits': 0b101010,
                      'window_size': 2048,
                      'csum': p_tcp.csum,
                      'urgent': 0x6f,
                      'option': p_tcp.option}
        _tcp_str = ','.join(['%s=%s' % (k, repr(tcp_values[k]))
                             for k, v in inspect.getmembers(p_tcp)
                             if k in tcp_values])
        tcp_str = '%s(%s)' % (tcp.tcp.__name__, _tcp_str)

        pkt_str = '%s, %s, %s, %s' % (eth_str, ipv4_str, tcp_str,
                                      repr(protocols['payload']))

        self.assertEqual(eth_str, str(p_eth))
        self.assertEqual(eth_str, repr(p_eth))

        self.assertEqual(ipv4_str, str(p_ipv4))
        self.assertEqual(ipv4_str, repr(p_ipv4))

        self.assertEqual(tcp_str, str(p_tcp))
        self.assertEqual(tcp_str, repr(p_tcp))

        self.assertEqual(pkt_str, str(pkt))
        self.assertEqual(pkt_str, repr(pkt))

    def test_ipv4_sctp(self):
        # build packet
        e = ethernet.ethernet()
        ip = ipv4.ipv4(proto=inet.IPPROTO_SCTP)
        s = sctp.sctp(chunks=[sctp.chunk_data(payload_data=self.payload)])

        p = e / ip / s
        p.serialize()

        ipaddr = addrconv.ipv4.text_to_bin('0.0.0.0')

        # ethernet !6s6sH
        e_buf = b'\xff\xff\xff\xff\xff\xff' \
            + b'\x00\x00\x00\x00\x00\x00' \
            + b'\x08\x00'

        # ipv4 !BBHHHBBHII
        ip_buf = b'\x45' \
            + b'\x00' \
            + b'\x00\x50' \
            + b'\x00\x00' \
            + b'\x00\x00' \
            + b'\xff' \
            + b'\x84' \
            + b'\x00\x00' \
            + ipaddr \
            + ipaddr

        # sctp !HHII + chunk_data !BBHIHHI + payload
        s_buf = b'\x00\x00' \
            + b'\x00\x00' \
            + b'\x00\x00\x00\x00' \
            + b'\x00\x00\x00\x00' \
            + b'\x00' \
            + b'\x00' \
            + b'\x00\x00' \
            + b'\x00\x00\x00\x00' \
            + b'\x00\x00' \
            + b'\x00\x00' \
            + b'\x00\x00\x00\x00' \
            + self.payload

        buf = e_buf + ip_buf + s_buf

        # parse
        pkt = packet.Packet(p.data)
        protocols = self.get_protocols(pkt)
        p_eth = protocols['ethernet']
        p_ipv4 = protocols['ipv4']
        p_sctp = protocols['sctp']

        # ethernet
        self.assertTrue(p_eth)
        self.assertEqual('ff:ff:ff:ff:ff:ff', p_eth.dst)
        self.assertEqual('00:00:00:00:00:00', p_eth.src)
        self.assertEqual(ether.ETH_TYPE_IP, p_eth.ethertype)

        # ipv4
        self.assertTrue(p_ipv4)
        self.assertEqual(4, p_ipv4.version)
        self.assertEqual(5, p_ipv4.header_length)
        self.assertEqual(0, p_ipv4.tos)
        l = len(ip_buf) + len(s_buf)
        self.assertEqual(l, p_ipv4.total_length)
        self.assertEqual(0, p_ipv4.identification)
        self.assertEqual(0, p_ipv4.flags)
        self.assertEqual(255, p_ipv4.ttl)
        self.assertEqual(inet.IPPROTO_SCTP, p_ipv4.proto)
        self.assertEqual('10.0.0.1', p_ipv4.src)
        self.assertEqual('10.0.0.2', p_ipv4.dst)
        t = bytearray(ip_buf)
        struct.pack_into('!H', t, 10, p_ipv4.csum)
        self.assertEqual(packet_utils.checksum(t), 0x1403)

        # sctp
        self.assertTrue(p_sctp)
        self.assertEqual(1, p_sctp.src_port)
        self.assertEqual(1, p_sctp.dst_port)
        self.assertEqual(0, p_sctp.vtag)
        assert isinstance(p_sctp.chunks[0], sctp.chunk_data)
        self.assertEqual(0, p_sctp.chunks[0]._type)
        self.assertEqual(0, p_sctp.chunks[0].unordered)
        self.assertEqual(0, p_sctp.chunks[0].begin)
        self.assertEqual(0, p_sctp.chunks[0].end)
        self.assertEqual(16 + len(self.payload), p_sctp.chunks[0].length)
        self.assertEqual(0, p_sctp.chunks[0].tsn)
        self.assertEqual(0, p_sctp.chunks[0].sid)
        self.assertEqual(0, p_sctp.chunks[0].seq)
        self.assertEqual(0, p_sctp.chunks[0].payload_id)
        self.assertEqual(self.payload, p_sctp.chunks[0].payload_data)
        self.assertEqual(len(s_buf), len(p_sctp))

        # to string
        eth_values = {'dst': 'ff:ff:ff:ff:ff:ff',
                      'src': '00:00:00:00:00:00',
                      'ethertype': ether.ETH_TYPE_IP}
        _eth_str = ','.join(['%s=%s' % (k, repr(eth_values[k]))
                             for k, v in inspect.getmembers(p_eth)
                             if k in eth_values])
        eth_str = '%s(%s)' % (ethernet.ethernet.__name__, _eth_str)

        ipv4_values = {'version': 4,
                       'header_length': 5,
                       'tos': 0,
                       'total_length': l,
                       'identification': 0,
                       'flags': 0,
                       'offset': 0,
                       'ttl': 255,
                       'proto': inet.IPPROTO_SCTP,
                       'csum': p_ipv4.csum,
                       'src': '10.0.0.1',
                       'dst': '10.0.0.2',
                       'option': None}
        _ipv4_str = ','.join(['%s=%s' % (k, repr(ipv4_values[k]))
                              for k, v in inspect.getmembers(p_ipv4)
                              if k in ipv4_values])
        ipv4_str = '%s(%s)' % (ipv4.ipv4.__name__, _ipv4_str)

        data_values = {'unordered': 0,
                       'begin': 0,
                       'end': 0,
                       'length': 16 + len(self.payload),
                       'tsn': 0,
                       'sid': 0,
                       'seq': 0,
                       'payload_id': 0,
                       'payload_data': self.payload}
        _data_str = ','.join(['%s=%s' % (k, repr(data_values[k]))
                              for k in sorted(data_values.keys())])
        data_str = '[%s(%s)]' % (sctp.chunk_data.__name__, _data_str)

        sctp_values = {'src_port': 1,
                       'dst_port': 1,
                       'vtag': 0,
                       'csum': repr(p_sctp.csum),
                       'chunks': data_str}
        _sctp_str = ','.join(['%s=%s' % (k, sctp_values[k])
                              for k, _ in inspect.getmembers(p_sctp)
                              if k in sctp_values])
        sctp_str = '%s(%s)' % (sctp.sctp.__name__, _sctp_str)

        pkt_str = '%s, %s, %s' % (eth_str, ipv4_str, sctp_str)

        self.assertEqual(eth_str, str(p_eth))
        self.assertEqual(eth_str, repr(p_eth))

        self.assertEqual(ipv4_str, str(p_ipv4))
        self.assertEqual(ipv4_str, repr(p_ipv4))

        self.assertEqual(sctp_str, str(p_sctp))
        self.assertEqual(sctp_str, repr(p_sctp))

        self.assertEqual(pkt_str, str(pkt))
        self.assertEqual(pkt_str, repr(pkt))

    def test_ipv4_icmp(self):
        # buid packet
        e = ethernet.ethernet()
        ip = ipv4.ipv4(proto=inet.IPPROTO_ICMP)
        ic = icmp.icmp()

        p = e / ip / ic
        p.serialize()

        ipaddr = addrconv.ipv4.text_to_bin('0.0.0.0')

        # ethernet !6s6sH
        e_buf = b'\xff\xff\xff\xff\xff\xff' \
            + b'\x00\x00\x00\x00\x00\x00' \
            + b'\x08\x00'

        # ipv4 !BBHHHBBHII
        ip_buf = b'\x45' \
            + b'\x00' \
            + b'\x00\x1c' \
            + b'\x00\x00' \
            + b'\x00\x00' \
            + b'\xff' \
            + b'\x01' \
            + b'\x00\x00' \
            + ipaddr \
            + ipaddr

        # icmp !BBH + echo !HH
        ic_buf = b'\x08' \
            + b'\x00' \
            + b'\x00\x00' \
            + b'\x00\x00' \
            + b'\x00\x00'

        buf = e_buf + ip_buf + ic_buf

        # parse
        pkt = packet.Packet(p.data)
        protocols = self.get_protocols(pkt)
        p_eth = protocols['ethernet']
        p_ipv4 = protocols['ipv4']
        p_icmp = protocols['icmp']

        # ethernet
        self.assertTrue(p_eth)
        self.assertEqual('ff:ff:ff:ff:ff:ff', p_eth.dst)
        self.assertEqual('00:00:00:00:00:00', p_eth.src)
        self.assertEqual(ether.ETH_TYPE_IP, p_eth.ethertype)

        # ipv4
        self.assertTrue(p_ipv4)
        self.assertEqual(4, p_ipv4.version)
        self.assertEqual(5, p_ipv4.header_length)
        self.assertEqual(0, p_ipv4.tos)
        l = len(ip_buf) + len(ic_buf)
        self.assertEqual(l, p_ipv4.total_length)
        self.assertEqual(0, p_ipv4.identification)
        self.assertEqual(0, p_ipv4.flags)
        self.assertEqual(255, p_ipv4.ttl)
        self.assertEqual(inet.IPPROTO_ICMP, p_ipv4.proto)
        self.assertEqual('10.0.0.1', p_ipv4.src)
        self.assertEqual('10.0.0.2', p_ipv4.dst)
        t = bytearray(ip_buf)
        struct.pack_into('!H', t, 10, p_ipv4.csum)
        self.assertEqual(packet_utils.checksum(t), 0x1403)

        # icmp
        self.assertTrue(p_icmp)
        self.assertEqual(8, p_icmp.type)
        self.assertEqual(0, p_icmp.code)
        self.assertEqual(0, p_icmp.data.id)
        self.assertEqual(0, p_icmp.data.seq)
        self.assertEqual(len(ic_buf), len(p_icmp))
        t = bytearray(ic_buf)
        struct.pack_into('!H', t, 2, p_icmp.csum)
        self.assertEqual(packet_utils.checksum(t), 0)

        # to string
        eth_values = {'dst': 'ff:ff:ff:ff:ff:ff',
                      'src': '00:00:00:00:00:00',
                      'ethertype': ether.ETH_TYPE_IP}
        _eth_str = ','.join(['%s=%s' % (k, repr(eth_values[k]))
                             for k, _ in inspect.getmembers(p_eth)
                             if k in eth_values])
        eth_str = '%s(%s)' % (ethernet.ethernet.__name__, _eth_str)

        ipv4_values = {'version': 4,
                       'header_length': 5,
                       'tos': 0,
                       'total_length': l,
                       'identification': 0,
                       'flags': 0,
                       'offset': p_ipv4.offset,
                       'ttl': 255,
                       'proto': inet.IPPROTO_ICMP,
                       'csum': p_ipv4.csum,
                       'src': '10.0.0.1',
                       'dst': '10.0.0.2',
                       'option': None}
        _ipv4_str = ','.join(['%s=%s' % (k, repr(ipv4_values[k]))
                              for k, _ in inspect.getmembers(p_ipv4)
                              if k in ipv4_values])
        ipv4_str = '%s(%s)' % (ipv4.ipv4.__name__, _ipv4_str)

        echo_values = {'id': 0,
                       'seq': 0,
                       'data': None}
        _echo_str = ','.join(['%s=%s' % (k, repr(echo_values[k]))
                              for k in sorted(echo_values.keys())])
        echo_str = '%s(%s)' % (icmp.echo.__name__, _echo_str)
        icmp_values = {'type': 8,
                       'code': 0,
                       'csum': p_icmp.csum,
                       'data': echo_str}
        _icmp_str = ','.join(['%s=%s' % (k, icmp_values[k])
                              for k, _ in inspect.getmembers(p_icmp)
                              if k in icmp_values])
        icmp_str = '%s(%s)' % (icmp.icmp.__name__, _icmp_str)

        pkt_str = '%s, %s, %s' % (eth_str, ipv4_str, icmp_str)

        self.assertEqual(eth_str, str(p_eth))
        self.assertEqual(eth_str, repr(p_eth))

        self.assertEqual(ipv4_str, str(p_ipv4))
        self.assertEqual(ipv4_str, repr(p_ipv4))

        self.assertEqual(icmp_str, str(p_icmp))
        self.assertEqual(icmp_str, repr(p_icmp))

        self.assertEqual(pkt_str, str(pkt))
        self.assertEqual(pkt_str, repr(pkt))

    def test_ipv6_udp(self):
        # build packet
        e = ethernet.ethernet(ethertype=ether.ETH_TYPE_IPV6)
        ip = ipv6.ipv6(nxt=inet.IPPROTO_UDP)
        u = udp.udp()

        p = e / ip / u / self.payload
        p.serialize()

        ipaddr = addrconv.ipv6.text_to_bin('::')

        # ethernet !6s6sH
        e_buf = b'\xff\xff\xff\xff\xff\xff' \
            + b'\x00\x00\x00\x00\x00\x00' \
            + b'\x86\xdd'

        # ipv6 !IHBB16s16s'
        ip_buf = b'\x60\x00\x00\x00' \
            + b'\x00\x00' \
            + b'\x11' \
            + b'\xff' \
            + b'\x00\x00' \
            + ipaddr \
            + ipaddr

        # udp !HHHH
        u_buf = b'\x00\x00' \
            + b'\x00\x00' \
            + b'\x00\x28' \
            + b'\x00\x00'

        buf = e_buf + ip_buf + u_buf + self.payload

        # parse
        pkt = packet.Packet(p.data)
        protocols = self.get_protocols(pkt)
        p_eth = protocols['ethernet']
        p_ipv6 = protocols['ipv6']
        p_udp = protocols['udp']

        # ethernet
        self.assertTrue(p_eth)
        self.assertEqual('ff:ff:ff:ff:ff:ff', p_eth.dst)
        self.assertEqual('00:00:00:00:00:00', p_eth.src)
        self.assertEqual(ether.ETH_TYPE_IPV6, p_eth.ethertype)

        # ipv6
        self.assertTrue(p_ipv6)
        self.assertEqual(6, p_ipv6.version)
        self.assertEqual(0, p_ipv6.traffic_class)
        self.assertEqual(0, p_ipv6.flow_label)
        self.assertEqual(len(u_buf) + len(self.payload), p_ipv6.payload_length)
        self.assertEqual(inet.IPPROTO_UDP, p_ipv6.nxt)
        self.assertEqual(255, p_ipv6.hop_limit)
        self.assertEqual('10::10', p_ipv6.src)
        self.assertEqual('20::20', p_ipv6.dst)

        # udp
        self.assertTrue(p_udp)
        self.assertEqual(1, p_udp.src_port)
        self.assertEqual(1, p_udp.dst_port)
        self.assertEqual(len(u_buf) + len(self.payload), p_udp.total_length)
        self.assertEqual(0x2B60, p_udp.csum)
        t = bytearray(u_buf)
        struct.pack_into('!H', t, 6, p_udp.csum)
        ph = struct.pack('!16s16sI3xB', ipaddr, ipaddr,
                         len(u_buf) + len(self.payload), 17)
        t = ph + t + self.payload
        self.assertEqual(packet_utils.checksum(t), 0x62)

        # payload
        self.assertTrue('payload' in protocols)
        self.assertEqual(self.payload, protocols['payload'])

        # to string
        eth_values = {'dst': 'ff:ff:ff:ff:ff:ff',
                      'src': '00:00:00:00:00:00',
                      'ethertype': ether.ETH_TYPE_IPV6}
        _eth_str = ','.join(['%s=%s' % (k, repr(eth_values[k]))
                             for k, v in inspect.getmembers(p_eth)
                             if k in eth_values])
        eth_str = '%s(%s)' % (ethernet.ethernet.__name__, _eth_str)

        ipv6_values = {'version': 6,
                       'traffic_class': 0,
                       'flow_label': 0,
                       'payload_length': len(u_buf) + len(self.payload),
                       'nxt': inet.IPPROTO_UDP,
                       'hop_limit': 255,
                       'src': '10::10',
                       'dst': '20::20',
                       'ext_hdrs': []}
        _ipv6_str = ','.join(['%s=%s' % (k, repr(ipv6_values[k]))
                              for k, v in inspect.getmembers(p_ipv6)
                              if k in ipv6_values])
        ipv6_str = '%s(%s)' % (ipv6.ipv6.__name__, _ipv6_str)

        udp_values = {'src_port': 1,
                      'dst_port': 1,
                      'total_length': len(u_buf) + len(self.payload),
                      'csum': 0x2B60}
        _udp_str = ','.join(['%s=%s' % (k, repr(udp_values[k]))
                             for k, v in inspect.getmembers(p_udp)
                             if k in udp_values])
        udp_str = '%s(%s)' % (udp.udp.__name__, _udp_str)

        pkt_str = '%s, %s, %s, %s' % (eth_str, ipv6_str, udp_str,
                                      repr(protocols['payload']))

        self.assertEqual(eth_str, str(p_eth))
        self.assertEqual(eth_str, repr(p_eth))

        self.assertEqual(ipv6_str, str(p_ipv6))
        self.assertEqual(ipv6_str, repr(p_ipv6))

        self.assertEqual(udp_str, str(p_udp))
        self.assertEqual(udp_str, repr(p_udp))

        self.assertEqual(pkt_str, str(pkt))
        self.assertEqual(pkt_str, repr(pkt))

    def test_ipv6_tcp(self):
        # build packet
        e = ethernet.ethernet(ethertype=ether.ETH_TYPE_IPV6)
        ip = ipv6.ipv6()
        t = tcp.tcp(option=b'\x01\x02')

        p = e / ip / t / self.payload
        p.serialize()

        ipaddr = addrconv.ipv6.text_to_bin('::')

        # ethernet !6s6sH
        e_buf = b'\xff\xff\xff\xff\xff\xff' \
            + b'\x00\x00\x00\x00\x00\x00' \
            + b'\x86\xdd'

        # ipv6 !IHBB16s16s'
        ip_buf = b'\x60\x00\x00\x00' \
            + b'\x00\x00' \
            + b'\x06' \
            + b'\xff' \
            + b'\x00\x00' \
            + ipaddr \
            + ipaddr

        # tcp !HHIIBBHHH + option
        t_buf = b'\x00\x00' \
            + b'\x00\x00' \
            + b'\x00\x00\x00\x00' \
            + b'\x00\x00\x00\x00' \
            + b'\x60' \
            + b'\x00' \
            + b'\x00\x00' \
            + b'\x00\x00' \
            + b'\x00\x00' \
            + b'\x01\x02\x00\x00'

        buf = e_buf + ip_buf + t_buf + self.payload

        # parse
        pkt = packet.Packet(p.data)
        protocols = self.get_protocols(pkt)
        p_eth = protocols['ethernet']
        p_ipv6 = protocols['ipv6']
        p_tcp = protocols['tcp']

        # ethernet
        self.assertTrue(p_eth)
        self.assertEqual('ff:ff:ff:ff:ff:ff', p_eth.dst)
        self.assertEqual('00:00:00:00:00:00', p_eth.src)
        self.assertEqual(ether.ETH_TYPE_IPV6, p_eth.ethertype)

        # ipv6
        self.assertTrue(p_ipv6)
        self.assertEqual(6, p_ipv6.version)
        self.assertEqual(0, p_ipv6.traffic_class)
        self.assertEqual(0, p_ipv6.flow_label)
        self.assertEqual(len(t_buf) + len(self.payload), p_ipv6.payload_length)
        self.assertEqual(inet.IPPROTO_TCP, p_ipv6.nxt)
        self.assertEqual(255, p_ipv6.hop_limit)
        self.assertEqual('10::10', p_ipv6.src)
        self.assertEqual('20::20', p_ipv6.dst)

        # tcp
        self.assertTrue(p_tcp)
        self.assertEqual(1, p_tcp.src_port)
        self.assertEqual(1, p_tcp.dst_port)
        self.assertEqual(0, p_tcp.seq)
        self.assertEqual(0, p_tcp.ack)
        self.assertEqual(6, p_tcp.offset)
        self.assertEqual(0, p_tcp.bits)
        self.assertEqual(0, p_tcp.window_size)
        self.assertEqual(0, p_tcp.urgent)
        self.assertEqual(len(t_buf), len(p_tcp))
        t = bytearray(t_buf)
        struct.pack_into('!H', t, 16, p_tcp.csum)
        ph = struct.pack('!16s16sI3xB', ipaddr, ipaddr,
                         len(t_buf) + len(self.payload), 6)
        t = ph + t + self.payload
        self.assertEqual(packet_utils.checksum(t), 0x62)

        # payload
        self.assertTrue('payload' in protocols)
        self.assertEqual(self.payload, protocols['payload'])

        # to string
        eth_values = {'dst': 'ff:ff:ff:ff:ff:ff',
                      'src': '00:00:00:00:00:00',
                      'ethertype': ether.ETH_TYPE_IPV6}
        _eth_str = ','.join(['%s=%s' % (k, repr(eth_values[k]))
                             for k, v in inspect.getmembers(p_eth)
                             if k in eth_values])
        eth_str = '%s(%s)' % (ethernet.ethernet.__name__, _eth_str)

        ipv6_values = {'version': 6,
                       'traffic_class': 0,
                       'flow_label': 0,
                       'payload_length': len(t_buf) + len(self.payload),
                       'nxt': inet.IPPROTO_TCP,
                       'hop_limit': 255,
                       'src': '10::10',
                       'dst': '20::20',
                       'ext_hdrs': []}
        _ipv6_str = ','.join(['%s=%s' % (k, repr(ipv6_values[k]))
                              for k, v in inspect.getmembers(p_ipv6)
                              if k in ipv6_values])
        ipv6_str = '%s(%s)' % (ipv6.ipv6.__name__, _ipv6_str)

        tcp_values = {'src_port': 1,
                      'dst_port': 1,
                      'seq': 0,
                      'ack': 0,
                      'offset': 6,
                      'bits': 0,
                      'window_size': 0,
                      'csum': p_tcp.csum,
                      'urgent': 0,
                      'option': p_tcp.option}
        _tcp_str = ','.join(['%s=%s' % (k, repr(tcp_values[k]))
                             for k, v in inspect.getmembers(p_tcp)
                             if k in tcp_values])
        tcp_str = '%s(%s)' % (tcp.tcp.__name__, _tcp_str)

        pkt_str = '%s, %s, %s, %s' % (eth_str, ipv6_str, tcp_str,
                                      repr(protocols['payload']))

        self.assertEqual(eth_str, str(p_eth))
        self.assertEqual(eth_str, repr(p_eth))

        self.assertEqual(ipv6_str, str(p_ipv6))
        self.assertEqual(ipv6_str, repr(p_ipv6))

        self.assertEqual(tcp_str, str(p_tcp))
        self.assertEqual(tcp_str, repr(p_tcp))

        self.assertEqual(pkt_str, str(pkt))
        self.assertEqual(pkt_str, repr(pkt))

    def test_ipv6_sctp(self):
        # build packet
        e = ethernet.ethernet(ethertype=ether.ETH_TYPE_IPV6)
        ip = ipv6.ipv6(nxt=inet.IPPROTO_SCTP)
        s = sctp.sctp(chunks=[sctp.chunk_data(payload_data=self.payload)])

        p = e / ip / s
        p.serialize()

        ipaddr = addrconv.ipv6.text_to_bin('::')

        # ethernet !6s6sH
        e_buf = b'\xff\xff\xff\xff\xff\xff' \
            + b'\x00\x00\x00\x00\x00\x00' \
            + b'\x86\xdd'

        # ipv6 !IHBB16s16s'
        ip_buf = b'\x60\x00\x00\x00' \
            + b'\x00\x00' \
            + b'\x84' \
            + b'\xff' \
            + b'\x00\x00' \
            + ipaddr \
            + ipaddr

        # sctp !HHII + chunk_data !BBHIHHI + payload
        s_buf = b'\x00\x00' \
            + b'\x00\x00' \
            + b'\x00\x00\x00\x00' \
            + b'\x00\x00\x00\x00' \
            + b'\x00' \
            + b'\x00' \
            + b'\x00\x00' \
            + b'\x00\x00\x00\x00' \
            + b'\x00\x00' \
            + b'\x00\x00' \
            + b'\x00\x00\x00\x00' \
            + self.payload

        buf = e_buf + ip_buf + s_buf

        # parse
        pkt = packet.Packet(p.data)
        protocols = self.get_protocols(pkt)
        p_eth = protocols['ethernet']
        p_ipv6 = protocols['ipv6']
        p_sctp = protocols['sctp']

        # ethernet
        self.assertTrue(p_eth)
        self.assertEqual('ff:ff:ff:ff:ff:ff', p_eth.dst)
        self.assertEqual('00:00:00:00:00:00', p_eth.src)
        self.assertEqual(ether.ETH_TYPE_IPV6, p_eth.ethertype)

        # ipv6
        self.assertTrue(p_ipv6)
        self.assertEqual(6, p_ipv6.version)
        self.assertEqual(0, p_ipv6.traffic_class)
        self.assertEqual(0, p_ipv6.flow_label)
        self.assertEqual(len(s_buf), p_ipv6.payload_length)
        self.assertEqual(inet.IPPROTO_SCTP, p_ipv6.nxt)
        self.assertEqual(255, p_ipv6.hop_limit)
        self.assertEqual('10::10', p_ipv6.src)
        self.assertEqual('20::20', p_ipv6.dst)

        # sctp
        self.assertTrue(p_sctp)
        self.assertEqual(1, p_sctp.src_port)
        self.assertEqual(1, p_sctp.dst_port)
        self.assertEqual(0, p_sctp.vtag)
        assert isinstance(p_sctp.chunks[0], sctp.chunk_data)
        self.assertEqual(0, p_sctp.chunks[0]._type)
        self.assertEqual(0, p_sctp.chunks[0].unordered)
        self.assertEqual(0, p_sctp.chunks[0].begin)
        self.assertEqual(0, p_sctp.chunks[0].end)
        self.assertEqual(16 + len(self.payload), p_sctp.chunks[0].length)
        self.assertEqual(0, p_sctp.chunks[0].tsn)
        self.assertEqual(0, p_sctp.chunks[0].sid)
        self.assertEqual(0, p_sctp.chunks[0].seq)
        self.assertEqual(0, p_sctp.chunks[0].payload_id)
        self.assertEqual(self.payload, p_sctp.chunks[0].payload_data)
        self.assertEqual(len(s_buf), len(p_sctp))

        # to string
        eth_values = {'dst': 'ff:ff:ff:ff:ff:ff',
                      'src': '00:00:00:00:00:00',
                      'ethertype': ether.ETH_TYPE_IPV6}
        _eth_str = ','.join(['%s=%s' % (k, repr(eth_values[k]))
                             for k, v in inspect.getmembers(p_eth)
                             if k in eth_values])
        eth_str = '%s(%s)' % (ethernet.ethernet.__name__, _eth_str)

        ipv6_values = {'version': 6,
                       'traffic_class': 0,
                       'flow_label': 0,
                       'payload_length': len(s_buf),
                       'nxt': inet.IPPROTO_SCTP,
                       'hop_limit': 255,
                       'src': '10::10',
                       'dst': '20::20',
                       'ext_hdrs': []}
        _ipv6_str = ','.join(['%s=%s' % (k, repr(ipv6_values[k]))
                              for k, v in inspect.getmembers(p_ipv6)
                              if k in ipv6_values])
        ipv6_str = '%s(%s)' % (ipv6.ipv6.__name__, _ipv6_str)

        data_values = {'unordered': 0,
                       'begin': 0,
                       'end': 0,
                       'length': 16 + len(self.payload),
                       'tsn': 0,
                       'sid': 0,
                       'seq': 0,
                       'payload_id': 0,
                       'payload_data': self.payload}
        _data_str = ','.join(['%s=%s' % (k, repr(data_values[k]))
                              for k in sorted(data_values.keys())])
        data_str = '[%s(%s)]' % (sctp.chunk_data.__name__, _data_str)

        sctp_values = {'src_port': 1,
                       'dst_port': 1,
                       'vtag': 0,
                       'csum': repr(p_sctp.csum),
                       'chunks': data_str}
        _sctp_str = ','.join(['%s=%s' % (k, sctp_values[k])
                              for k, _ in inspect.getmembers(p_sctp)
                              if k in sctp_values])
        sctp_str = '%s(%s)' % (sctp.sctp.__name__, _sctp_str)

        pkt_str = '%s, %s, %s' % (eth_str, ipv6_str, sctp_str)

        self.assertEqual(eth_str, str(p_eth))
        self.assertEqual(eth_str, repr(p_eth))

        self.assertEqual(ipv6_str, str(p_ipv6))
        self.assertEqual(ipv6_str, repr(p_ipv6))

        self.assertEqual(sctp_str, str(p_sctp))
        self.assertEqual(sctp_str, repr(p_sctp))

        self.assertEqual(pkt_str, str(pkt))
        self.assertEqual(pkt_str, repr(pkt))

    def test_ipv6_icmpv6(self):
        # build packet
        e = ethernet.ethernet(ethertype=ether.ETH_TYPE_IPV6)
        ip = ipv6.ipv6(nxt=inet.IPPROTO_ICMPV6)
        ic = icmpv6.icmpv6()

        p = e / ip / ic
        p.serialize()

        ipaddr = addrconv.ipv6.text_to_bin('::')

        # ethernet !6s6sH
        e_buf = b'\xff\xff\xff\xff\xff\xff' \
            + b'\x00\x00\x00\x00\x00\x00' \
            + b'\x86\xdd'

        # ipv6 !IHBB16s16s'
        ip_buf = b'\x60\x00\x00\x00' \
            + b'\x00\x00' \
            + b'\x3a' \
            + b'\xff' \
            + b'\x00\x00' \
            + ipaddr \
            + ipaddr

        # icmpv6 !BBH
        ic_buf = b'\x00' \
            + b'\x00' \
            + b'\x00\x00'

        buf = e_buf + ip_buf + ic_buf

        # parse
        pkt = packet.Packet(p.data)
        protocols = self.get_protocols(pkt)
        p_eth = protocols['ethernet']
        p_ipv6 = protocols['ipv6']
        p_icmpv6 = protocols['icmpv6']

        # ethernet
        self.assertTrue(p_eth)
        self.assertEqual('ff:ff:ff:ff:ff:ff', p_eth.dst)
        self.assertEqual('00:00:00:00:00:00', p_eth.src)
        self.assertEqual(ether.ETH_TYPE_IPV6, p_eth.ethertype)

        # ipv6
        self.assertTrue(p_ipv6)
        self.assertEqual(6, p_ipv6.version)
        self.assertEqual(0, p_ipv6.traffic_class)
        self.assertEqual(0, p_ipv6.flow_label)
        self.assertEqual(len(ic_buf), p_ipv6.payload_length)
        self.assertEqual(inet.IPPROTO_ICMPV6, p_ipv6.nxt)
        self.assertEqual(255, p_ipv6.hop_limit)
        self.assertEqual('10::10', p_ipv6.src)
        self.assertEqual('20::20', p_ipv6.dst)

        # icmpv6
        self.assertTrue(p_icmpv6)
        self.assertEqual(0, p_icmpv6.type_)
        self.assertEqual(0, p_icmpv6.code)
        self.assertEqual(len(ic_buf), len(p_icmpv6))
        t = bytearray(ic_buf)
        struct.pack_into('!H', t, 2, p_icmpv6.csum)
        ph = struct.pack('!16s16sI3xB', ipaddr, ipaddr, len(ic_buf), 58)
        t = ph + t
        self.assertEqual(packet_utils.checksum(t), 0x60)

        # to string
        eth_values = {'dst': 'ff:ff:ff:ff:ff:ff',
                      'src': '00:00:00:00:00:00',
                      'ethertype': ether.ETH_TYPE_IPV6}
        _eth_str = ','.join(['%s=%s' % (k, repr(eth_values[k]))
                             for k, _ in inspect.getmembers(p_eth)
                             if k in eth_values])
        eth_str = '%s(%s)' % (ethernet.ethernet.__name__, _eth_str)

        ipv6_values = {'version': 6,
                       'traffic_class': 0,
                       'flow_label': 0,
                       'payload_length': len(ic_buf),
                       'nxt': inet.IPPROTO_ICMPV6,
                       'hop_limit': 255,
                       'src': '10::10',
                       'dst': '20::20',
                       'ext_hdrs': []}
        _ipv6_str = ','.join(['%s=%s' % (k, repr(ipv6_values[k]))
                              for k, _ in inspect.getmembers(p_ipv6)
                              if k in ipv6_values])
        ipv6_str = '%s(%s)' % (ipv6.ipv6.__name__, _ipv6_str)

        icmpv6_values = {'type_': 0,
                         'code': 0,
                         'csum': p_icmpv6.csum,
                         'data': b''}
        _icmpv6_str = ','.join(['%s=%s' % (k, repr(icmpv6_values[k]))
                                for k, _ in inspect.getmembers(p_icmpv6)
                                if k in icmpv6_values])
        icmpv6_str = '%s(%s)' % (icmpv6.icmpv6.__name__, _icmpv6_str)

        pkt_str = '%s, %s, %s' % (eth_str, ipv6_str, icmpv6_str)

        self.assertEqual(eth_str, str(p_eth))
        self.assertEqual(eth_str, repr(p_eth))

        self.assertEqual(ipv6_str, str(p_ipv6))
        self.assertEqual(ipv6_str, repr(p_ipv6))

        self.assertEqual(icmpv6_str, str(p_icmpv6))
        self.assertEqual(icmpv6_str, repr(p_icmpv6))

        self.assertEqual(pkt_str, str(pkt))
        self.assertEqual(pkt_str, repr(pkt))

    def test_llc_bpdu(self):
        # buid packet
        e = ethernet.ethernet(self.dst_mac, self.src_mac,
                              ether.ETH_TYPE_IEEE802_3)
        llc_control = llc.ControlFormatU(0, 0, 0)
        l = llc.llc(llc.SAP_BPDU, llc.SAP_BPDU, llc_control)
        b = bpdu.ConfigurationBPDUs(flags=0,
                                    root_priority=32768,
                                    root_system_id_extension=0,
                                    root_mac_address=self.src_mac,
                                    root_path_cost=0,
                                    bridge_priority=32768,
                                    bridge_system_id_extension=0,
                                    bridge_mac_address=self.dst_mac,
                                    port_priority=128,
                                    port_number=4,
                                    message_age=1,
                                    max_age=20,
                                    hello_time=2,
                                    forward_delay=15)

        p = packet.Packet()
        p.add_protocol(e)
        p.add_protocol(l)
        p.add_protocol(b)
        p.serialize()

        # ethernet !6s6sH
        e_buf = self.dst_mac_bin + self.src_mac_bin + b'\x05\xdc'

        # llc !BBB
        l_buf = (b'\x42'
                 b'\x42'
                 b'\x03')

        # bpdu !HBBBQIQHHHHH
        b_buf = (b'\x00\x00'
                 b'\x00'
                 b'\x00'
                 b'\x00'
                 b'\x80\x00\xbb\xbb\xbb\xbb\xbb\xbb'
                 b'\x00\x00\x00\x00'
                 b'\x80\x00\xaa\xaa\xaa\xaa\xaa\xaa'
                 b'\x80\x04'
                 b'\x01\x00'
                 b'\x14\x00'
                 b'\x02\x00'
                 b'\x0f\x00')

        buf = e_buf + l_buf + b_buf

        # Append padding if ethernet frame is less than 60 bytes length
        pad_len = 60 - len(buf)
        if pad_len > 0:
            buf += b'\x00' * pad_len
        self.assertEqual(buf, p.data)

        # parse
        pkt = packet.Packet(p.data)
        protocols = self.get_protocols(pkt)
        p_eth = protocols['ethernet']
        p_llc = protocols['llc']
        p_bpdu = protocols['ConfigurationBPDUs']

        # ethernet
        self.assertTrue(p_eth)
        self.assertEqual(self.dst_mac, p_eth.dst)
        self.assertEqual(self.src_mac, p_eth.src)
        self.assertEqual(ether.ETH_TYPE_IEEE802_3, p_eth.ethertype)

        # llc
        self.assertTrue(p_llc)
        self.assertEqual(llc.SAP_BPDU, p_llc.dsap_addr)
        self.assertEqual(llc.SAP_BPDU, p_llc.ssap_addr)
        self.assertEqual(0, p_llc.control.modifier_function1)
        self.assertEqual(0, p_llc.control.pf_bit)
        self.assertEqual(0, p_llc.control.modifier_function2)

        # bpdu
        self.assertTrue(p_bpdu)
        self.assertEqual(bpdu.PROTOCOL_IDENTIFIER, p_bpdu._protocol_id)
        self.assertEqual(bpdu.PROTOCOLVERSION_ID_BPDU, p_bpdu._version_id)
        self.assertEqual(bpdu.TYPE_CONFIG_BPDU, p_bpdu._bpdu_type)
        self.assertEqual(0, p_bpdu.flags)
        self.assertEqual(32768, p_bpdu.root_priority)
        self.assertEqual(0, p_bpdu.root_system_id_extension)
        self.assertEqual(self.src_mac, p_bpdu.root_mac_address)
        self.assertEqual(0, p_bpdu.root_path_cost)
        self.assertEqual(32768, p_bpdu.bridge_priority)
        self.assertEqual(0, p_bpdu.bridge_system_id_extension)
        self.assertEqual(self.dst_mac, p_bpdu.bridge_mac_address)
        self.assertEqual(128, p_bpdu.port_priority)
        self.assertEqual(4, p_bpdu.port_number)
        self.assertEqual(1, p_bpdu.message_age)
        self.assertEqual(20, p_bpdu.max_age)
        self.assertEqual(2, p_bpdu.hello_time)
        self.assertEqual(15, p_bpdu.forward_delay)

        # to string
        eth_values = {'dst': self.dst_mac,
                      'src': self.src_mac,
                      'ethertype': ether.ETH_TYPE_IEEE802_3}
        _eth_str = ','.join(['%s=%s' % (k, repr(eth_values[k]))
                             for k, v in inspect.getmembers(p_eth)
                             if k in eth_values])
        eth_str = '%s(%s)' % (ethernet.ethernet.__name__, _eth_str)

        ctrl_values = {'modifier_function1': 0,
                       'pf_bit': 0,
                       'modifier_function2': 0}
        _ctrl_str = ','.join(['%s=%s' % (k, repr(ctrl_values[k]))
                              for k, v in inspect.getmembers(p_llc.control)
                              if k in ctrl_values])
        ctrl_str = '%s(%s)' % (llc.ControlFormatU.__name__, _ctrl_str)

        llc_values = {'dsap_addr': repr(llc.SAP_BPDU),
                      'ssap_addr': repr(llc.SAP_BPDU),
                      'control': ctrl_str}
        _llc_str = ','.join(['%s=%s' % (k, llc_values[k])
                             for k, v in inspect.getmembers(p_llc)
                             if k in llc_values])
        llc_str = '%s(%s)' % (llc.llc.__name__, _llc_str)

        _long = int if six.PY3 else long
        bpdu_values = {'flags': 0,
                       'root_priority': _long(32768),
                       'root_system_id_extension': _long(0),
                       'root_mac_address': self.src_mac,
                       'root_path_cost': 0,
                       'bridge_priority': _long(32768),
                       'bridge_system_id_extension': _long(0),
                       'bridge_mac_address': self.dst_mac,
                       'port_priority': 128,
                       'port_number': 4,
                       'message_age': float(1),
                       'max_age': float(20),
                       'hello_time': float(2),
                       'forward_delay': float(15)}
        _bpdu_str = ','.join(['%s=%s' % (k, repr(bpdu_values[k]))
                              for k, v in inspect.getmembers(p_bpdu)
                              if k in bpdu_values])
        bpdu_str = '%s(%s)' % (bpdu.ConfigurationBPDUs.__name__, _bpdu_str)

        pkt_str = '%s, %s, %s' % (eth_str, llc_str, bpdu_str)

        self.assertEqual(eth_str, str(p_eth))
        self.assertEqual(eth_str, repr(p_eth))

        self.assertEqual(llc_str, str(p_llc))
        self.assertEqual(llc_str, repr(p_llc))

        self.assertEqual(bpdu_str, str(p_bpdu))
        self.assertEqual(bpdu_str, repr(p_bpdu))

        self.assertEqual(pkt_str, str(pkt))
        self.assertEqual(pkt_str, repr(pkt))

    def test_div_api(self):
        e = ethernet.ethernet(self.dst_mac, self.src_mac, ether.ETH_TYPE_IP)
        i = ipv4.ipv4()
        u = udp.udp(self.src_port, self.dst_port)
        pkt = e / i / u
        self.assertTrue(isinstance(pkt, packet.Packet))
        self.assertTrue(isinstance(pkt.protocols[0], ethernet.ethernet))
        self.assertTrue(isinstance(pkt.protocols[1], ipv4.ipv4))
        self.assertTrue(isinstance(pkt.protocols[2], udp.udp))
