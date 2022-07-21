# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2013 YAMAMOTO Takashi <yamamoto at valinux co jp>
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
import testscenarios

from os_ken.ofproto import ofproto_v1_2
from os_ken.ofproto import ofproto_v1_3
from os_ken.ofproto import ofproto_v1_2_parser
from os_ken.ofproto import ofproto_v1_3_parser

from os_ken.lib import addrconv
from struct import unpack


def _list_test_cases():
    ofpps = [ofproto_v1_2_parser, ofproto_v1_3_parser]
    cases = []
    for ofpp in ofpps:
        mod = ofpp.__name__.split('.')[-1]
        method_name = 'test_' + mod + '_ofpmatch_compat'
        cases.append({'name': method_name, 'ofpp': ofpp})
    return cases


class Test_Parser_Compat(testscenarios.WithScenarios, unittest.TestCase):

    scenarios = [(case['name'], case) for case in _list_test_cases()]

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_parser(self):
        self._test(name=self.name, ofpp=self.ofpp)

    def _test(self, name, ofpp):
        ofp = {
            ofproto_v1_2_parser: ofproto_v1_2,
            ofproto_v1_3_parser: ofproto_v1_3,
        }[ofpp]

        in_port = 987654321
        eth_src = 'aa:bb:cc:dd:ee:ff'
        ipv4_src = '192.0.2.9'
        ipv6_src = 'fe80::f00b:a4ff:feef:5d8f'

        old_in_port = in_port
        old_eth_src = addrconv.mac.text_to_bin(eth_src)
        old_ipv4_src = unpack('!I', addrconv.ipv4.text_to_bin(ipv4_src))[0]
        old_ipv6_src = list(unpack('!8H',
                                   addrconv.ipv6.text_to_bin(ipv6_src)))

        def check(o):
            check_old(o)
            check_new(o)

        def check_old(o):
            # old api
            def get_field(m, t):
                for f in m.fields:
                    if isinstance(f, t):
                        return f
            get_value = lambda m, t: get_field(m, t).value

            self.assertEqual(get_value(o, ofpp.MTInPort), old_in_port)
            self.assertEqual(get_value(o, ofpp.MTEthSrc), old_eth_src)
            self.assertEqual(get_value(o, ofpp.MTIPV4Src), old_ipv4_src)
            self.assertEqual(get_value(o, ofpp.MTIPv6Src), old_ipv6_src)

        def check_new(o):
            # new api
            self.assertEqual(o['in_port'], in_port)
            self.assertEqual(o['eth_src'], eth_src)
            self.assertEqual(o['ipv4_src'], ipv4_src)
            self.assertEqual(o['ipv6_src'], ipv6_src)

        # ensure that old and new api produces the same thing

        # old api
        old = ofpp.OFPMatch()
        old.set_in_port(old_in_port)
        old.set_dl_src(old_eth_src)
        old.set_ipv4_src(old_ipv4_src)
        old.set_ipv6_src(old_ipv6_src)

        old_buf = bytearray()
        old.serialize(old_buf, 0)

        # note: you can't inspect an object composed with the old set_XXX api
        # before serialize().
        check_old(old)

        # another variant of old api; originally it was intended to be
        # internal but actually used in the field.  eg. LINC l2_switch_v1_3.py
        old2 = ofpp.OFPMatch()
        old2.append_field(ofp.OXM_OF_IN_PORT, old_in_port)
        old2.append_field(ofp.OXM_OF_ETH_SRC, old_eth_src)
        old2.append_field(ofp.OXM_OF_IPV4_SRC, old_ipv4_src)
        old2.append_field(ofp.OXM_OF_IPV6_SRC, old_ipv6_src)
        check_old(old2)

        old2_buf = bytearray()
        old2.serialize(old2_buf, 0)

        # new api
        new = ofpp.OFPMatch(in_port=in_port, eth_src=eth_src,
                            ipv4_src=ipv4_src, ipv6_src=ipv6_src)
        check_new(new)

        new_buf = bytearray()
        new.serialize(new_buf, 0)
        self.assertEqual(new_buf, old_buf)
        self.assertEqual(new_buf, old2_buf)

        old_jsondict = old.to_jsondict()
        old2_jsondict = old2.to_jsondict()
        new_jsondict = new.to_jsondict()
        self.assertEqual(new_jsondict, old_jsondict)
        self.assertEqual(new_jsondict, old2_jsondict)

        self.assertEqual(str(new), str(old))
        self.assertEqual(str(new), str(old2))

        # a parsed object can be inspected by old and new api

        check(ofpp.OFPMatch.parser(bytes(new_buf), 0))
        check(ofpp.OFPMatch.from_jsondict(list(new_jsondict.values())[0]))
