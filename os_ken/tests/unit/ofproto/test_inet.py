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
from os_ken.ofproto.inet import *


LOG = logging.getLogger('test_inet')


class TestInet(unittest.TestCase):
    """ Test case for inet
    """

    def test_ip_proto(self):
        self.assertEqual(IPPROTO_IP, 0)
        self.assertEqual(IPPROTO_HOPOPTS, 0)
        self.assertEqual(IPPROTO_ICMP, 1)
        self.assertEqual(IPPROTO_TCP, 6)
        self.assertEqual(IPPROTO_UDP, 17)
        self.assertEqual(IPPROTO_ROUTING, 43)
        self.assertEqual(IPPROTO_FRAGMENT, 44)
        self.assertEqual(IPPROTO_AH, 51)
        self.assertEqual(IPPROTO_ICMPV6, 58)
        self.assertEqual(IPPROTO_NONE, 59)
        self.assertEqual(IPPROTO_DSTOPTS, 60)
        self.assertEqual(IPPROTO_SCTP, 132)
