# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2013 Isaku Yamahata <yamahata at private email ne jp>
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

try:
    # Python 3
    from imp import reload
except ImportError:
    # Python 2
    pass

import unittest
import logging
from nose.tools import eq_


LOG = logging.getLogger('test_ofproto')


class TestOfprotCommon(unittest.TestCase):
    """ Test case for ofproto
    """

    def test_ofp_event(self):
        import os_ken.ofproto
        reload(os_ken.ofproto)
        import os_ken.controller.ofp_event
        reload(os_ken.controller.ofp_event)

    def test_ofproto(self):
        # When new version of OFP support is added,
        # this test must be updated.
        import os_ken.ofproto
        reload(os_ken.ofproto)
        ofp_modules = os_ken.ofproto.get_ofp_modules()

        import os_ken.ofproto.ofproto_v1_0
        import os_ken.ofproto.ofproto_v1_2
        import os_ken.ofproto.ofproto_v1_3
        import os_ken.ofproto.ofproto_v1_4
        import os_ken.ofproto.ofproto_v1_5
        eq_(set(ofp_modules.keys()), set([os_ken.ofproto.ofproto_v1_0.OFP_VERSION,
                                          os_ken.ofproto.ofproto_v1_2.OFP_VERSION,
                                          os_ken.ofproto.ofproto_v1_3.OFP_VERSION,
                                          os_ken.ofproto.ofproto_v1_4.OFP_VERSION,
                                          os_ken.ofproto.ofproto_v1_5.OFP_VERSION,
                                          ]))
        consts_mods = set([ofp_mod[0] for ofp_mod in ofp_modules.values()])
        eq_(consts_mods, set([os_ken.ofproto.ofproto_v1_0,
                              os_ken.ofproto.ofproto_v1_2,
                              os_ken.ofproto.ofproto_v1_3,
                              os_ken.ofproto.ofproto_v1_4,
                              os_ken.ofproto.ofproto_v1_5,
                              ]))

        parser_mods = set([ofp_mod[1] for ofp_mod in ofp_modules.values()])
        import os_ken.ofproto.ofproto_v1_0_parser
        import os_ken.ofproto.ofproto_v1_2_parser
        import os_ken.ofproto.ofproto_v1_3_parser
        import os_ken.ofproto.ofproto_v1_4_parser
        import os_ken.ofproto.ofproto_v1_5_parser
        eq_(parser_mods, set([os_ken.ofproto.ofproto_v1_0_parser,
                              os_ken.ofproto.ofproto_v1_2_parser,
                              os_ken.ofproto.ofproto_v1_3_parser,
                              os_ken.ofproto.ofproto_v1_4_parser,
                              os_ken.ofproto.ofproto_v1_5_parser,
                              ]))
