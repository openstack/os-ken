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
from os_ken.ofproto.ofproto_v1_2 import *


LOG = logging.getLogger('test_ofproto_v12')


class TestOfprot12(unittest.TestCase):
    """ Test case for ofproto_v1_2
    """

    def test_struct_ofp_header(self):
        self.assertEqual(OFP_HEADER_PACK_STR, '!BBHI')
        self.assertEqual(OFP_HEADER_SIZE, 8)

    def test_enum_ofp_type(self):
        self.assertEqual(OFPT_HELLO, 0)
        self.assertEqual(OFPT_ERROR, 1)
        self.assertEqual(OFPT_ECHO_REQUEST, 2)
        self.assertEqual(OFPT_ECHO_REPLY, 3)
        self.assertEqual(OFPT_EXPERIMENTER, 4)
        self.assertEqual(OFPT_FEATURES_REQUEST, 5)
        self.assertEqual(OFPT_FEATURES_REPLY, 6)
        self.assertEqual(OFPT_GET_CONFIG_REQUEST, 7)
        self.assertEqual(OFPT_GET_CONFIG_REPLY, 8)
        self.assertEqual(OFPT_SET_CONFIG, 9)
        self.assertEqual(OFPT_PACKET_IN, 10)
        self.assertEqual(OFPT_FLOW_REMOVED, 11)
        self.assertEqual(OFPT_PORT_STATUS, 12)
        self.assertEqual(OFPT_PACKET_OUT, 13)
        self.assertEqual(OFPT_FLOW_MOD, 14)
        self.assertEqual(OFPT_GROUP_MOD, 15)
        self.assertEqual(OFPT_PORT_MOD, 16)
        self.assertEqual(OFPT_TABLE_MOD, 17)
        self.assertEqual(OFPT_STATS_REQUEST, 18)
        self.assertEqual(OFPT_STATS_REPLY, 19)
        self.assertEqual(OFPT_BARRIER_REQUEST, 20)
        self.assertEqual(OFPT_BARRIER_REPLY, 21)
        self.assertEqual(OFPT_QUEUE_GET_CONFIG_REQUEST, 22)
        self.assertEqual(OFPT_QUEUE_GET_CONFIG_REPLY, 23)
        self.assertEqual(OFPT_ROLE_REQUEST, 24)
        self.assertEqual(OFPT_ROLE_REPLY, 25)

    def test_struct_ofp_port(self):
        self.assertEqual(OFP_PORT_PACK_STR, '!I4x6s2x16sIIIIIIII')
        self.assertEqual(OFP_PORT_SIZE, 64)

    def test_enum_ofp_port_config(self):
        self.assertEqual(OFPPC_PORT_DOWN, 1 << 0)
        self.assertEqual(OFPPC_NO_RECV, 1 << 2)
        self.assertEqual(OFPPC_NO_FWD, 1 << 5)
        self.assertEqual(OFPPC_NO_PACKET_IN, 1 << 6)

    def test_enum_ofp_port_state(self):
        self.assertEqual(OFPPS_LINK_DOWN, 1 << 0)
        self.assertEqual(OFPPS_BLOCKED, 1 << 1)
        self.assertEqual(OFPPS_LIVE, 1 << 2)

    def test_enum_ofp_port_no(self):
        self.assertEqual(OFPP_MAX, 0xffffff00)
        self.assertEqual(OFPP_IN_PORT, 0xfffffff8)
        self.assertEqual(OFPP_TABLE, 0xfffffff9)
        self.assertEqual(OFPP_NORMAL, 0xfffffffa)
        self.assertEqual(OFPP_FLOOD, 0xfffffffb)
        self.assertEqual(OFPP_ALL, 0xfffffffc)
        self.assertEqual(OFPP_CONTROLLER, 0xfffffffd)
        self.assertEqual(OFPP_LOCAL, 0xfffffffe)
        self.assertEqual(OFPP_ANY, 0xffffffff)
        self.assertEqual(OFPQ_ALL, 0xffffffff)

    def test_enum_ofp_port_features(self):
        self.assertEqual(OFPPF_10MB_HD, 1 << 0)
        self.assertEqual(OFPPF_10MB_FD, 1 << 1)
        self.assertEqual(OFPPF_100MB_HD, 1 << 2)
        self.assertEqual(OFPPF_100MB_FD, 1 << 3)
        self.assertEqual(OFPPF_1GB_HD, 1 << 4)
        self.assertEqual(OFPPF_1GB_FD, 1 << 5)
        self.assertEqual(OFPPF_10GB_FD, 1 << 6)
        self.assertEqual(OFPPF_40GB_FD, 1 << 7)
        self.assertEqual(OFPPF_100GB_FD, 1 << 8)
        self.assertEqual(OFPPF_1TB_FD, 1 << 9)
        self.assertEqual(OFPPF_OTHER, 1 << 10)
        self.assertEqual(OFPPF_COPPER, 1 << 11)
        self.assertEqual(OFPPF_FIBER, 1 << 12)
        self.assertEqual(OFPPF_AUTONEG, 1 << 13)
        self.assertEqual(OFPPF_PAUSE, 1 << 14)
        self.assertEqual(OFPPF_PAUSE_ASYM, 1 << 15)

    def test_struct_ofp_packet_queue(self):
        self.assertEqual(OFP_PACKET_QUEUE_PACK_STR, '!IIH6x')
        self.assertEqual(OFP_PACKET_QUEUE_SIZE, 16)

    def test_enum_ofp_queue_properties(self):
        self.assertEqual(OFPQT_MIN_RATE, 1)
        self.assertEqual(OFPQT_MAX_RATE, 2)
        self.assertEqual(OFPQT_EXPERIMENTER, 0xffff)

    def test_struct_ofp_queue_prop_header(self):
        self.assertEqual(OFP_QUEUE_PROP_HEADER_PACK_STR, '!HH4x')
        self.assertEqual(OFP_QUEUE_PROP_HEADER_SIZE, 8)

    def test_struct_ofp_queue_prop_min_rate(self):
        self.assertEqual(OFP_QUEUE_PROP_MIN_RATE_PACK_STR, '!H6x')
        self.assertEqual(OFP_QUEUE_PROP_MIN_RATE_SIZE, 16)

    def test_struct_ofp_queue_prop_max_rate(self):
        self.assertEqual(OFP_QUEUE_PROP_MAX_RATE_PACK_STR, '!H6x')
        self.assertEqual(OFP_QUEUE_PROP_MAX_RATE_SIZE, 16)

    def test_struct_ofp_queue_prop_experimenter(self):
        self.assertEqual(OFP_QUEUE_PROP_EXPERIMENTER_PACK_STR, '!I4x')
        self.assertEqual(OFP_QUEUE_PROP_EXPERIMENTER_SIZE, 16)

    def test_struct_ofp_match(self):
        self.assertEqual(OFP_MATCH_PACK_STR, '!HHBBBB')
        self.assertEqual(OFP_MATCH_SIZE, 8)

    def test_enum_ofp_match_type(self):
        self.assertEqual(OFPMT_STANDARD, 0)
        self.assertEqual(OFPMT_OXM, 1)

    def test_enum_ofp_oxm_class(self):
        self.assertEqual(OFPXMC_NXM_0, 0x0000)
        self.assertEqual(OFPXMC_NXM_1, 0x0001)
        self.assertEqual(OFPXMC_OPENFLOW_BASIC, 0x8000)
        self.assertEqual(OFPXMC_EXPERIMENTER, 0xFFFF)

    def test_enmu_oxm_ofb_match_fields(self):
        self.assertEqual(OFPXMT_OFB_IN_PORT, 0)
        self.assertEqual(OFPXMT_OFB_IN_PHY_PORT, 1)
        self.assertEqual(OFPXMT_OFB_METADATA, 2)
        self.assertEqual(OFPXMT_OFB_ETH_DST, 3)
        self.assertEqual(OFPXMT_OFB_ETH_SRC, 4)
        self.assertEqual(OFPXMT_OFB_ETH_TYPE, 5)
        self.assertEqual(OFPXMT_OFB_VLAN_VID, 6)
        self.assertEqual(OFPXMT_OFB_VLAN_PCP, 7)
        self.assertEqual(OFPXMT_OFB_IP_DSCP, 8)
        self.assertEqual(OFPXMT_OFB_IP_ECN, 9)
        self.assertEqual(OFPXMT_OFB_IP_PROTO, 10)
        self.assertEqual(OFPXMT_OFB_IPV4_SRC, 11)
        self.assertEqual(OFPXMT_OFB_IPV4_DST, 12)
        self.assertEqual(OFPXMT_OFB_TCP_SRC, 13)
        self.assertEqual(OFPXMT_OFB_TCP_DST, 14)
        self.assertEqual(OFPXMT_OFB_UDP_SRC, 15)
        self.assertEqual(OFPXMT_OFB_UDP_DST, 16)
        self.assertEqual(OFPXMT_OFB_SCTP_SRC, 17)
        self.assertEqual(OFPXMT_OFB_SCTP_DST, 18)
        self.assertEqual(OFPXMT_OFB_ICMPV4_TYPE, 19)
        self.assertEqual(OFPXMT_OFB_ICMPV4_CODE, 20)
        self.assertEqual(OFPXMT_OFB_ARP_OP, 21)
        self.assertEqual(OFPXMT_OFB_ARP_SPA, 22)
        self.assertEqual(OFPXMT_OFB_ARP_TPA, 23)
        self.assertEqual(OFPXMT_OFB_ARP_SHA, 24)
        self.assertEqual(OFPXMT_OFB_ARP_THA, 25)
        self.assertEqual(OFPXMT_OFB_IPV6_SRC, 26)
        self.assertEqual(OFPXMT_OFB_IPV6_DST, 27)
        self.assertEqual(OFPXMT_OFB_IPV6_FLABEL, 28)
        self.assertEqual(OFPXMT_OFB_ICMPV6_TYPE, 29)
        self.assertEqual(OFPXMT_OFB_ICMPV6_CODE, 30)
        self.assertEqual(OFPXMT_OFB_IPV6_ND_TARGET, 31)
        self.assertEqual(OFPXMT_OFB_IPV6_ND_SLL, 32)
        self.assertEqual(OFPXMT_OFB_IPV6_ND_TLL, 33)
        self.assertEqual(OFPXMT_OFB_MPLS_LABEL, 34)
        self.assertEqual(OFPXMT_OFB_MPLS_TC, 35)

    def test_enum_ofp_vlan_id(self):
        self.assertEqual(OFPVID_PRESENT, 0x1000)
        self.assertEqual(OFPVID_NONE, 0x0000)

    def test_struct_ofp_oxm_experimenter_header(self):
        self.assertEqual(OFP_OXM_EXPERIMENTER_HEADER_PACK_STR, '!II')
        self.assertEqual(OFP_OXM_EXPERIMENTER_HEADER_SIZE, 8)

    def test_enum_ofp_instruction_type(self):
        self.assertEqual(OFPIT_GOTO_TABLE, 1)
        self.assertEqual(OFPIT_WRITE_METADATA, 2)
        self.assertEqual(OFPIT_WRITE_ACTIONS, 3)
        self.assertEqual(OFPIT_APPLY_ACTIONS, 4)
        self.assertEqual(OFPIT_CLEAR_ACTIONS, 5)
        self.assertEqual(OFPIT_EXPERIMENTER, 0xFFFF)

    def test_struct_ofp_instruction_goto_table(self):
        self.assertEqual(OFP_INSTRUCTION_GOTO_TABLE_PACK_STR, '!HHB3x')
        self.assertEqual(OFP_INSTRUCTION_GOTO_TABLE_SIZE, 8)

    def test_struct_ofp_instruction_write_metadata(self):
        self.assertEqual(OFP_INSTRUCTION_WRITE_METADATA_PACK_STR, '!HH4xQQ')
        self.assertEqual(OFP_INSTRUCTION_WRITE_METADATA_SIZE, 24)

    def test_struct_ofp_instaruction_actions(self):
        self.assertEqual(OFP_INSTRUCTION_ACTIONS_PACK_STR, '!HH4x')
        self.assertEqual(OFP_INSTRUCTION_ACTIONS_SIZE, 8)

    def test_enum_ofp_action_type(self):
        self.assertEqual(OFPAT_OUTPUT, 0)
        self.assertEqual(OFPAT_COPY_TTL_OUT, 11)
        self.assertEqual(OFPAT_COPY_TTL_IN, 12)
        self.assertEqual(OFPAT_SET_MPLS_TTL, 15)
        self.assertEqual(OFPAT_DEC_MPLS_TTL, 16)
        self.assertEqual(OFPAT_PUSH_VLAN, 17)
        self.assertEqual(OFPAT_POP_VLAN, 18)
        self.assertEqual(OFPAT_PUSH_MPLS, 19)
        self.assertEqual(OFPAT_POP_MPLS, 20)
        self.assertEqual(OFPAT_SET_QUEUE, 21)
        self.assertEqual(OFPAT_GROUP, 22)
        self.assertEqual(OFPAT_SET_NW_TTL, 23)
        self.assertEqual(OFPAT_DEC_NW_TTL, 24)
        self.assertEqual(OFPAT_SET_FIELD, 25)
        self.assertEqual(OFPAT_EXPERIMENTER, 0xffff)

    def test_struct_ofp_action_header(self):
        self.assertEqual(OFP_ACTION_HEADER_PACK_STR, '!HH4x')
        self.assertEqual(OFP_ACTION_HEADER_SIZE, 8)

    def test_struct_ofp_action_output(self):
        self.assertEqual(OFP_ACTION_OUTPUT_PACK_STR, '!HHIH6x')
        self.assertEqual(OFP_ACTION_OUTPUT_SIZE, 16)

    def test_enum_ofp_controller_max_len(self):
        self.assertEqual(OFPCML_MAX, 0xffe5)
        self.assertEqual(OFPCML_NO_BUFFER, 0xffff)

    def test_struct_ofp_action_group(self):
        self.assertEqual(OFP_ACTION_GROUP_PACK_STR, '!HHI')
        self.assertEqual(OFP_ACTION_GROUP_SIZE, 8)

    def test_struct_ofp_action_set_queue(self):
        self.assertEqual(OFP_ACTION_SET_QUEUE_PACK_STR, '!HHI')
        self.assertEqual(OFP_ACTION_SET_QUEUE_SIZE, 8)

    def test_struct_ofp_aciton_mpls_ttl(self):
        self.assertEqual(OFP_ACTION_MPLS_TTL_PACK_STR, '!HHB3x')
        self.assertEqual(OFP_ACTION_MPLS_TTL_SIZE, 8)

    def test_struct_ofp_action_nw_ttl(self):
        self.assertEqual(OFP_ACTION_NW_TTL_PACK_STR, '!HHB3x')
        self.assertEqual(OFP_ACTION_NW_TTL_SIZE, 8)

    def test_struct_ofp_action_push(self):
        self.assertEqual(OFP_ACTION_PUSH_PACK_STR, '!HHH2x')
        self.assertEqual(OFP_ACTION_PUSH_SIZE, 8)

    def test_struct_ofp_action_pop_mpls(self):
        self.assertEqual(OFP_ACTION_POP_MPLS_PACK_STR, '!HHH2x')
        self.assertEqual(OFP_ACTION_POP_MPLS_SIZE, 8)

    def test_struct_ofp_action_set_field(self):
        self.assertEqual(OFP_ACTION_SET_FIELD_PACK_STR, '!HH4B')
        self.assertEqual(OFP_ACTION_SET_FIELD_SIZE, 8)

    def test_struct_ofp_action_experimenter_header(self):
        self.assertEqual(OFP_ACTION_EXPERIMENTER_HEADER_PACK_STR, '!HHI')
        self.assertEqual(OFP_ACTION_EXPERIMENTER_HEADER_SIZE, 8)

    def test_struct_ofp_switch_feature(self):
        self.assertEqual(OFP_SWITCH_FEATURES_PACK_STR, '!QIB3xII')
        self.assertEqual(OFP_SWITCH_FEATURES_SIZE, 32)

    def test_enum_ofp_capabilities(self):
        self.assertEqual(OFPC_FLOW_STATS, 1 << 0)
        self.assertEqual(OFPC_TABLE_STATS, 1 << 1)
        self.assertEqual(OFPC_PORT_STATS, 1 << 2)
        self.assertEqual(OFPC_GROUP_STATS, 1 << 3)
        self.assertEqual(OFPC_IP_REASM, 1 << 5)
        self.assertEqual(OFPC_QUEUE_STATS, 1 << 6)
        self.assertEqual(OFPC_PORT_BLOCKED, 1 << 8)

    def test_struct_ofp_switch_config(self):
        self.assertEqual(OFP_SWITCH_CONFIG_PACK_STR, '!HH')
        self.assertEqual(OFP_SWITCH_CONFIG_SIZE, 12)

    def test_enum_ofp_config_flags(self):
        self.assertEqual(OFPC_FRAG_NORMAL, 0)
        self.assertEqual(OFPC_FRAG_DROP, 1 << 0)
        self.assertEqual(OFPC_FRAG_REASM, 1 << 1)
        self.assertEqual(OFPC_FRAG_MASK, 3)
        self.assertEqual(OFPC_INVALID_TTL_TO_CONTROLLER, 1 << 2)

    def test_enum_ofp_table(self):
        self.assertEqual(OFPTT_MAX, 0xfe)
        self.assertEqual(OFPTT_ALL, 0xff)

    def test_struct_ofp_table_mod(self):
        self.assertEqual(OFP_TABLE_MOD_PACK_STR, '!B3xI')
        self.assertEqual(OFP_TABLE_MOD_SIZE, 16)

    def test_enum_ofp_table_config(self):
        self.assertEqual(OFPTC_TABLE_MISS_CONTROLLER, 0)
        self.assertEqual(OFPTC_TABLE_MISS_CONTINUE, 1 << 0)
        self.assertEqual(OFPTC_TABLE_MISS_DROP, 1 << 1)
        self.assertEqual(OFPTC_TABLE_MISS_MASK, 3)

    def test_struct_ofp_flow_mod(self):
        self.assertEqual(OFP_FLOW_MOD_PACK_STR, '!QQBBHHHIIIH2xHHBBBB')
        self.assertEqual(OFP_FLOW_MOD_SIZE, 56)

    def test_enum_ofp_flow_mod_command(self):
        self.assertEqual(OFPFC_ADD, 0)
        self.assertEqual(OFPFC_MODIFY, 1)
        self.assertEqual(OFPFC_MODIFY_STRICT, 2)
        self.assertEqual(OFPFC_DELETE, 3)
        self.assertEqual(OFPFC_DELETE_STRICT, 4)

    def test_enum_ofp_flow_mod_flags(self):
        self.assertEqual(OFPFF_SEND_FLOW_REM, 1 << 0)
        self.assertEqual(OFPFF_CHECK_OVERLAP, 1 << 1)
        self.assertEqual(OFPFF_RESET_COUNTS, 1 << 2)

    def test_struct_ofp_group_mod(self):
        self.assertEqual(OFP_GROUP_MOD_PACK_STR, '!HBxI')
        self.assertEqual(OFP_GROUP_MOD_SIZE, 16)

    # same to OFPP_*
    def test_enum_ofp_group(self):
        self.assertEqual(OFPG_MAX, 0xffffff00)
        self.assertEqual(OFPG_ALL, 0xfffffffc)
        self.assertEqual(OFPG_ANY, 0xffffffff)

    def test_enum_ofp_group_mod_command(self):
        self.assertEqual(OFPGC_ADD, 0)
        self.assertEqual(OFPGC_MODIFY, 1)
        self.assertEqual(OFPGC_DELETE, 2)

    def test_enum_ofp_group_type(self):
        self.assertEqual(OFPGT_ALL, 0)
        self.assertEqual(OFPGT_SELECT, 1)
        self.assertEqual(OFPGT_INDIRECT, 2)
        self.assertEqual(OFPGT_FF, 3)

    def test_struct_ofp_bucket(self):
        self.assertEqual(OFP_BUCKET_PACK_STR, '!HHII4x')
        self.assertEqual(OFP_BUCKET_SIZE, 16)

    def test_struct_ofp_port_mod(self):
        self.assertEqual(OFP_PORT_MOD_PACK_STR, '!I4x6s2xIII4x')
        self.assertEqual(OFP_PORT_MOD_SIZE, 40)

    def test_sturct_ofp_stats_request(self):
        self.assertEqual(OFP_STATS_REQUEST_PACK_STR, '!HH4x')
        self.assertEqual(OFP_STATS_REQUEST_SIZE, 16)

    # OFPSF_Rself.assertEqual* flags (none yet defined).
    # The only value defined for flags in a reply is whether more
    # replies will follow this one - this has the value 0x0001.
    def test_enum_ofp_stats_reply_flags(self):
        self.assertEqual(OFPSF_REPLY_MORE, 0x0001)

    def test_struct_ofp_stats_reply(self):
        self.assertEqual(OFP_STATS_REPLY_PACK_STR, '!HH4x')
        self.assertEqual(OFP_STATS_REPLY_SIZE, 16)

    def test_enum_ofp_stats_types(self):
        self.assertEqual(OFPST_DESC, 0)
        self.assertEqual(OFPST_FLOW, 1)
        self.assertEqual(OFPST_AGGREGATE, 2)
        self.assertEqual(OFPST_TABLE, 3)
        self.assertEqual(OFPST_PORT, 4)
        self.assertEqual(OFPST_QUEUE, 5)
        self.assertEqual(OFPST_GROUP, 6)
        self.assertEqual(OFPST_GROUP_DESC, 7)
        self.assertEqual(OFPST_GROUP_FEATURES, 8)
        self.assertEqual(OFPST_EXPERIMENTER, 0xffff)

    def test_struct_ofp_desc_stats(self):
        self.assertEqual(OFP_DESC_STATS_PACK_STR, '!256s256s256s32s256s')
        self.assertEqual(OFP_DESC_STATS_SIZE, 1056)

    def test_struct_ofp_flow_stats_request(self):
        self.assertEqual(OFP_FLOW_STATS_REQUEST_PACK_STR, '!B3xII4xQQ')
        self.assertEqual(OFP_FLOW_STATS_REQUEST_SIZE, 40)

    def test_struct_ofp_flow_stats(self):
        self.assertEqual(OFP_FLOW_STATS_PACK_STR, '!HBxIIHHH6xQQQ')
        self.assertEqual(OFP_FLOW_STATS_SIZE, 56)

    def test_struct_ofp_aggregate_stats_request(self):
        self.assertEqual(OFP_AGGREGATE_STATS_REQUEST_PACK_STR, '!B3xII4xQQ')
        self.assertEqual(OFP_AGGREGATE_STATS_REQUEST_SIZE, 40)

    def test_struct_ofp_aggregate_stats_reply(self):
        self.assertEqual(OFP_AGGREGATE_STATS_REPLY_PACK_STR, '!QQI4x')
        self.assertEqual(OFP_AGGREGATE_STATS_REPLY_SIZE, 24)

    def test_sturct_ofp_table_stats(self):
        self.assertEqual(OFP_TABLE_STATS_PACK_STR, '!B7x32sQQIIQQQQIIIIQQ')
        self.assertEqual(OFP_TABLE_STATS_SIZE, 128)

    def test_struct_ofp_port_stats_request(self):
        self.assertEqual(OFP_PORT_STATS_REQUEST_PACK_STR, '!I4x')
        self.assertEqual(OFP_PORT_STATS_REQUEST_SIZE, 8)

    def test_struct_ofp_port_stats(self):
        self.assertEqual(OFP_PORT_STATS_PACK_STR, '!I4xQQQQQQQQQQQQ')
        self.assertEqual(OFP_PORT_STATS_SIZE, 104)

    def test_struct_ofp_queue_stats_request(self):
        self.assertEqual(OFP_QUEUE_STATS_REQUEST_PACK_STR, '!II')
        self.assertEqual(OFP_QUEUE_STATS_REQUEST_SIZE, 8)

    def test_struct_ofp_queue_stats(self):
        self.assertEqual(OFP_QUEUE_STATS_PACK_STR, '!IIQQQ')
        self.assertEqual(OFP_QUEUE_STATS_SIZE, 32)

    def test_struct_ofp_group_stats_request(self):
        self.assertEqual(OFP_GROUP_STATS_REQUEST_PACK_STR, '!I4x')
        self.assertEqual(OFP_GROUP_STATS_REQUEST_SIZE, 8)

    def test_struct_ofp_group_stats(self):
        self.assertEqual(OFP_GROUP_STATS_PACK_STR, '!H2xII4xQQ')
        self.assertEqual(OFP_GROUP_STATS_SIZE, 32)

    def test_struct_ofp_bucket_counter(self):
        self.assertEqual(OFP_BUCKET_COUNTER_PACK_STR, '!QQ')
        self.assertEqual(OFP_BUCKET_COUNTER_SIZE, 16)

    def test_struct_ofp_group_desc_stats(self):
        self.assertEqual(OFP_GROUP_DESC_STATS_PACK_STR, '!HBxI')
        self.assertEqual(OFP_GROUP_DESC_STATS_SIZE, 8)

    def test_struct_ofp_group_features_stats(self):
        self.assertEqual(OFP_GROUP_FEATURES_STATS_PACK_STR, '!II4I4I')
        self.assertEqual(OFP_GROUP_FEATURES_STATS_SIZE, 40)

    def test_enmu_ofp_group_capabilities(self):
        self.assertEqual(OFPGFC_SELECT_WEIGHT, 1 << 0)
        self.assertEqual(OFPGFC_SELECT_LIVENESS, 1 << 1)
        self.assertEqual(OFPGFC_CHAINING, 1 << 2)
        self.assertEqual(OFPGFC_CHAINING_CHECKS, 1 << 3)

    def test_struct_ofp_experimenter_stats_header(self):
        self.assertEqual(OFP_EXPERIMENTER_STATS_HEADER_PACK_STR, '!II')
        self.assertEqual(OFP_EXPERIMENTER_STATS_HEADER_SIZE, 8)

    def test_struct_opf_queue_get_config_request(self):
        self.assertEqual(OFP_QUEUE_GET_CONFIG_REQUEST_PACK_STR, '!I4x')
        self.assertEqual(OFP_QUEUE_GET_CONFIG_REQUEST_SIZE, 16)

    def test_struct_ofp_queue_get_config_reply(self):
        self.assertEqual(OFP_QUEUE_GET_CONFIG_REPLY_PACK_STR, '!I4x')
        self.assertEqual(OFP_QUEUE_GET_CONFIG_REPLY_SIZE, 16)

    def test_struct_ofp_packet_out(self):
        self.assertEqual(OFP_PACKET_OUT_PACK_STR, '!IIH6x')
        self.assertEqual(OFP_PACKET_OUT_SIZE, 24)

    def test_struct_ofp_role_request(self):
        self.assertEqual(OFP_ROLE_REQUEST_PACK_STR, '!I4xQ')
        self.assertEqual(OFP_ROLE_REQUEST_SIZE, 24)

    def test_enum_ofp_controller_role(self):
        self.assertEqual(OFPCR_ROLE_NOCHANGE, 0)
        self.assertEqual(OFPCR_ROLE_EQUAL, 1)
        self.assertEqual(OFPCR_ROLE_MASTER, 2)
        self.assertEqual(OFPCR_ROLE_SLAVE, 3)

    def test_struct_ofp_packet_in(self):
        self.assertEqual(OFP_PACKET_IN_PACK_STR, '!IHBB')
        self.assertEqual(OFP_PACKET_IN_SIZE, 24)

    def test_enum_ofp_packet_in_reason(self):
        self.assertEqual(OFPR_NO_MATCH, 0)
        self.assertEqual(OFPR_ACTION, 1)
        self.assertEqual(OFPR_INVALID_TTL, 2)

    def test_struct_ofp_flow_removed(self):
        self.assertEqual(OFP_FLOW_REMOVED_PACK_STR, '!QHBBIIHHQQHHBBBB')
        self.assertEqual(OFP_FLOW_REMOVED_PACK_STR0, '!QHBBIIHHQQ')
        self.assertEqual(OFP_FLOW_REMOVED_SIZE, 56)

    def test_enum_ofp_flow_removed_reason(self):
        self.assertEqual(OFPRR_IDLE_TIMEOUT, 0)
        self.assertEqual(OFPRR_HARD_TIMEOUT, 1)
        self.assertEqual(OFPRR_DELETE, 2)
        self.assertEqual(OFPRR_GROUP_DELETE, 3)

    def test_struct_ofp_port_status(self):
        self.assertEqual(OFP_PORT_STATUS_PACK_STR, '!B7xI4x6s2x16sIIIIIIII')
        self.assertEqual(OFP_PORT_STATUS_DESC_OFFSET, 16)
        self.assertEqual(OFP_PORT_STATUS_SIZE, 80)

    def test_enum_ofp_port_reason(self):
        self.assertEqual(OFPPR_ADD, 0)
        self.assertEqual(OFPPR_DELETE, 1)
        self.assertEqual(OFPPR_MODIFY, 2)

    def test_struct_ofp_error_msg(self):
        self.assertEqual(OFP_ERROR_MSG_PACK_STR, '!HH')
        self.assertEqual(OFP_ERROR_MSG_SIZE, 12)

    def test_enum_ofp_error_type(self):
        self.assertEqual(OFPET_HELLO_FAILED, 0)
        self.assertEqual(OFPET_BAD_REQUEST, 1)
        self.assertEqual(OFPET_BAD_ACTION, 2)
        self.assertEqual(OFPET_BAD_INSTRUCTION, 3)
        self.assertEqual(OFPET_BAD_MATCH, 4)
        self.assertEqual(OFPET_FLOW_MOD_FAILED, 5)
        self.assertEqual(OFPET_GROUP_MOD_FAILED, 6)
        self.assertEqual(OFPET_PORT_MOD_FAILED, 7)
        self.assertEqual(OFPET_TABLE_MOD_FAILED, 8)
        self.assertEqual(OFPET_QUEUE_OP_FAILED, 9)
        self.assertEqual(OFPET_SWITCH_CONFIG_FAILED, 10)
        self.assertEqual(OFPET_ROLE_REQUEST_FAILED, 11)
        self.assertEqual(OFPET_EXPERIMENTER, 0xffff)

    def test_enum_ofp_hello_failed_code(self):
        self.assertEqual(OFPHFC_INCOMPATIBLE, 0)
        self.assertEqual(OFPHFC_EPERM, 1)

    def test_enum_ofp_bad_request_code(self):
        self.assertEqual(OFPBRC_BAD_VERSION, 0)
        self.assertEqual(OFPBRC_BAD_TYPE, 1)
        self.assertEqual(OFPBRC_BAD_STAT, 2)
        self.assertEqual(OFPBRC_BAD_EXPERIMENTER, 3)
        self.assertEqual(OFPBRC_BAD_EXP_TYPE, 4)
        self.assertEqual(OFPBRC_EPERM, 5)
        self.assertEqual(OFPBRC_BAD_LEN, 6)
        self.assertEqual(OFPBRC_BUFFER_EMPTY, 7)
        self.assertEqual(OFPBRC_BUFFER_UNKNOWN, 8)
        self.assertEqual(OFPBRC_BAD_TABLE_ID, 9)
        self.assertEqual(OFPBRC_IS_SLAVE, 10)
        self.assertEqual(OFPBRC_BAD_PORT, 11)
        self.assertEqual(OFPBRC_BAD_PACKET, 12)

    def test_enum_ofp_bad_action_code(self):
        self.assertEqual(OFPBAC_BAD_TYPE, 0)
        self.assertEqual(OFPBAC_BAD_LEN, 1)
        self.assertEqual(OFPBAC_BAD_EXPERIMENTER, 2)
        self.assertEqual(OFPBAC_BAD_EXP_TYPE, 3)
        self.assertEqual(OFPBAC_BAD_OUT_PORT, 4)
        self.assertEqual(OFPBAC_BAD_ARGUMENT, 5)
        self.assertEqual(OFPBAC_EPERM, 6)
        self.assertEqual(OFPBAC_TOO_MANY, 7)
        self.assertEqual(OFPBAC_BAD_QUEUE, 8)
        self.assertEqual(OFPBAC_BAD_OUT_GROUP, 9)
        self.assertEqual(OFPBAC_MATCH_INCONSISTENT, 10)
        self.assertEqual(OFPBAC_UNSUPPORTED_ORDER, 11)
        self.assertEqual(OFPBAC_BAD_TAG, 12)
        self.assertEqual(OFPBAC_BAD_SET_TYPE, 13)
        self.assertEqual(OFPBAC_BAD_SET_LEN, 14)
        self.assertEqual(OFPBAC_BAD_SET_ARGUMENT, 15)

    def test_enum_ofp_bad_instruction_code(self):
        self.assertEqual(OFPBIC_UNKNOWN_INST, 0)
        self.assertEqual(OFPBIC_UNSUP_INST, 1)
        self.assertEqual(OFPBIC_BAD_TABLE_ID, 2)
        self.assertEqual(OFPBIC_UNSUP_METADATA, 3)
        self.assertEqual(OFPBIC_UNSUP_METADATA_MASK, 4)
        self.assertEqual(OFPBIC_BAD_EXPERIMENTER, 5)
        self.assertEqual(OFPBIC_BAD_EXP_TYPE, 6)
        self.assertEqual(OFPBIC_BAD_LEN, 7)
        self.assertEqual(OFPBIC_EPERM, 8)

    def test_enum_ofp_bad_match_code(self):
        self.assertEqual(OFPBMC_BAD_TYPE, 0)
        self.assertEqual(OFPBMC_BAD_LEN, 1)
        self.assertEqual(OFPBMC_BAD_TAG, 2)
        self.assertEqual(OFPBMC_BAD_DL_ADDR_MASK, 3)
        self.assertEqual(OFPBMC_BAD_NW_ADDR_MASK, 4)
        self.assertEqual(OFPBMC_BAD_WILDCARDS, 5)
        self.assertEqual(OFPBMC_BAD_FIELD, 6)
        self.assertEqual(OFPBMC_BAD_VALUE, 7)
        self.assertEqual(OFPBMC_BAD_MASK, 8)
        self.assertEqual(OFPBMC_BAD_PREREQ, 9)
        self.assertEqual(OFPBMC_DUP_FIELD, 10)
        self.assertEqual(OFPBMC_EPERM, 11)

    def test_enum_ofp_flow_mod_failed_code(self):
        self.assertEqual(OFPFMFC_UNKNOWN, 0)
        self.assertEqual(OFPFMFC_TABLE_FULL, 1)
        self.assertEqual(OFPFMFC_BAD_TABLE_ID, 2)
        self.assertEqual(OFPFMFC_OVERLAP, 3)
        self.assertEqual(OFPFMFC_EPERM, 4)
        self.assertEqual(OFPFMFC_BAD_TIMEOUT, 5)
        self.assertEqual(OFPFMFC_BAD_COMMAND, 6)
        self.assertEqual(OFPFMFC_BAD_FLAGS, 7)

    def test_enum_ofp_group_mod_failed_code(self):
        self.assertEqual(OFPGMFC_GROUP_EXISTS, 0)
        self.assertEqual(OFPGMFC_INVALID_GROUP, 1)
        self.assertEqual(OFPGMFC_WEIGHT_UNSUPPORTED, 2)
        self.assertEqual(OFPGMFC_OUT_OF_GROUPS, 3)
        self.assertEqual(OFPGMFC_OUT_OF_BUCKETS, 4)
        self.assertEqual(OFPGMFC_CHAINING_UNSUPPORTED, 5)
        self.assertEqual(OFPGMFC_WATCH_UNSUPPORTED, 6)
        self.assertEqual(OFPGMFC_LOOP, 7)
        self.assertEqual(OFPGMFC_UNKNOWN_GROUP, 8)
        self.assertEqual(OFPGMFC_CHAINED_GROUP, 9)
        self.assertEqual(OFPGMFC_BAD_TYPE, 10)
        self.assertEqual(OFPGMFC_BAD_COMMAND, 11)
        self.assertEqual(OFPGMFC_BAD_BUCKET, 12)
        self.assertEqual(OFPGMFC_BAD_WATCH, 13)
        self.assertEqual(OFPGMFC_EPERM, 14)

    def test_enum_ofp_port_mod_failed_code(self):
        self.assertEqual(OFPPMFC_BAD_PORT, 0)
        self.assertEqual(OFPPMFC_BAD_HW_ADDR, 1)
        self.assertEqual(OFPPMFC_BAD_CONFIG, 2)
        self.assertEqual(OFPPMFC_BAD_ADVERTISE, 3)
        self.assertEqual(OFPPMFC_EPERM, 4)

    def test_enum_ofp_table_mod_failed_code(self):
        self.assertEqual(OFPTMFC_BAD_TABLE, 0)
        self.assertEqual(OFPTMFC_BAD_CONFIG, 1)
        self.assertEqual(OFPTMFC_EPERM, 2)

    def test_enum_ofp_queue_op_failed_code(self):
        self.assertEqual(OFPQOFC_BAD_PORT, 0)
        self.assertEqual(OFPQOFC_BAD_QUEUE, 1)
        self.assertEqual(OFPQOFC_EPERM, 2)

    def test_enum_ofp_switch_config_failed_code(self):
        self.assertEqual(OFPSCFC_BAD_FLAGS, 0)
        self.assertEqual(OFPSCFC_BAD_LEN, 1)
        self.assertEqual(OFPSCFC_EPERM, 2)

    def test_enum_ofp_role_request_failed_code(self):
        self.assertEqual(OFPRRFC_STALE, 0)
        self.assertEqual(OFPRRFC_UNSUP, 1)
        self.assertEqual(OFPRRFC_BAD_ROLE, 2)

    def test_struct_ofp_error_experimenter_msg(self):
        self.assertEqual(OFP_ERROR_EXPERIMENTER_MSG_PACK_STR, '!HHI')
        self.assertEqual(OFP_ERROR_EXPERIMENTER_MSG_SIZE, 16)

    def test_struct_ofp_experimenter_header(self):
        self.assertEqual(OFP_EXPERIMENTER_HEADER_PACK_STR, '!II')
        self.assertEqual(OFP_EXPERIMENTER_HEADER_SIZE, 16)

    # OXM is interpreted as a 32-bit word in network byte order.
    # - oxm_class   17-bit to 32-bit (OFPXMC_*).
    # - oxm_field   10-bit to 16-bit (OFPXMT_OFB_*).
    # - oxm_hasmask  9-bit           (Set if OXM include a bitmask).
    # - oxm_length   1-bit to 8-bit  (Lenght of OXM payload).
    def _test_OXM(self, value, class_, field, hasmask, length):
        virfy = (class_ << 16) | (field << 9) | (hasmask << 8) | length
        self.assertEqual(value >> 32, 0)
        self.assertEqual(value, virfy)

    def _test_OXM_basic(self, value, field, hasmask, length):
        self._test_OXM(value, OFPXMC_OPENFLOW_BASIC, field, hasmask, length)

    def test_OXM_basic(self):
        self._test_OXM_basic(OXM_OF_IN_PORT, OFPXMT_OFB_IN_PORT, 0, 4)
        self._test_OXM_basic(OXM_OF_IN_PHY_PORT, OFPXMT_OFB_IN_PHY_PORT, 0, 4)
        self._test_OXM_basic(OXM_OF_METADATA, OFPXMT_OFB_METADATA, 0, 8)
        self._test_OXM_basic(OXM_OF_METADATA_W, OFPXMT_OFB_METADATA, 1, 16)
        self._test_OXM_basic(OXM_OF_ETH_DST, OFPXMT_OFB_ETH_DST, 0, 6)
        self._test_OXM_basic(OXM_OF_ETH_DST_W, OFPXMT_OFB_ETH_DST, 1, 12)
        self._test_OXM_basic(OXM_OF_ETH_SRC, OFPXMT_OFB_ETH_SRC, 0, 6)
        self._test_OXM_basic(OXM_OF_ETH_SRC_W, OFPXMT_OFB_ETH_SRC, 1, 12)
        self._test_OXM_basic(OXM_OF_ETH_TYPE, OFPXMT_OFB_ETH_TYPE, 0, 2)
        self._test_OXM_basic(OXM_OF_VLAN_VID, OFPXMT_OFB_VLAN_VID, 0, 2)
        self._test_OXM_basic(OXM_OF_VLAN_VID_W, OFPXMT_OFB_VLAN_VID, 1, 4)
        self._test_OXM_basic(OXM_OF_VLAN_PCP, OFPXMT_OFB_VLAN_PCP, 0, 1)
        self._test_OXM_basic(OXM_OF_IP_DSCP, OFPXMT_OFB_IP_DSCP, 0, 1)
        self._test_OXM_basic(OXM_OF_IP_ECN, OFPXMT_OFB_IP_ECN, 0, 1)
        self._test_OXM_basic(OXM_OF_IP_PROTO, OFPXMT_OFB_IP_PROTO, 0, 1)
        self._test_OXM_basic(OXM_OF_IPV4_SRC, OFPXMT_OFB_IPV4_SRC, 0, 4)
        self._test_OXM_basic(OXM_OF_IPV4_SRC_W, OFPXMT_OFB_IPV4_SRC, 1, 8)
        self._test_OXM_basic(OXM_OF_IPV4_DST, OFPXMT_OFB_IPV4_DST, 0, 4)
        self._test_OXM_basic(OXM_OF_IPV4_DST_W, OFPXMT_OFB_IPV4_DST, 1, 8)
        self._test_OXM_basic(OXM_OF_TCP_SRC, OFPXMT_OFB_TCP_SRC, 0, 2)
        self._test_OXM_basic(OXM_OF_TCP_DST, OFPXMT_OFB_TCP_DST, 0, 2)
        self._test_OXM_basic(OXM_OF_UDP_SRC, OFPXMT_OFB_UDP_SRC, 0, 2)
        self._test_OXM_basic(OXM_OF_UDP_DST, OFPXMT_OFB_UDP_DST, 0, 2)
        self._test_OXM_basic(OXM_OF_SCTP_SRC, OFPXMT_OFB_SCTP_SRC, 0, 2)
        self._test_OXM_basic(OXM_OF_SCTP_DST, OFPXMT_OFB_SCTP_DST, 0, 2)
        self._test_OXM_basic(OXM_OF_ICMPV4_TYPE, OFPXMT_OFB_ICMPV4_TYPE, 0, 1)
        self._test_OXM_basic(OXM_OF_ICMPV4_CODE, OFPXMT_OFB_ICMPV4_CODE, 0, 1)
        self._test_OXM_basic(OXM_OF_ARP_OP, OFPXMT_OFB_ARP_OP, 0, 2)
        self._test_OXM_basic(OXM_OF_ARP_SPA, OFPXMT_OFB_ARP_SPA, 0, 4)
        self._test_OXM_basic(OXM_OF_ARP_SPA_W, OFPXMT_OFB_ARP_SPA, 1, 8)
        self._test_OXM_basic(OXM_OF_ARP_TPA, OFPXMT_OFB_ARP_TPA, 0, 4)
        self._test_OXM_basic(OXM_OF_ARP_TPA_W, OFPXMT_OFB_ARP_TPA, 1, 8)
        self._test_OXM_basic(OXM_OF_ARP_SHA, OFPXMT_OFB_ARP_SHA, 0, 6)
        self._test_OXM_basic(OXM_OF_ARP_SHA_W, OFPXMT_OFB_ARP_SHA, 1, 12)
        self._test_OXM_basic(OXM_OF_ARP_THA, OFPXMT_OFB_ARP_THA, 0, 6)
        self._test_OXM_basic(OXM_OF_ARP_THA_W, OFPXMT_OFB_ARP_THA, 1, 12)
        self._test_OXM_basic(OXM_OF_IPV6_SRC, OFPXMT_OFB_IPV6_SRC, 0, 16)
        self._test_OXM_basic(OXM_OF_IPV6_SRC_W, OFPXMT_OFB_IPV6_SRC, 1, 32)
        self._test_OXM_basic(OXM_OF_IPV6_DST, OFPXMT_OFB_IPV6_DST, 0, 16)
        self._test_OXM_basic(OXM_OF_IPV6_DST_W, OFPXMT_OFB_IPV6_DST, 1, 32)
        self._test_OXM_basic(OXM_OF_IPV6_FLABEL, OFPXMT_OFB_IPV6_FLABEL, 0, 4)
        self._test_OXM_basic(OXM_OF_IPV6_FLABEL_W,
                             OFPXMT_OFB_IPV6_FLABEL, 1, 8)
        self._test_OXM_basic(OXM_OF_ICMPV6_TYPE, OFPXMT_OFB_ICMPV6_TYPE, 0, 1)
        self._test_OXM_basic(OXM_OF_ICMPV6_CODE, OFPXMT_OFB_ICMPV6_CODE, 0, 1)
        self._test_OXM_basic(OXM_OF_IPV6_ND_TARGET,
                             OFPXMT_OFB_IPV6_ND_TARGET, 0, 16)
        self._test_OXM_basic(OXM_OF_IPV6_ND_SLL, OFPXMT_OFB_IPV6_ND_SLL, 0, 6)
        self._test_OXM_basic(OXM_OF_IPV6_ND_TLL, OFPXMT_OFB_IPV6_ND_TLL, 0, 6)
        self._test_OXM_basic(OXM_OF_MPLS_LABEL, OFPXMT_OFB_MPLS_LABEL, 0, 4)
        self._test_OXM_basic(OXM_OF_MPLS_TC, OFPXMT_OFB_MPLS_TC, 0, 1)

    def test_define_constants(self):
        self.assertEqual(OFP_VERSION, 0x03)
        self.assertEqual(OFP_TCP_PORT, 6633)
        self.assertEqual(MAX_XID, 0xffffffff)
