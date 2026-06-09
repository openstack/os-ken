# Copyright (C) 2025 Red Hat, Inc.
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
from unittest import mock

from os_ken.app.ofctl import event
from os_ken.app.ofctl import exception
from os_ken.app.ofctl import service


class _FakeBarrierRequest:
    def __init__(self, *args, **kwargs):
        self.xid = None


class _FakeMsg:
    pass


class TestOfctlService(unittest.TestCase):

    def setUp(self):
        with mock.patch('os_ken.base.app_manager.OSKenApp.__init__',
                        return_value=None):
            self.service = service.OfctlService()
        self.service.name = 'ofctl_service'
        self.service._switches = {}
        self.service._observing_events = {}
        self.service.logger = mock.MagicMock()
        self.service.reply_to_request = mock.MagicMock()

        self.datapath = mock.MagicMock()
        self.datapath.id = 1

        self.datapath.ofproto_parser = mock.MagicMock()
        self.datapath.ofproto_parser.OFPBarrierRequest = _FakeBarrierRequest

        self._xid_counter = 0

        def _set_xid(msg):
            self._xid_counter += 1
            msg.xid = self._xid_counter

        self.datapath.set_xid = _set_xid

        self.si = service._SwitchInfo(datapath=self.datapath)
        self.service._switches[self.datapath.id] = self.si

    def _make_msg(self):
        msg = mock.MagicMock(spec=_FakeMsg)
        msg.datapath = self.datapath
        return msg

    def test_handle_send_msg_serialize_exception(self):
        """send_msg raising during serialize must cancel, not hang."""
        msg = self._make_msg()
        self.datapath.send_msg.side_effect = TypeError(
            "object of type 'NoneType' has no len()")

        req = event.SendMsgRequest(msg=msg, reply_cls=None, reply_multi=False)
        self.service._handle_send_msg(req)

        self.service.reply_to_request.assert_called_once()
        call_args = self.service.reply_to_request.call_args
        reply = call_args[0][1]
        self.assertIsInstance(reply, event.Reply)
        self.assertIsInstance(reply.exception, exception.InvalidMessage)

        self.assertEqual({}, self.si.barriers)
        self.assertEqual({}, self.si.xids)
        self.assertEqual({}, self.si.results)

    def test_handle_send_msg_send_returns_false(self):
        """send_msg returning False must cancel with InvalidDatapath."""
        msg = self._make_msg()
        self.datapath.send_msg.return_value = False

        req = event.SendMsgRequest(msg=msg, reply_cls=None, reply_multi=False)
        self.service._handle_send_msg(req)

        self.service.reply_to_request.assert_called_once()
        call_args = self.service.reply_to_request.call_args
        reply = call_args[0][1]
        self.assertIsInstance(reply, event.Reply)
        self.assertIsInstance(reply.exception, exception.InvalidDatapath)

        self.assertEqual({}, self.si.barriers)
        self.assertEqual({}, self.si.xids)
        self.assertEqual({}, self.si.results)

    def test_handle_send_msg_unknown_dpid(self):
        """Request for unknown dpid must reply with InvalidDatapath."""
        self.service._switches.clear()

        msg = self._make_msg()
        req = event.SendMsgRequest(msg=msg, reply_cls=None, reply_multi=False)
        self.service._handle_send_msg(req)

        self.service.reply_to_request.assert_called_once()
        call_args = self.service.reply_to_request.call_args
        reply = call_args[0][1]
        self.assertIsInstance(reply, event.Reply)
        self.assertIsInstance(reply.exception, exception.InvalidDatapath)


class TestOfctlServiceHandleSendMsg(unittest.TestCase):
    """Test that _handle_send_msg rejects messages with stale datapaths."""

    def setUp(self):
        self.svc = service.OfctlService.__new__(service.OfctlService)
        self.svc.name = 'ofctl_service'
        self.svc._switches = {}
        self.svc._observing_events = {}
        self.svc.reply_to_request = mock.Mock()
        self.svc.logger = mock.Mock()

    def _make_datapath(self, dpid):
        dp = mock.Mock()
        dp.id = dpid

        dp.ofproto_parser.OFPBarrierRequest = _FakeBarrierRequest
        dp.send_msg = mock.Mock(return_value=True)
        dp.set_xid = mock.Mock(side_effect=lambda m: setattr(m, 'xid', 1))
        return dp

    def _make_request(self, datapath, reply_cls=None):
        msg = mock.Mock()
        msg.datapath = datapath
        msg.xid = None
        req = event.SendMsgRequest(msg=msg, reply_cls=reply_cls,
                                   reply_multi=False)
        return req

    def test_handle_send_msg_unknown_dpid(self):
        """Request for unknown dpid is rejected with InvalidDatapath."""
        dp = self._make_datapath(1)
        req = self._make_request(dp)

        self.svc._handle_send_msg(req)

        self.svc.reply_to_request.assert_called_once()
        reply = self.svc.reply_to_request.call_args[0][1]
        self.assertIsInstance(reply.exception, exception.InvalidDatapath)

    def test_handle_send_msg_stale_datapath_rejected(self):
        """Request with stale datapath is rejected when switch reconnected."""
        old_dp = self._make_datapath(1)
        new_dp = self._make_datapath(1)

        # Switch reconnected: _switches has new datapath
        si = service._SwitchInfo(datapath=new_dp)
        self.svc._switches[1] = si

        # Request carries the OLD datapath
        req = self._make_request(old_dp)

        self.svc._handle_send_msg(req)

        # Should be rejected
        self.svc.reply_to_request.assert_called_once()
        reply = self.svc.reply_to_request.call_args[0][1]
        self.assertIsInstance(reply.exception, exception.InvalidDatapath)
        # Should NOT have sent anything on the old datapath
        old_dp.send_msg.assert_not_called()

    def test_handle_send_msg_current_datapath_accepted(self):
        """Request with current datapath is processed normally."""
        dp = self._make_datapath(1)
        dp.ofproto_parser.OFPBarrierRequest.return_value = mock.Mock()

        si = service._SwitchInfo(datapath=dp)
        self.svc._switches[1] = si

        req = self._make_request(dp)

        self.svc._handle_send_msg(req)

        # Should NOT have been rejected
        self.svc.reply_to_request.assert_not_called()
        # Should have sent the message and barrier
        self.assertEqual(2, dp.send_msg.call_count)
