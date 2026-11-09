#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import importlib
import os
import threading
import unittest
from unittest import mock

from os_ken.base import app_manager
from os_ken.controller import event
import os_ken.lib.hub


class _Event(event.EventBase):
    pass


class _Exception(Exception):
    pass


class TestEventLoopNative(unittest.TestCase):

    @mock.patch.dict(os.environ, {"OSKEN_HUB_TYPE": "native"})
    def setUp(self):
        importlib.reload(os_ken.lib.hub)
        self.handled = []
        self.second_handled = threading.Event()

        def handler(ev):
            self.handled.append(ev)
            if len(self.handled) == 1:
                raise _Exception()
            self.second_handled.set()

        self.app = app_manager.OSKenApp()
        self.app.register_handler(_Event, handler)
        self.app.start()
        self.addCleanup(self.app.stop)

    @mock.patch.object(app_manager.LOG, 'exception')
    def test_handler_exception_keeps_event_loop(self, mock_log_exception):
        self.app._send_event(_Event(), None)
        self.app._send_event(_Event(), None)

        self.assertTrue(self.second_handled.wait(timeout=5),
                        "The event loop ended on the handler exception")
        mock_log_exception.assert_called_once()
