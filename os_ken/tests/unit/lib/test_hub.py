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

import os
import unittest
from unittest import mock
import importlib
import socket
import threading
import time

import os_ken.lib.hub


class TestHubType(unittest.TestCase):

    @mock.patch.dict(os.environ, {"OSKEN_HUB_TYPE": "eventlet"})
    def test_eventlet_mode(self):
        hub = importlib.reload(os_ken.lib.hub)
        self.assertEqual("eventlet", hub.HUB_TYPE)

    @mock.patch.dict(os.environ, {"OSKEN_HUB_TYPE": "native"})
    def test_native_mode(self):
        hub = importlib.reload(os_ken.lib.hub)
        self.assertEqual("native", hub.HUB_TYPE)

    @mock.patch.dict(os.environ, {"OSKEN_HUB_TYPE": "other"})
    def test_other_mode(self):
        self.assertRaises(NotImplementedError, importlib.reload, os_ken.lib.hub)


class TestStreamServerEventlet(unittest.TestCase):
    @mock.patch.dict(os.environ, {"OSKEN_HUB_TYPE": "eventlet"})
    def setUp(self):
        self.hub = importlib.reload(os_ken.lib.hub)

    @mock.patch("os_ken.lib.ip.valid_ipv6", return_value=False)
    @mock.patch("os_ken.lib.hub.listen")
    def test_ipv4_server(self, mock_listen, mock_valid_ipv6):
        mock_listen.return_value = mock.Mock()
        handle = mock.Mock()

        server = self.hub.StreamServer(("127.0.0.1", 1234), handle=handle)

        mock_listen.assert_called_once_with(("127.0.0.1", 1234))
        self.assertEqual(server.handle, handle)

    @mock.patch("os_ken.lib.ip.valid_ipv6", return_value=True)
    @mock.patch("os_ken.lib.hub.listen")
    def test_ipv6_server(self, mock_listen, mock_valid_ipv6):
        mock_listen.return_value = mock.Mock()
        handle = mock.Mock()

        server = self.hub.StreamServer(("::1", 1234), handle=handle)

        mock_listen.assert_called_once_with(("::1", 1234), family=socket.AF_INET6)
        self.assertEqual(server.handle, handle)

    @mock.patch("os.path.isdir", return_value=True)
    @mock.patch("os_ken.lib.hub.listen")
    def test_unix_socket_server(self, mock_listen, mock_isdir):
        mock_listen.return_value = mock.Mock()
        handle = mock.Mock()

        server = self.hub.StreamServer(("/tmp/test_socket",), handle=handle)

        mock_listen.assert_called_once_with("/tmp/test_socket", family=socket.AF_UNIX)
        self.assertEqual(server.handle, handle)

    @mock.patch("os_ken.lib.ip.valid_ipv6", return_value=False)
    @mock.patch("os_ken.lib.hub.listen")
    def test_ssl_server(self, mock_listen, mock_valid_ipv6):
        mock_listen.return_value = mock.Mock()
        handle = mock.Mock()

        ssl_ctx = mock.Mock()
        ssl_args = {
            "ssl_ctx": ssl_ctx,
            "certfile": "cert.pem",
            "keyfile": "key.pem",
            "cert_reqs": mock.sentinel.cert_reqs,
            "ca_certs": "ca.pem",
        }

        server = self.hub.StreamServer(("127.0.0.1", 1234), handle=handle, **ssl_args)

        ssl_ctx.load_cert_chain.assert_called_once_with("cert.pem", "key.pem")
        ssl_ctx.load_verify_locations.assert_called_once_with("ca.pem")
        self.assertEqual(ssl_ctx.verify_mode, mock.sentinel.cert_reqs)

        wrapped_handle = server.handle
        sock = mock.Mock()
        addr = ("127.0.0.1", 5678)
        wrapped_handle(sock, addr)

        ssl_ctx.wrap_socket.assert_called_once_with(sock, server_side=True)
        handle.assert_called_once_with(ssl_ctx.wrap_socket(), addr)


class TestStreamServerNative(TestStreamServerEventlet):

    @mock.patch.dict(os.environ, {"OSKEN_HUB_TYPE": "native"})
    def setUp(self):
        self.hub = importlib.reload(os_ken.lib.hub)


class TestStreamClientEventlet(unittest.TestCase):

    @mock.patch.dict(os.environ, {"OSKEN_HUB_TYPE": "eventlet"})
    def setUp(self):
        self.hub = importlib.reload(os_ken.lib.hub)

    def test_connection(self):
        addr = ("127.0.0.1", 1234)
        timeout = 5
        with mock.patch("socket.create_connection") as mock_create_conn:
            mock_create_conn.return_value = mock.Mock()
            client = self.hub.StreamClient(addr, timeout=timeout)
            connection = client.connect()

            self.assertIsNotNone(connection)
            mock_create_conn.assert_called_once_with(addr, timeout=timeout)


class TestStreamClientNative(TestStreamClientEventlet):

    @mock.patch.dict(os.environ, {"OSKEN_HUB_TYPE": "native"})
    def setUp(self):
        self.hub = importlib.reload(os_ken.lib.hub)


class TestEventEventlet(unittest.TestCase):

    @mock.patch.dict(os.environ, {"OSKEN_HUB_TYPE": "eventlet"})
    def setUp(self):
        self.hub = importlib.reload(os_ken.lib.hub)
        self.event = self.hub.Event()

    def test_initial_state(self):
        self.assertFalse(self.event.is_set())

    def test_set_event(self):
        self.event.set()
        self.assertTrue(self.event.is_set())

    def test_clear_event(self):
        self.event.set()
        self.event.clear()
        self.assertFalse(self.event.is_set())

    def test_wait_success(self):
        def set_event_after_delay():
            threading.Timer(0.1, self.event.set).start()

        set_event_after_delay()
        result = self.event.wait(timeout=1)
        self.assertTrue(result)

    def test_wait_timeout(self):
        result = self.event.wait(timeout=1)
        self.assertFalse(result)


class TestEventNative(TestEventEventlet):

    @mock.patch.dict(os.environ, {"OSKEN_HUB_TYPE": "native"})
    def setUp(self):
        self.hub = importlib.reload(os_ken.lib.hub)
        self.event = self.hub.Event()


class TestThreadManagementEventlet(unittest.TestCase):

    @mock.patch.dict(os.environ, {"OSKEN_HUB_TYPE": "eventlet"})
    def setUp(self):
        self.hub = importlib.reload(os_ken.lib.hub)

    def test_spawn(self):
        result = []

        def task():
            result.append(mock.sentinel.value)

        thread = self.hub.spawn(task)
        thread.wait()
        self.assertEqual([mock.sentinel.value], result)

    def test_spawn_after(self):
        result = []

        def task():
            result.append(mock.sentinel.value)

        start_time = time.time()
        thread = self.hub.spawn_after(1, task)
        thread.wait()

        self.assertGreaterEqual(time.time() - start_time, 1)
        self.assertEqual([mock.sentinel.value], result)

    @mock.patch('os_ken.lib.hub.LOG.error')
    def test_spawn_raise_error_false(self, mock_log_error):
        def failing_task():
            raise Exception()

        thread = self.hub.spawn(failing_task, raise_error=False)
        thread.wait()
        self.assertIn("exception", mock_log_error.call_args[0][0])

    def test_spawn_raise_error_true(self):
        def failing_task():
            raise Exception()

        thread = self.hub.spawn(failing_task, raise_error=True)
        self.assertRaises(Exception, thread.wait)

    def test_spawn_task_exit(self):
        def exit_task():
            raise os_ken.lib.hub.TaskExit()

        try:
            thread = self.hub.spawn(exit_task, raise_error=True)
        except:
            self.fail("Should not be here")

    def test_joinall(self):
        result = []

        def task1():
            result.append(mock.sentinel.value1)

        def task2():
            result.append(mock.sentinel.value2)

        thread1 = self.hub.spawn(task1)
        thread2 = self.hub.spawn_after(1, task2)
        self.hub.joinall([thread1, thread2])

        self.assertEqual([mock.sentinel.value1,
                          mock.sentinel.value2], result)

    def test_defined(self):
        self.assertTrue(callable(self.hub.getcurrent))
        self.assertTrue(callable(self.hub.sleep))
        self.assertTrue(callable(self.hub.Queue))
        self.assertTrue(callable(self.hub.QueueEmpty))
        self.assertTrue(callable(self.hub.Semaphore))
        self.assertTrue(callable(self.hub.BoundedSemaphore))
        self.assertTrue(callable(self.hub.TaskExit))


class TestThreadManagementNative(unittest.TestCase):

    @mock.patch.dict(os.environ, {"OSKEN_HUB_TYPE": "native"})
    def setUp(self):
        self.hub = importlib.reload(os_ken.lib.hub)
