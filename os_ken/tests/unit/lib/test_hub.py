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

import unittest
from unittest import mock
import socket
import threading
import time

import os_ken.lib.hub


class _Exception(Exception):
    pass


class TestStreamServer(unittest.TestCase):

    @mock.patch("os_ken.lib.ip.valid_ipv6", return_value=False)
    @mock.patch("os_ken.lib.hub.listen")
    def test_ipv4_server(self, mock_listen, mock_valid_ipv6):
        mock_listen.return_value = mock.Mock()
        handle = mock.Mock()

        server = os_ken.lib.hub.StreamServer(
            ("127.0.0.1", 1234), handle=handle)

        mock_listen.assert_called_once_with(("127.0.0.1", 1234))
        self.assertEqual(server.handle, handle)

    @mock.patch("os_ken.lib.ip.valid_ipv6", return_value=True)
    @mock.patch("os_ken.lib.hub.listen")
    def test_ipv6_server(self, mock_listen, mock_valid_ipv6):
        mock_listen.return_value = mock.Mock()
        handle = mock.Mock()

        server = os_ken.lib.hub.StreamServer(("::1", 1234), handle=handle)

        mock_listen.assert_called_once_with(("::1", 1234), family=socket.AF_INET6)
        self.assertEqual(server.handle, handle)

    @mock.patch("os.path.isdir", return_value=True)
    @mock.patch("os_ken.lib.hub.listen")
    def test_unix_socket_server(self, mock_listen, mock_isdir):
        mock_listen.return_value = mock.Mock()
        handle = mock.Mock()

        server = os_ken.lib.hub.StreamServer(
            ("/tmp/test_socket",), handle=handle)

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

        server = os_ken.lib.hub.StreamServer(
            ("127.0.0.1", 1234), handle=handle, **ssl_args)

        ssl_ctx.load_cert_chain.assert_called_once_with("cert.pem", "key.pem")
        ssl_ctx.load_verify_locations.assert_called_once_with("ca.pem")
        self.assertEqual(ssl_ctx.verify_mode, mock.sentinel.cert_reqs)

        wrapped_handle = server.handle
        sock = mock.Mock()
        addr = ("127.0.0.1", 5678)
        wrapped_handle(sock, addr)

        ssl_ctx.wrap_socket.assert_called_once_with(sock, server_side=True)
        handle.assert_called_once_with(ssl_ctx.wrap_socket(), addr)


class TestStreamClient(unittest.TestCase):

    def test_connection(self):
        addr = ("127.0.0.1", 1234)
        timeout = 5
        with mock.patch("socket.create_connection") as mock_create_conn:
            mock_create_conn.return_value = mock.Mock()
            client = os_ken.lib.hub.StreamClient(addr, timeout=timeout)
            connection = client.connect()

            self.assertIsNotNone(connection)
            mock_create_conn.assert_called_once_with(addr, timeout=timeout)


class TestEvent(unittest.TestCase):

    def setUp(self):
        self.hub = os_ken.lib.hub
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

    def test_set_between_check_and_wait(self):
        # set() lands right after the waiter tests the flag and before it
        # starts waiting; the waiter must still be woken.
        event = self.event
        real_set = event.set

        class Flag(object):
            raced = False

            def __get__(self, obj, objtype=None):
                value = obj.__dict__['_flag']
                if not value and not Flag.raced:
                    Flag.raced = True
                    real_set()
                return value

            def __set__(self, obj, value):
                obj.__dict__['_flag'] = value

        class RacyEvent(type(event)):
            _cond = Flag()

        event.__class__ = RacyEvent
        event._cond = False

        done = []
        thread = threading.Thread(target=lambda: done.append(event.wait()),
                                  daemon=True)
        thread.start()
        thread.join(3)
        self.assertEqual([True], done)

    def test_timeout_context(self):
        with os_ken.lib.hub.Timeout(seconds=10):
            time.sleep(1)

    def test_timeout_context_exception(self):
        try:
            with os_ken.lib.hub.Timeout(seconds=1,
                                        exception=_Exception):
                time.sleep(2)
            self.fail('A "_Exception" should have been raised')
        except _Exception:
            pass


class TestThreadManagement(unittest.TestCase):

    def setUp(self):
        self.hub = os_ken.lib.hub

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

    # NOTE: wait() does not raise the exception that ended the thread.
    @unittest.expectedFailure
    def test_spawn_raise_error_true(self):
        def failing_task():
            raise Exception()

        thread = self.hub.spawn(failing_task, raise_error=True)
        self.assertRaises(Exception, thread.wait)

    def test_spawn_task_exit(self):
        def exit_task():
            raise os_ken.lib.hub.TaskExit()

        try:
            self.hub.spawn(exit_task, raise_error=True)
        except Exception:
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


class TestListen(unittest.TestCase):

    def setUp(self):
        self.hub = os_ken.lib.hub

        self.patcher = mock.patch('socket.socket')
        self.mock_socket = self.patcher.start()

        self.sock = mock.MagicMock()
        self.mock_socket.return_value = self.sock

    def tearDown(self):
        self.patcher.stop()

    def test_default_socket_creation(self):
        addr = ('127.0.0.1', 8080)
        sock = self.hub.listen(addr)

        self.mock_socket.assert_called_once_with(
            socket.AF_INET, socket.SOCK_STREAM)

        self.sock.setsockopt.assert_has_calls([
            mock.call(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1),
        ])

        self.sock.bind.assert_called_once_with(addr)
        self.sock.listen.assert_called_once_with(50)

        self.assertEqual(self.sock, sock)

    def test_socket_with_ipv6(self):
        addr = ('::1', 8080)
        sock = self.hub.listen(addr, family=socket.AF_INET6)

        self.mock_socket.assert_called_once_with(
            socket.AF_INET6, socket.SOCK_STREAM)

        self.sock.setsockopt.assert_has_calls([
            mock.call(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1),
        ])

        self.sock.bind.assert_called_once_with(addr)
        self.sock.listen.assert_called_once_with(50)

        self.assertEqual(self.sock, sock)
