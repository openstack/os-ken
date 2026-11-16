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

import logging
import os
import queue
import socket
import ssl
import sys
import threading
import time
import traceback

from os_ken.lib import ip


LOG = logging.getLogger('os_ken.lib.hub')


getcurrent = threading.current_thread
sleep = time.sleep
Queue = queue.Queue
QueueEmpty = queue.Empty
Semaphore = threading.Semaphore
BoundedSemaphore = threading.BoundedSemaphore


class StreamServer(object):
    def __init__(self, listen_info, handle=None, backlog=None,
                 spawn='default', **ssl_args):
        assert backlog is None
        assert spawn == 'default'

        if ip.valid_ipv6(listen_info[0]):
            self.server = listen(listen_info, family=socket.AF_INET6)
        elif os.path.isdir(os.path.dirname(listen_info[0])):
            # Case for Unix domain socket
            self.server = listen(listen_info[0], family=socket.AF_UNIX)
        else:
            self.server = listen(listen_info)

        if ssl_args:
            ssl_args.setdefault('server_side', True)
            if 'ssl_ctx' not in ssl_args:
                raise RuntimeError("no SSLContext ssl_ctx in ssl_args")
            ctx = ssl_args.pop('ssl_ctx')
            ctx.load_cert_chain(ssl_args.pop('certfile'),
                                ssl_args.pop('keyfile'))
            if 'cert_reqs' in ssl_args:
                ctx.verify_mode = ssl_args.pop('cert_reqs')
            if 'ca_certs' in ssl_args:
                ctx.load_verify_locations(ssl_args.pop('ca_certs'))

            def wrap_and_handle_ctx(sock, addr):
                handle(ctx.wrap_socket(sock, **ssl_args), addr)

            self.handle = wrap_and_handle_ctx
        else:
            self.handle = handle

    def serve_forever(self):
        while True:
            sock, addr = self.server.accept()
            spawn(self.handle, sock, addr)


class StreamClient(object):
    def __init__(self, addr, timeout=None, **ssl_args):
        assert ip.valid_ipv4(addr[0]) or ip.valid_ipv6(addr[0])
        self.addr = addr
        self.timeout = timeout
        self.ssl_args = ssl_args
        self._is_active = True

    def connect(self):
        try:
            if self.timeout is not None:
                client = socket.create_connection(self.addr,
                                                  timeout=self.timeout)
            else:
                client = socket.create_connection(self.addr)
        except socket.error:
            return None

        if self.ssl_args:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.load_cert_chain(self.ssl_args.pop('certfile'),
                                self.ssl_args.pop('keyfile'))
            if 'cert_reqs' in self.ssl_args:
                ctx.verify_mode = self.ssl_args.pop('cert_reqs')
            if 'ca_certs' in self.ssl_args:
                ctx.load_verify_location(self.ssl_args.pop('ca_certs'))
            client = ctx.wrap_socket(client, **self.ssl_args)

        return client

    def connect_loop(self, handle, interval):
        while self._is_active:
            sock = self.connect()
            if sock:
                handle(sock, self.addr)
            sleep(interval)

    def stop(self):
        self._is_active = False


class Event(object):
    def __init__(self):
        self._ev = HubEvent()
        self._cond = False

    def _wait(self, timeout=None):
        while True:
            # Grab the current event before testing the flag: set() flips
            # the flag first and only then wakes and replaces the event, so
            # a concurrent set() can no longer leave us on a fresh event
            # that nobody will ever signal.
            ev = self._ev
            if self._cond:
                return
            ev.wait()

    def _broadcast(self):
        self._ev.send()
        # Re-create the underlying event so that multiple set() calls
        # can be issued, mirroring the semantics of a manual-reset
        # event that can be broadcast more than once.
        self._ev = HubEvent()

    def is_set(self):
        return self._cond

    def set(self):
        self._cond = True
        self._broadcast()

    def clear(self):
        self._cond = False

    def wait(self, timeout=None):
        if timeout is None:
            self._wait()
        else:
            try:
                with Timeout(timeout):
                    self._wait()
            except Timeout:
                pass

        return self._cond


class HubThread(threading.Thread):
    def __init__(self, target, args=(), kwargs=None):
        self.raise_error = kwargs.pop('raise_error', False)
        super().__init__(target=target, args=args, kwargs=kwargs)

    def wait(self, timeout=None):
        self.join(timeout)

    def run(self):
        try:
            super().run()
        except TaskExit:
            pass
        except BaseException as e:
            if self.raise_error:
                raise e
            else:
                LOG.error('HubThread uncaught exception: %s',
                          traceback.format_exc())

    def cancel(self):
        # NOTE(sahid): There is no safe and reliable way to force
        # stopping a thread in Python.  It is recommended to implement
        # a proper termination mechanism using a flag or an event.
        pass


def spawn(func, *args, **kwargs):
    thread = HubThread(func, args, kwargs)
    thread.start()
    return thread


class HubTimer(threading.Timer):
    def wait(self, timeout=None):
        self.join(timeout)


def spawn_after(seconds, func, *args, **kwargs):
    kwargs.pop('raise_error', False)
    timer = HubTimer(seconds, func, args=args, kwargs=kwargs)
    timer.daemon = True
    timer.start()
    return timer


def joinall(threads):
    for thread in threads:
        thread.join()


def kill(thread):
    thread.cancel()


class TaskExit(Exception):
    """Raised to end a thread normally.

    Not Exception itself: the event loop would take any exception of
    a handler for a normal exit, and end without logging it.
    """


class HubEvent(threading.Event):
    def send(self):
        self.set()


class Timeout(BaseException):
    """A context manager that raises an exception after a timeout."""

    def __init__(self, seconds=None, exception=None):
        self._event = threading.Event()
        self._event.set()
        self._queue = queue.Queue()

        self.seconds = seconds
        self.exception = exception

        self.timer = None
        self._timed_out = False

    def start(self):
        if self.seconds is None:
            # "fake" timeout (never expires)
            self.timer = None
        else:
            self.timer = threading.Timer(self.seconds, self._on_timeout)
            self.timer.start()
        return self

    def __enter__(self):
        if self.timer is None:
            self.start()
        return self

    def __exit__(self, typ, value, tb):
        self.cancel()
        # Check if timeout occurred during execution
        if self._timed_out:
            try:
                exc = self._queue.get_nowait()
                # Only raise if we're not already handling an exception
                # and the exception type is not False (which means
                # suppress)
                if self.exception is not False:
                    raise exc
            except queue.Empty:
                pass

    def _on_timeout(self):
        self._timed_out = True
        if self.exception is None or isinstance(self.exception, bool):
            # timeout that raises self
            exc = self
        else:
            exc = self.exception
        self._queue.put(exc)
        self._event.set()

    def cancel(self):
        if self.timer:
            self.timer.cancel()
        self._event.set()


def listen(addr, family=socket.AF_INET, backlog=50, reuse_addr=True,
           reuse_port=None):
    sock = socket.socket(family, socket.SOCK_STREAM)
    if reuse_addr and sys.platform[:3] != 'win':
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    elif reuse_port is None:
        reuse_port = True
        if reuse_port and hasattr(socket, 'SO_REUSEPORT'):
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except Exception:
                # Not supported by the platform
                pass
    sock.bind(addr)
    sock.listen(backlog)
    return sock
