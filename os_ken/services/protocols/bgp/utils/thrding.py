# Copyright 2026 Openinfra Foundation
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

import threading
import logging

from os_ken.lib import hub


LOG = logging.getLogger('utils.thrding')


class ThreadingIOFactory(object):

    @staticmethod
    def create_custom_event():
        LOG.debug('Create Threading based CustomEvent called')
        return hub.Event()

    @staticmethod
    def create_looping_call(funct, *args, **kwargs):
        LOG.debug('Threading based create_looping_call called')
        return LoopingCall(funct, *args, **kwargs)


class LoopingCall(object):
    def __init__(self, funct, *args, **kwargs):
        self._funct = funct
        self._args = args
        self._kwargs = kwargs
        self._running = False
        self._interval = 0
        self._cancel_event = threading.Event()
        self._thread = None

    def _loop(self):
        while self._running:
            # Wait for interval, but can be interrupted by cancel_event
            if self._cancel_event.wait(self._interval):
                # Event was set => reset or stop requested
                self._cancel_event.clear()
                if not self._running:
                    break
                continue
            if self._running:
                self._funct(*self._args, **self._kwargs)

    def start(self, interval, now=True):
        if self._running:
            self.stop()
        self._running = True
        self._interval = interval
        self._cancel_event.clear()

        if now:
            self._funct(*self._args, **self._kwargs)

        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        self._cancel_event.set()

    def reset(self):
        self._cancel_event.set()
