# Copyright 2020 Red Hat, Inc.
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
import platform
import sys

from os_ken.lib import sockaddr


system = platform.system()


class Test_sockaddr(unittest.TestCase):

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_sockaddr_linux_sa_in4(self):
        if system != 'Linux' or sys.byteorder != 'little':
            return

        addr = '127.0.0.1'
        expected_result = (b'\x02\x00\x00\x00'
            b'\x7f\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00')
        self.assertEqual(expected_result, sockaddr.sa_in4(addr))

    def test_sockaddr_linux_sa_in6(self):
        if system != 'Linux' or sys.byteorder != 'little':
            return

        addr = 'dead:beef::1'
        expected_result = (b'\n\x00\x00\x00\x00\x00\x00\x00\xde\xad\xbe\xef'
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00')
        self.assertEqual(expected_result, sockaddr.sa_in6(addr))

    def test_sockaddr_sa_to_ss(self):
        addr = b'\x01'
        expected_result = b'\x01' + 127 * b'\x00'
        self.assertEqual(expected_result, sockaddr.sa_to_ss(addr))
