# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
# Copyright (C) 2011 Isaku Yamahata <yamahata at valinux co jp>
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


class OSKenException(Exception):
    message = 'An unknown exception'

    def __init__(self, msg=None, **kwargs):
        self.kwargs = kwargs
        if msg is None:
            msg = self.message

        try:
            msg = msg % kwargs
        except Exception:
            msg = self.message

        super(OSKenException, self).__init__(msg)


class OFPUnknownVersion(OSKenException):
    message = 'unknown version %(version)x'


class OFPMalformedMessage(OSKenException):
    message = 'malformed message'


class OFPTruncatedMessage(OSKenException):
    message = 'truncated message: %(orig_ex)s'

    def __init__(self, ofpmsg, residue, original_exception,
                 msg=None, **kwargs):
        self.ofpmsg = ofpmsg
        self.residue = residue
        self.original_exception = original_exception
        kwargs['orig_ex'] = str(original_exception)

        super(OFPTruncatedMessage, self).__init__(msg, **kwargs)


class OFPInvalidActionString(OSKenException):
    message = 'unable to parse: %(action_str)s'


class NetworkNotFound(OSKenException):
    message = 'no such network id %(network_id)s'


class NetworkAlreadyExist(OSKenException):
    message = 'network id %(network_id)s already exists'


class PortNotFound(OSKenException):
    message = 'no such port (%(dpid)s, %(port)s) in network %(network_id)s'


class PortAlreadyExist(OSKenException):
    message = 'port (%(dpid)s, %(port)s) in network %(network_id)s ' \
              'already exists'


class PortUnknown(OSKenException):
    message = 'unknown network id for port (%(dpid)s %(port)s)'


class MacAddressDuplicated(OSKenException):
    message = 'MAC address %(mac)s is duplicated'
