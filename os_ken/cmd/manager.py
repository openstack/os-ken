#!/usr/bin/env python3
#
# Copyright (C) 2011, 2012 Nippon Telegraph and Telephone Corporation.
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

import os
import sys

from os_ken.lib import hub
hub.patch(thread=False)

from os_ken import cfg

import logging
from os_ken import log
log.early_init_log(logging.DEBUG)

from os_ken import flags
from os_ken import __version__ as version
from os_ken.base.app_manager import AppManager
from os_ken.controller import controller
from os_ken.topology import switches


CONF = cfg.CONF
CONF.register_cli_opts([
    cfg.ListOpt('app-lists', default=[],
                help='application module name to run'),
    cfg.MultiStrOpt('app', positional=True, default=[],
                    help='application module name to run'),
    cfg.StrOpt('pid-file', default=None, help='pid file name'),
    cfg.BoolOpt('enable-debugger', default=False,
                help='don\'t overwrite Python standard threading library'
                '(use only for debugging)'),
    cfg.StrOpt('user-flags', default=None,
               help='Additional flags file for user applications'),
])


def _parse_user_flags():
    """
    Parses user-flags file and loads it to register user defined options.
    """
    try:
        idx = list(sys.argv).index('--user-flags')
        user_flags_file = sys.argv[idx + 1]
    except (ValueError, IndexError):
        user_flags_file = ''

    if user_flags_file and os.path.isfile(user_flags_file):
        from os_ken.utils import _import_module_file
        _import_module_file(user_flags_file)


def main(args=None, prog=None):
    _parse_user_flags()
    try:
        CONF(args=args, prog=prog,
             project='os_ken', version='osken-manager %s' % version,
             default_config_files=['/usr/local/etc/os_ken/os_ken.conf'])
    except cfg.ConfigFilesNotFoundError:
        CONF(args=args, prog=prog,
             project='os_ken', version='osken-manager %s' % version)

    log.init_log()
    logger = logging.getLogger(__name__)

    if CONF.enable_debugger:
        msg = 'debugging is available (--enable-debugger option is turned on)'
        logger.info(msg)
    else:
        hub.patch(thread=True)

    if CONF.pid_file:
        with open(CONF.pid_file, 'w') as pid_file:
            pid_file.write(str(os.getpid()))

    app_lists = CONF.app_lists + CONF.app
    # keep old behavior, run ofp if no application is specified.
    if not app_lists:
        app_lists = ['os_ken.controller.ofp_handler']

    app_mgr = AppManager.get_instance()
    app_mgr.load_apps(app_lists)
    contexts = app_mgr.create_contexts()
    services = []
    services.extend(app_mgr.instantiate_apps(**contexts))

    try:
        hub.joinall(services)
    except KeyboardInterrupt:
        logger.debug("Keyboard Interrupt received. "
                     "Closing OSKen application manager...")
    finally:
        app_mgr.close()


if __name__ == "__main__":
    main()
