===================
Testing VRRP Module
===================

This page describes how to test OS-Ken VRRP service

Running integrated tests
========================

Some testing scripts are available.

* os_ken/tests/integrated/test_vrrp_linux_multi.py
* os_ken/tests/integrated/test_vrrp_multi.py

Each files include how to run in the comment.
Please refer to it.


Running multiple OS-Ken VRRP in network namespace
=================================================

The following command lines set up necessary bridges and interfaces.

And then run OSKen-VRRP::

    # ip netns add gateway1
    # ip netns add gateway2

    # ip link add dev vrrp-br0 type bridge
    # ip link add dev vrrp-br1 type bridge

    # ip link add veth0 type veth peer name veth0-br0
    # ip link add veth1 type veth peer name veth1-br0
    # ip link add veth2 type veth peer name veth2-br0
    # ip link add veth3 type veth peer name veth3-br1
    # ip link add veth4 type veth peer name veth4-br1
    # ip link add veth5 type veth peer name veth5-br1

    # ip link set dev veth0-br0 master vrrp-br0
    # ip link set dev veth1-br0 master vrrp-br0
    # ip link set dev veth2-br0 master vrrp-br0
    # ip link set dev veth3-br0 master vrrp-br1
    # ip link set dev veth4-br0 master vrrp-br1
    # ip link set dev veth5-br0 master vrrp-br1

    # ip link set vrrp-br0 up
    # ip link set vrrp-br1 up

    # ip link set veth0 up
    # ip link set veth0-br0 up
    # ip link set veth1-br0 up
    # ip link set veth2-br0 up
    # ip link set veth3-br1 up
    # ip link set veth4-br1 up
    # ip link set veth5 up
    # ip link set veth5-br1 up

    # ip link set veth1 netns gateway1
    # ip link set veth2 netns gateway2
    # ip link set veth3 netns gateway1
    # ip link set veth4 netns gateway2

    # ip netns exec gateway1 ip link set veth1 up
    # ip netns exec gateway2 ip link set veth2 up
    # ip netns exec gateway1 ip link set veth3 up
    # ip netns exec gateway2 ip link set veth4 up

    # ip netns exec gateway1 .os_ken-vrrp veth1 '10.0.0.2' 254
    # ip netns exec gateway2 .os_ken-vrrp veth2 '10.0.0.3' 100


.. admonition:: Caveats

   Please make sure that all interfaces and bridges are UP.
   Don't forget interfaces in netns gateway1/gateway2.

::

                    ^ veth5
                    |
                    V veth5-br1
            -----------------------
            |Linux Brirge vrrp-br1|
            -----------------------
     veth3-br1^               ^ veth4-br1
              |               |
         veth3V               V veth4
         -------------       -------------
         |netns      |       |netns      |
         |gateway1   |       |gateway2   |
         |os_ken-vrrp|       |os_ken-vrrp|
         -------------       ----------
         veth1^               ^ veth2
              |               |
     veth1-br0V               V veth2-br0
            -----------------------
            |Linux Brirge vrrp-br0|
            -----------------------
                    ^ veth0-br0
                    |
                    V veth0



Here's the helper executable, os_ken-vrrp::

    #!/usr/bin/env python3
    #
    # Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
    # Copyright (C) 2013 Isaku Yamahata <yamahata at valinux co jp>
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

    from os_ken.lib import hub
    hub.patch()

    # TODO:
    #   Right now, we have our own patched copy of ovs python bindings
    #   Once our modification is upstreamed and widely deployed,
    #   use it
    #
    # NOTE: this modifies sys.path and thus affects the following imports.
    # eg. oslo.config.cfg.
    import os_ken.contrib

    from oslo.config import cfg
    import logging
    import netaddr
    import sys
    import time

    from os_ken import log
    log.early_init_log(logging.DEBUG)

    from os_ken import flags
    from os_ken import version
    from os_ken.base import app_manager
    from os_ken.controller import controller
    from os_ken.lib import mac as lib_mac
    from os_ken.lib.packet import vrrp
    from os_ken.services.protocols.vrrp import api as vrrp_api
    from os_ken.services.protocols.vrrp import event as vrrp_event


    CONF = cfg.CONF

    _VRID = 7
    _IP_ADDRESS = '10.0.0.1'
    _PRIORITY = 100


    class VRRPTestRouter(app_manager.OSKenApp):
        def __init__(self, *args, **kwargs):
            super(VRRPTestRouter, self).__init__(*args, **kwargs)
            print args
            self.logger.debug('vrrp_config %s', args)
            self._ifname = args[0]
            self._primary_ip_address = args[1]
            self._priority = int(args[2])

        def start(self):
            print 'start'
            hub.spawn(self._main)

        def _main(self):
            print self
            interface = vrrp_event.VRRPInterfaceNetworkDevice(
                lib_mac.DONTCARE, self._primary_ip_address, None, self._ifname)
            self.logger.debug('%s', interface)

            ip_addresses = [_IP_ADDRESS]
            config = vrrp_event.VRRPConfig(
                version=vrrp.VRRP_VERSION_V3, vrid=_VRID, priority=self._priority,
                ip_addresses=ip_addresses)
            self.logger.debug('%s', config)

            rep = vrrp_api.vrrp_config(self, interface, config)
            self.logger.debug('%s', rep)


    def main():
        vrrp_config = sys.argv[-3:]
        sys.argv = sys.argv[:-3]
        CONF(project='os_ken', version='os_ken-vrrp %s' % version)

        log.init_log()
        # always enable ofp for now.
        app_lists = ['os_ken.services.protocols.vrrp.manager',
                     'os_ken.services.protocols.vrrp.dumper',
                     'os_ken.services.protocols.vrrp.sample_manager']

        app_mgr = app_manager.AppManager.get_instance()
        app_mgr.load_apps(app_lists)
        contexts = app_mgr.create_contexts()
        app_mgr.instantiate_apps(**contexts)
        vrrp_router = app_mgr.instantiate(VRRPTestRouter, *vrrp_config, **contexts)
        vrrp_router.start()

        while True:
            time.sleep(999999)

        app_mgr.close()


    if __name__ == "__main__":
        main()
