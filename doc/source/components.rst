********************
Components of OS-Ken
********************

Executables
===========

osken-manager
------------------

The main executable.


Base components
===============

os_ken.base.app_manager
-----------------------
.. automodule:: os_ken.base.app_manager


OpenFlow controller
===================

os_ken.controller.controller
----------------------------
.. automodule:: os_ken.controller.controller

os_ken.controller.dpset
-----------------------
.. automodule:: os_ken.controller.dpset

os_ken.controller.ofp_event
---------------------------
.. automodule:: os_ken.controller.ofp_event

os_ken.controller.ofp_handler
-----------------------------
.. automodule:: os_ken.controller.ofp_handler


OpenFlow wire protocol encoder and decoder
==========================================

os_ken.ofproto.ofproto_v1_0
---------------------------
.. automodule:: os_ken.ofproto.ofproto_v1_0

os_ken.ofproto.ofproto_v1_0_parser
----------------------------------
.. automodule:: os_ken.ofproto.ofproto_v1_0_parser

os_ken.ofproto.ofproto_v1_2
---------------------------
.. automodule:: os_ken.ofproto.ofproto_v1_2

os_ken.ofproto.ofproto_v1_2_parser
----------------------------------
.. automodule:: os_ken.ofproto.ofproto_v1_2_parser

os_ken.ofproto.ofproto_v1_3
---------------------------
.. automodule:: os_ken.ofproto.ofproto_v1_3

os_ken.ofproto.ofproto_v1_3_parser
----------------------------------
.. automodule:: os_ken.ofproto.ofproto_v1_3_parser

os_ken.ofproto.ofproto_v1_4
---------------------------
.. automodule:: os_ken.ofproto.ofproto_v1_4

os_ken.ofproto.ofproto_v1_4_parser
----------------------------------
.. automodule:: os_ken.ofproto.ofproto_v1_4_parser

os_ken.ofproto.ofproto_v1_5
---------------------------
.. automodule:: os_ken.ofproto.ofproto_v1_5

os_ken.ofproto.ofproto_v1_5_parser
----------------------------------
.. automodule:: os_ken.ofproto.ofproto_v1_5_parser


OS-Ken applications
===================

os_ken.app.cbench
-----------------
.. automodule:: os_ken.app.cbench

os_ken.app.simple_switch
------------------------
.. automodule:: os_ken.app.simple_switch

os_ken.topology
---------------
.. automodule:: os_ken.topology


Libraries
=========

os_ken.lib.packet
-----------------
.. automodule:: os_ken.lib.packet

os_ken.lib.ovs
--------------
.. automodule:: os_ken.lib.ovs

os_ken.lib.of_config
--------------------
.. automodule:: os_ken.lib.of_config

os_ken.lib.netconf
------------------
.. automodule:: os_ken.lib.netconf

os_ken.lib.xflow
----------------
.. automodule:: os_ken.lib.xflow


Third party libraries
=====================

os_ken.contrib.ovs
------------------

Open vSwitch python binding. Used by os_ken.lib.ovs.

os_ken.contrib.oslo.config
--------------------------

Oslo configuration library. Used for osken-manager's command-line options
and configuration files.

os_ken.contrib.ncclient
-----------------------

Python library for NETCONF client. Used by os_ken.lib.of_config.

