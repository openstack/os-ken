:orphan:

.. _getting_started:

***************
Getting Started
***************

Overview/What's OS-Ken the Network Operating System
===================================================
OS-Ken is an open-sourced Network Operating System which is licensed under Apache v2.0.
It supports openflow protocol.

If you are not familiar with Software Defined Network(SDN) and
OpenFlow/openflow controller,
please refer to `openflow org <http://www.openflow.org/>`_ .

The mailing list is available at
`OpenStack-dev ML <http://lists.openstack.org/cgi-bin/mailman/listinfo/openstack-discuss>`_


Installing OS-Ken Network Operating System
==========================================
Extract source code and just type::

   % python ./setup.py install

Then, run osken-manager.
It listens to ip address 0.0.0.0 and port 6633 by default.
Then have your openflow switch (hardware or openvswitch OVS) to connect to
osken-manager.

For OVS case, you can done it by

  % ovs-vsctl set-controller <your bridge>  tcp:<ip addr>[:<port: default 6633>]

At the moment, osken-manager supports only tcp method.

invoking application and Configuration
======================================
It can be configured by passing configuration file like::

  osken-manager [generic/application specific options...]

The generic available is as follows::

  --app-lists: application module name to run;
    repeat this option to specify a list of values
  --help: show help

The options for openflow controller::

  --ofp-listen-host: openflow listen host
    (default: '')
  --ofp-tcp-listen-port: openflow tcp listen port
    (default: '6633')
    (an integer)

The options for log::

  --default-log-level: default log level
    (an integer)
  --log-dir: log file directory
  --log-file: log file name
  --log-file-mode: default log file permission
    (default: '0644')
  --[no]use-stderr: log to standard error
    (default: 'true')
  --use-syslog: output to syslog
    (default: 'False')
  --[no]verbose: show debug output
    (default: 'false')

The option for oslo.config.cfg::

  --config-file: Path to a config file to use. Multiple config files
    can be specified, with values in later files taking precedence.
    (default: [])
  --config-dir: Path to a config directory to pull *.conf files from.
    This file set is sorted, so as to provide a predictable parse order if
    individual options are over-ridden. The set is parsed after the file(s),
    if any, specified via --config-file, hence over-ridden options in the
    directory take precedence.
