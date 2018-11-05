****************
MRT file library
****************

Introduction
============

OS-Ken MRT file library helps you to read/write MRT
(Multi-Threaded Routing Toolkit) Routing Information Export Format
[`RFC6396`_].

.. _RFC6396: https://tools.ietf.org/html/rfc6396

Reading MRT file
================

For loading the routing information contained in MRT files, you can use
mrtlib.Reader.

.. autoclass:: os_ken.lib.mrtlib.Reader

Writing MRT file
================

For dumping the routing information which your OSKenApp generated, you can use
mrtlib.Writer.

.. autoclass:: os_ken.lib.mrtlib.Writer
