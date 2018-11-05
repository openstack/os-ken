*****************
PCAP file library
*****************

Introduction
============

OS-Ken PCAP file library helps you to read/write PCAP file which file
format are described in `The Wireshark Wiki`_.

.. _The Wireshark Wiki: https://wiki.wireshark.org/Development/LibpcapFileFormat

Reading PCAP file
=================

For loading the packet data containing in PCAP files, you can use
pcaplib.Reader.

.. autoclass:: os_ken.lib.pcaplib.Reader

Writing PCAP file
=================

For dumping the packet data which your OSKenApp received, you can use
pcaplib.Writer.

.. autoclass:: os_ken.lib.pcaplib.Writer
