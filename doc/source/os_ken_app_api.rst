**********************
OS-Ken application API
**********************

OS-Ken application programming model
====================================

Threads, events, and event queues
---------------------------------

OS-Ken applications are single-threaded entities which implement
various functionalities in OS-Ken. Events are messages between them.

OS-Ken applications send asynchronous events to each other.
Besides that, there are some OS-Ken-internal event sources which
are not OS-Ken applications. One of the examples of such event sources
is the OpenFlow controller.
While an event can currently contain arbitrary python objects,
it's discouraged to pass complex objects (eg. unpickleable objects)
between OS-Ken applications.

Each OS-Ken application has a receive queue for events.
The queue is FIFO and preserves the order of events.
Each OS-Ken application has a thread for event processing.
The thread keeps draining the receive queue by dequeueing an event
and calling the appropritate event handler for the event type.
Because the event handler is called in the context of
the event processing thread, it should be careful when blocking.
While an event handler is blocked, no further events for
the OS-Ken application will be processed.

There are kinds of events which are used to implement synchronous
inter-application calls between OS-Ken applications.
While such requests use the same machinery as ordinary
events, their replies are put on a queue dedicated to the transaction
to avoid deadlock.

While threads and queues are currently implemented with eventlet/greenlet,
a direct use of them in a OS-Ken application is strongly discouraged.

Contexts
--------
Contexts are ordinary python objects shared among OS-Ken applications.
The use of contexts is discouraged for new code.

Create a OS-Ken application
===========================
A OS-Ken application is a python module which defines a subclass of
os_ken.base.app_manager.RyuApp.
If two or more such classes are defined in a module, the first one
(by name order) will be picked by app_manager.
An OS-Ken application is singleton: only a single instance of a given OS-Ken
application is supported.

Observe events
==============
A OS-Ken application can register itself to listen for specific events
using os_ken.controller.handler.set_ev_cls decorator.

Generate events
===============
A OS-Ken application can raise events by calling appropriate
os_ken.base.app_manager.RyuApp's methods like send_event or
send_event_to_observers.

Event classes
=============
An event class describes a OS-Ken event generated in the system.
By convention, event class names are prefixed by "Event".
Events are generated either by the core part of OS-Ken or OS-Ken applications.
A OS-Ken application can register its interest for a specific type of
event by providing a handler method using the
os_ken.controller.handler.set_ev_cls decorator.

OpenFlow event classes
----------------------
os_ken.controller.ofp_event module exports event classes which describe
receptions of OpenFlow messages from connected switches.
By convention, they are named as os_ken.controller.ofp_event.EventOFPxxxx
where xxxx is the name of the corresponding OpenFlow message.
For example, EventOFPPacketIn for the packet-in message.
The OpenFlow controller part of OS-Ken automatically decodes OpenFlow messages
received from switches and send these events to OS-Ken applications which
expressed an interest using os_ken.controller.handler.set_ev_cls.
OpenFlow event classes are subclasses of the following class.

.. autoclass:: os_ken.controller.ofp_event.EventOFPMsgBase

See :ref:`ofproto_ref` for more info about OpenFlow messages.

os_ken.base.app_manager.RyuApp
==============================

See :ref:`api_ref`.

os_ken.controller.handler.set_ev_cls
====================================

.. autofunction:: os_ken.controller.handler.set_ev_cls

os_ken.controller.controller.Datapath
=====================================

.. autoclass:: os_ken.controller.controller.Datapath

os_ken.controller.event.EventBase
=================================

.. autoclass:: os_ken.controller.event.EventBase

os_ken.controller.event.EventRequestBase
========================================

.. autoclass:: os_ken.controller.event.EventRequestBase

os_ken.controller.event.EventReplyBase
======================================

.. autoclass:: os_ken.controller.event.EventReplyBase

os_ken.controller.ofp_event.EventOFPStateChange
===============================================

.. autoclass:: os_ken.controller.ofp_event.EventOFPStateChange

os_ken.controller.ofp_event.EventOFPPortStateChange
===================================================

.. autoclass:: os_ken.controller.ofp_event.EventOFPPortStateChange

os_ken.controller.dpset.EventDP
===============================

.. autoclass:: os_ken.controller.dpset.EventDP

os_ken.controller.dpset.EventPortAdd
====================================

.. autoclass:: os_ken.controller.dpset.EventPortAdd

os_ken.controller.dpset.EventPortDelete
=======================================

.. autoclass:: os_ken.controller.dpset.EventPortDelete

os_ken.controller.dpset.EventPortModify
=======================================

.. autoclass:: os_ken.controller.dpset.EventPortModify

os_ken.controller.network.EventNetworkPort
==========================================

.. autoclass:: os_ken.controller.network.EventNetworkPort

os_ken.controller.network.EventNetworkDel
=========================================

.. autoclass:: os_ken.controller.network.EventNetworkDel

os_ken.controller.network.EventMacAddress
=========================================

.. autoclass:: os_ken.controller.network.EventMacAddress

os_ken.controller.tunnels.EventTunnelKeyAdd
===========================================

.. autoclass:: os_ken.controller.tunnels.EventTunnelKeyAdd

os_ken.controller.tunnels.EventTunnelKeyDel
===========================================

.. autoclass:: os_ken.controller.tunnels.EventTunnelKeyDel

os_ken.controller.tunnels.EventTunnelPort
=========================================

.. autoclass:: os_ken.controller.tunnels.EventTunnelPort
