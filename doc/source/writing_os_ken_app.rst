*********************
The First Application
*********************

Whetting Your Appetite
======================

If you want to manage the network gears (switches, routers, etc) at
your way, you need to write your OS-Ken application. Your application
tells OS-Ken how you want to manage the gears. Then OS-Ken configures the
gears by using OpenFlow protocol, etc.

Writing OS-Ken application is easy. It's just Python scripts.


Start Writing
=============

We show a OS-Ken application that make OpenFlow switches work as a dumb
layer 2 switch.

Open a text editor creating a new file with the following content:

.. code-block:: python

   from os_ken.base import app_manager

   class L2Switch(app_manager.RyuApp):
       def __init__(self, *args, **kwargs):
           super(L2Switch, self).__init__(*args, **kwargs)

OS-Ken application is just a Python script so you can save the file with
any name, extensions, and any place you want. Let's name the file
'l2.py' at your home directory.

This application does nothing useful yet, however it's a complete OS-Ken
application. In fact, you can run this OS-Ken application::

   % os_ken-manager ~/l2.py
   loading app /Users/fujita/l2.py
   instantiating app /Users/fujita/l2.py


All you have to do is defining needs a new subclass of RyuApp to run
your Python script as a OS-Ken application.

Next let's add the functionality of sending a received packet to all
the ports.

.. code-block:: python

   from os_ken.base import app_manager
   from os_ken.controller import ofp_event
   from os_ken.controller.handler import MAIN_DISPATCHER
   from os_ken.controller.handler import set_ev_cls
   from os_ken.ofproto import ofproto_v1_0

   class L2Switch(app_manager.RyuApp):
       OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

       def __init__(self, *args, **kwargs):
           super(L2Switch, self).__init__(*args, **kwargs)

       @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
       def packet_in_handler(self, ev):
           msg = ev.msg
           dp = msg.datapath
           ofp = dp.ofproto
           ofp_parser = dp.ofproto_parser

           actions = [ofp_parser.OFPActionOutput(ofp.OFPP_FLOOD)]
           out = ofp_parser.OFPPacketOut(
               datapath=dp, buffer_id=msg.buffer_id, in_port=msg.in_port,
               actions=actions)
           dp.send_msg(out)


A new method 'packet_in_handler' is added to L2Switch class. This is
called when OS-Ken receives an OpenFlow packet_in message. The trick is
'set_ev_cls' decorator. This decorator tells OS-Ken when the decorated
function should be called.

The first argument of the decorator indicates an event that makes
function called. As you expect easily, every time OS-Ken gets a
packet_in message, this function is called.

The second argument indicates the state of the switch. Probably, you
want to ignore packet_in messages before the negotiation between OS-Ken
and the switch finishes. Using 'MAIN_DISPATCHER' as the second
argument means this function is called only after the negotiation
completes.

Next let's look at the first half of the 'packet_in_handler' function.

* ev.msg is an object that represents a packet_in data structure.

* msg.dp is an object that represents a datapath (switch).

* dp.ofproto and dp.ofproto_parser are objects that represent the
  OpenFlow protocol that OS-Ken and the switch negotiated.

Ready for the second half.

* OFPActionOutput class is used with a packet_out message to specify a
  switch port that you want to send the packet out of. This
  application need a switch to send out of all the ports so OFPP_FLOOD
  constant is used.

* OFPPacketOut class is used to build a packet_out message.

* If you call Datapath class's send_msg method with a OpenFlow message
  class object, OS-Ken builds and send the on-wire data format to the switch.


Here, you finished implementing your first OS-Ken application. You are ready to
run this OS-Ken application that does something useful.


A dumb l2 switch is too dumb? You want to implement a learning l2
switch? Move to `the next step
<https://github.com/osrg/os_ken/blob/master/os_ken/app/simple_switch.py>`_. You
can learn from the existing OS-Ken applications at `os_ken/app
<https://github.com/osrg/os_ken/blob/master/os_ken/app/>`_ directory and
`integrated tests
<https://github.com/osrg/os_ken/blob/master/os_ken/tests/integrated/>`_
directory.
