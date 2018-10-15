***************
Topology Viewer
***************

os_ken.app.gui_topology.gui_topology provides topology visualization.

This depends on following os_ken applications.

======================== =================================================
os_ken.app.rest_topology Get node and link data.
os_ken.app.ws_topology   Being notified change of link up/down.
os_ken.app.ofctl_rest    Get flows of datapaths.
======================== =================================================

Usage
=====

Run mininet (or join your real environment)::

    $ sudo mn --controller remote --topo tree,depth=3

Run GUI application::

    $ PYTHONPATH=. ./bin/os_ken run --observe-links os_ken/app/gui_topology/gui_topology.py

Access http://<ip address of os_ken host>:8080 with your web browser.

Screenshot
==========

.. image:: gui.png
   :width: 640 px

