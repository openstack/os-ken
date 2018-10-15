****************
os_ken.app.ofctl
****************

os_ken.app.ofctl provides a convenient way to use OpenFlow messages
synchronously.

OfctlService os_ken application is automatically loaded if your
OS-Ken application imports ofctl.api module.

Example::

    import os_ken.app.ofctl.api

OfctlService application internally uses OpenFlow barrier messages
to ensure message boundaries.  As OpenFlow messages are asynchronous
and some of messages does not have any replies on success, barriers
are necessary for correct error handling.

api module
==========

.. automodule:: os_ken.app.ofctl.api
   :members:

exceptions
==========

.. automodule:: os_ken.app.ofctl.exception
   :members:
