Proxy-Negotiate
###############
**This has been completely rewritten as of version 1.0.0.**

HTTP Negotiate proxy authentication support for applications. This allows
applications that do not natively support proxies (SSH, Telnet) using a
netcat-like implementation or ones that do not support the Negotiate method of
proxy authentication by running a local proxy.

Installation
============

Install the easy way through PyPi:

.. code:: shell

  $ pip install proxy-negotiate

Or alternatively download and build yourself:

.. code:: shell

  $ git clone https://github.com/cour4g3/proxy-negotiate
  $ cd proxy-negotiate
  $ python setup.py install

Usage
=====
You will obviously need to be part of a domain for Negotiate authentication to
work or alternatively on Windows, be running the Kerberos for Windows Manager.

nc-negotiate
------------
A netcat-like implementation for use with programs such as SSH and Telnet:

.. code:: shell

  $ nc-negotiate host port [proxy_host] [proxy_port]

Example of usage with OpenSSH command line:

.. code:: shell

  $ ssh -o ProxyCommand="nc-negotiate %h %p" myexternalhost.com

Or in your `~/.ssh/config`:

.. code::

  Host myexternalhost.com:
      ProxyCommand nc-negotiate %h %p

proxy-negotiate
---------------
For application that support proxies but not Negotiate proxy authentication:

.. code:: shell

  $ proxy-negotiate proxy_host proxy_port [listen_host:127.0.0.1] [listen_port:8080]

License
=======
Licensed under the MIT License.
