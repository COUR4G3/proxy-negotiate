Proxy-Negotiate
###############

HTTP Negotiate (SPNEGO) proxy authentication support for applications. This
allows applications that do not support HTTP proxies or do not support HTTP
proxies with Negotiate authentication to allow them to safely traverse
corporate firewalls without whitelisting IP addresses or MAC addresses and
rather relying on secure user authentication. This tool is not intended to
bypass firewall or proxy restrictions, in fact this tool was designed for better
corporate security and centralized control.

Installation
============

Install the easy way through PyPi:

    $ pip install proxy-negotiate

Or alternatively download and build yourself:


    $ git clone https://github.com/cour4g3/proxy-negotiate
    $ cd proxy-negotiate
    $ python setup.py install

Usage
=====

On Windows you need to be connected to a domain or alternatively running the MIT
Kerberos Ticket Manager, on Linux you need to install and setup the MIT or
Heimdal Kerberos client/workstation tools.

nc-negotiate
------------

A netcat-like implementation for use with programs such as SSH; now by simply
using ProxyCommand, SSH can safely traverse the proxy through an HTTP CONNECT
TCP tunnel.

    $ nc-negotiate host port [proxy_host] [proxy_port]

Example of usage with `ssh` command line:

    $ ssh -o ProxyCommand="nc-negotiate %h %p" myexternalhost.com

Or in your `~/.ssh/config`:

    Host myexternalhost.com:
        ProxyCommand nc-negotiate %h %p

proxy-negotiate
---------------

For applications that support proxies but don't support authentication or don't
support Negotiate, this acts a pseudo-proxy that applies the correct
Authorization headers and then passes the connection request on:

     $ proxy-negotiate [port] [proxy_host] [proxy_port]

Then set your proxy configuration in your application or alternatively your
proxy environment variables:

    $ export HTTP_PROXY=http://localhost:8080

Now your application will correctly authenticate through the proxy without
knowing how to. It also means no network passwords floating around in arbitary
configuration files.

## Todo

- Better parsing of the `http_proxy` and other proxy environment variables.
- Consider methods to route requests from applications that do not support
  proxies at all.

## License

Licensed under the MIT License.
