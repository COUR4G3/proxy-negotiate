# Proxy-Negotiate

HTTP Negotiate (SPNEGO) proxy authentication support for applications. This
allows applications that do not support HTTP proxies or do not support HTTP
proxies with Negotiate authentication to allow them to safely traverse
corporate firewalls without whitelisting IP addresses or MAC addresses and
rather relying on secure user authentication. This tool is not intended to
bypass firewall or proxy restrictions, in fact this tool was designed for better
corporate security and centralized control.

## Usage

### nc-negotiate

A netcat-like implementation for use with programs such as SSH; now by simply
using ProxyCommand, SSH can safely traverse the proxy through an HTTP CONNECT
TCP tunnel.

    worm-nc host port [proxy_host] [proxy_port]

Example of usage with openSSH:

```
Host myexternalhost.com:
    ProxyCommand worm-nc %h %p
```

## Todo

- Better parsing of the `http_proxy` and other proxy environment variables.
- Implement a fake proxy to modify requests from applications that do not
  support HTTP Negotiate proxy authentication and pass it to the real proxy with
  the correct authentication header.

## License

Licensed under the MIT License.
