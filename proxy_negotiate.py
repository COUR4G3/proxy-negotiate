__version__ = '0.1'

import base64
import fcntl
import gssapi
import os
import select
import socket
import sys

def netcat(host, port, proxy_host, proxy_port):
    # Establish CONNECT tunnel through proxy
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((proxy_host, proxy_port))

    sock.send(('CONNECT %s:%d HTTP/1.1\r\n' % (host, port)).encode('ascii'))
    sock.send(('Host: %s:%d\r\n' % (host, port)).encode('ascii'))
    sock.send(('Proxy-Connection: Keep-Alive\r\n').encode('ascii'))
    sock.send(('\r\n').encode('ascii'))

    data = b''
    while True:
        data += sock.recv(1500)
        if b'\r\n\r\n' in data:
            # Any data after HTTP Response header is a TCP stream for our program
            idx = data.find(b'\r\n\r\n') + 4
            lines = data[:idx+4].split(b'\r\n')[:-2]
            data = data[idx+4:]
            break

    _, status_code, status_message = lines[0].split(b' ', 2)
    status_code = int(status_code)

    if status_code == 407:
        # Proxy Authentication Required
        sock.close()

        # generate SPNEGO token and base64 encode
        bearer = 'Negotiate'
        service = gssapi.Name('HTTP@%s' % proxy_host, gssapi.NameType.hostbased_service)
        ctx = gssapi.SecurityContext(name=service, usage='initiate')

        token = ctx.step()
        token = base64.b64encode(token).decode('ascii')

        # Retry CONNECT tunnel with Proxy-Authorization this time
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((proxy_host, proxy_port))

        sock.send(('CONNECT %s:%d HTTP/1.1\r\n' % (host, port)).encode('ascii'))
        sock.send(('Host: %s:%d\r\n' % (host, port)).encode('ascii'))
        sock.send(('Proxy-Authorization: %s %s\r\n' % (bearer, token)).encode('ascii'))
        sock.send(('Proxy-Connection: Keep-Alive\r\n').encode('ascii'))
        sock.send(('\r\n').encode('ascii'))

        data = b''
        while True:
            data += sock.recv(1500)
            if b'\r\n\r\n' in data:
                # Any data after HTTP Response header is a TCP stream for our program
                idx = data.find(b'\r\n\r\n') + 4
                lines = data[:idx+4].split(b'\r\n')[:-2]
                data = data[idx+4:]
                break

        _, status_code, status_message = lines[0].split(b' ', 2)
        status_code = int(status_code)

        if status_code == 407:
            sock.close()
            sys.stderr.write('Proxy %s rejected our credentials\n' % proxy_host)
            sys.exit(1)
        elif status_code != 200:
            sock.close()
            sys.stderr.write('Proxy %s responded with %d %s\n' % (proxy_host, status_code, status_message))
            sys.exit(1)
    elif status_code != 200:
        sock.close()
        sys.stderr.write('Proxy %s responded with %d %s\n' % (proxy_host, status_code, status_message))
        sys.exit(1)

    sys.stderr.write('Proxy %s connected to %s:%d\n' % (proxy_host, host, port))

    # Any data received after the 200 Connection Established is for our program
    if data:
        sys.stdout.buffer.write(data)
        sys.stdout.flush()

    # Set stdin to non-blocking
    fd = sys.stdin.fileno()
    fl = fcntl.fcntl(fd, fcntl.F_GETFL)
    fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)

    # Start netcat-ing ...
    running = True
    while running:
        for ready in select.select([sys.stdin, sock], [], [])[0]:
            if ready == sys.stdin:
                if sys.version >= (3,0):
                    data = sys.stdin.buffer.read()
                else:
                    data = sys.stdin.read()
                if not data:
                    # As soon as one end of tunnel closes then close
                    running = False
                    break
                sock.send(data)
            elif ready == sock:
                data = sock.recv(1500)
                if not data:
                    # As soon as one end of tunnel closes then close
                    running = False
                    break
                if sys.version >= (3,0):
                    sys.stdout.buffer.write(data)
                else:
                    sys.stdout.write(data)
                sys.stdout.flush()

    sock.close()
