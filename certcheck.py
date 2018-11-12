#!/usr/bin/env python3

import ssl
import socket
import json

# List of tuples consisting of hostnames and ports to check.
servers = [
    ('eff.org', 443),
    ('www.verisign.com', 443),
    ('www.python.com', 443),
    ('non-standard-port.example.com', 4433),
]


def getpeercert(hostname, port, timeout=5.0):
    ctx = ssl.create_default_context()
    with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as sock:
        sock.settimeout(timeout)
        sock.connect((hostname, port))
        return sock.getpeercert()


def serialize(cert):
    # Transform sequence of nested tuples into a dictionary.
    # 'issuer': ((('countryName', 'IL'),),
    #            (('organizationName', 'StartCom Ltd.'),),
    #            ...)
    #  -->
    # 'issuer': {'countryName': 'IL',
    #            'organizationName': 'StartCom Ltd.',
    #            ...}
    cert['issuer'] = dict([i[0] for i in cert['issuer']])
    cert['subject'] = dict([s[0] for s in cert['subject']])
    if 'subjectAltName' in cert:
        # Transform a sequence of tuples into a list of dictionaries.
        # 'subjectAltName': (('DNS', '*.eff.org'), ('DNS', 'eff.org'))
        #  -->
        # 'subjectAltName': [{'DNS': '*.eff.org'}, {'DNS': 'eff.org'}]
        cert['subjectAltName'] = [{k: v} for k, v in cert['subjectAltName']]
    # All the work above means the peer cert info serializes nicely into JSON.
    return json.dumps(cert, separators=(',', ':'))


def main():
    for hostname, port in servers:
        try:
            cert = getpeercert(hostname, port)
            print('hostname: "{0}", port: "{1}", status: "{2}", cert: {3}'.
                  format(hostname, port, 'valid', serialize(cert)))
        except ssl.SSLError as ex:
            print('hostname: "{0}", port: "{1}", status: "{2}"'.
                  format(hostname, port, ex.reason))
        except (socket.gaierror, socket.timeout, ConnectionRefusedError) as ex:
            print('Error connecting to {0}:{1} - {2}'.
                  format(hostname, port, ex))


if __name__ == '__main__':
    main()
