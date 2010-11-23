# -*- coding: utf-8 -*-

# stdlib
import uuid
from os import path

# The value will be regenerated on each server's startup. Don't share it with
# anyone.
INSTANCE_SECRET = uuid.uuid4().hex

# Useful constants
cur_dir = path.dirname(__file__)
no_url_match = ('404 Not Found', 'text/plain', 'Not Found')
forbidden = ('403 Forbidden', 'text/plain', 'You are not allowed to access this resource')

# Logging
http_log=None
https_log=None

# Hosts
http_host = '0.0.0.0'
https_host = '0.0.0.0'

# Ports
http_starting_port = 15100
https_starting_port = 15200

# Crypto
keyfile = path.join(cur_dir, './crypto/server-priv.pem')
certfile = path.join(cur_dir, './crypto/server-cert.pem')
ca_certs = path.join(cur_dir, './crypto/ca-cert.pem')

# Server headers
server_tag = 'sec-wall'

# ##############################################################################

def foobar():
    return {
        'cert-needed': True,
        'cert-commonName':'foobar',
        'host': 'http://localhost:17090'
    }

def not_authorized():
    return {
        'cert-needed': True,
        'cert-commonName':INSTANCE_SECRET,
        'host': 'http://localhost:17090'
    }

urls = (
    ('/foo/bar', foobar()),
    ('/*', not_authorized())
)
