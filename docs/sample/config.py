# -*- coding: utf-8 -*-

# stdlib
import uuid

# The value will be regenerated on each server's startup. Don't share it with
# anyone.
INSTANCE_SECRET = uuid.uuid4().hex

# ##############################################################################

def foobar():
    return {
        'ssl': True,
        'ssl-cert':True,
        'ssl-cert-commonName':'localhost',
        'ssl-cert-organizationalUnitName':'sec-wall',

        'host': 'http://localhost:17090'
    }

def baz():
    return {
        'ssl': True,
        'wsse-pwd':True,
        'wsse-pwd-username':'myuser',
        'wsse-pwd-password':'zxc',
        'wsse-pwd-password-digest': True,
        'wsse-pwd-reject-empty-nonce-creation':True,
        'wsse-pwd-reject-stale-tokens':True,
        'wsse-pwd-reject-expiry-limit':180,
        'wsse-pwd-nonce-freshness-time':180,
        'wsse-pwd-realm': 'bazbaz',

        'host': 'http://localhost:17090'
    }

def default():
    return {
        'cert-needed': True,
        'cert-commonName':INSTANCE_SECRET,
    }

urls = (
    ('/foo/bar', foobar()),
    ('/baz', baz()),
    ('/*', default())
)
