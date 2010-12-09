# -*- coding: utf-8 -*-

"""
Copyright (C) 2010 Dariusz Suchojad <dsuch at gefira.pl>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

from __future__ import absolute_import, division, print_function, unicode_literals

# stdlib
import multiprocessing, os.path as path

# Spring Python
from springpython.config import Object, PythonConfig
from springpython.context import scope

# sec-wall
from secwall import wsse
from secwall.core import version

class SecWallContext(PythonConfig):
    """ A Spring Python's application context for sec-wall.
    """

    @Object
    def wsse(self):
        return wsse.WSSE()

    @Object
    def server_type(self):
        """ Whether to start a plain HTTP (http) server or an SSL/TLS one (https).
        Defaults to 'http'.
        """
        return 'http'

    @Object
    def host(self):
        """ Host to bind to.
        """
        return '0.0.0.0'

    @Object
    def port(self):
        """ Port to bind to.
        """
        return 15100

    @Object
    def log(self):
        """ Whether to log plain HTTP traffic.
        """
        return None

    @Object
    def crypto_dir(self):
        """ The base directory holding crypto material.
        """
        return './crypto'

    @Object
    def keyfile(self):
        """ Location of the server's private key.
        """
        return path.join(self.crypto_dir(), 'server-priv.pem')

    @Object
    def certfile(self):
        """ Location of the server's certificate.
        """
        return path.join(self.crypto_dir(), 'server-cert.pem')

    @Object
    def ca_certs(self):
        """ Location of the file containing CAs the server is to trust.
        """
        return path.join(self.crypto_dir(), 'ca-cert.pem')

    @Object
    def not_authorized(self):
        """ HTTP code, the content type and a user friendly description
        for 401 error.
        """
        return ['401 Not Authorized', 'text/plain', str('You are not authorized to access this resource')]

    @Object
    def forbidden(self):
        """ HTTP code, the content type and a user friendly description
        for 403 error.
        """
        return ['403 Forbidden', 'text/plain', str('You are not allowed to access this resource')]

    @Object
    def no_url_match(self):
        """ HTTP code, the content type and a user friendly description
        for 401 error.
        """
        return ['404 Not Found', 'text/plain', str('Not Found')]

    @Object
    def internal_server_error(self):
        """ HTTP code, the content type and a user friendly description
        for 500 error.
        """
        return ['500 Internal Server Error', 'text/plain', str('Internal Server Error')]

    @Object
    def validation_precedence(self):
        """ The order of types of security configuration. If there's more than
        one configuration for the given URL, only one will be used and it will
        the one that is higher on this list (closer to index 0).
        """
        return ['ssl-cert', 'basic-auth', 'digest-auth', 'wsse-pwd', 'custom-http', 'xpath']

    @Object
    def client_cert_401_www_auth(self):
        """ See disussion at http://www6.ietf.org/mail-archive/web/tls/current/msg05589.html
        """
        return 'Transport mode="tls-client-certificate"'

    @Object
    def syslog_host(self):
        """ Syslog host.
        """
        return '127.0.0.1'

    @Object
    def syslog_port(self):
        """ Syslog port.
        """
        return 514

    @Object
    def syslog_facility(self):
        """ Syslog facility.
        """
        return 'local0'

    @Object
    def syslog_level(self):
        """ Syslog logging level, for HAProxy.
        """
        return 'err'

    @Object
    def server_tag(self):
        """ How will sec-wall introduce itself to client and backend applications.
        """
        return 'sec-wall/{0}'.format(version)

    @Object
    def config_py_template(self):
        return """# -*- coding: utf-8 -*-

# stdlib
import os.path as path, uuid

# The value will be regenerated on each server's startup.
# Don't share it with anyone.
INSTANCE_SECRET = uuid.uuid4().hex

# Useful constants
cur_dir = path.dirname(__file__)

# Crypto
keyfile = path.join(cur_dir, './crypto/server-priv.pem')
certfile = path.join(cur_dir, './crypto/server-cert.pem')
ca_certs = path.join(cur_dir, './crypto/ca-cert.pem')

# ##############################################################################

def default():
    return {
        'ssl': True,
        'ssl-cert': True,
        'ssl-cert-commonName':INSTANCE_SECRET,
        'host': 'http://' + INSTANCE_SECRET
    }

urls = [
    ('/*', default()),
]
"""

    @Object
    def zdaemon_conf_proxy_template(self):
        return """
<runner>
    program python -m secwall.main --fork {config_dir} {is_https}
    socket-name {config_dir}/zdaemon.sock
    transcript {config_dir}/logs/proxy.log
</runner>

<eventlog>
    <logfile>
        path {config_dir}/zdaemon.log
    </logfile>
</eventlog>
"""
