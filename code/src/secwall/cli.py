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
import imp, os, sys

# sec-wall
from secwall.server import Proxy

config_py_template = """# -*- coding: utf-8 -*-

# stdlib
import uuid

# The value will be regenerated on each server's startup.
# Don't share it with anyone.
INSTANCE_SECRET = uuid.uuid4().hex

# ##############################################################################

def default():
    return {
        'ssl': True,
        'ssl-cert': True,
        'ssl-cert-commonName':INSTANCE_SECRET,
        'host': 'http://' + INSTANCE_SECRET
    }

urls = (
    ('/*', default()),
)
"""

class _Command(object):
    """ A base class for all CLI commands.
    """

    # A directory containing a file of that name will be considered to
    # be a sec-wall's config directory.
    _config_marker = '.sec-wall-config'

class Init(_Command):
    """ Handles the 'sec-wall --init /foo/bar' command.
    """
    def run(self, config_dir, app_ctx):
        listing = os.listdir(config_dir)
        if listing:
            msg = '{0} is not empty. Please re-run the command in an empty directory.'
            msg = msg.format(config_dir)
            print(msg)
            sys.exit(3)

        open(os.path.join(config_dir, 'config.py'), 'w').write(config_py_template)
        open(os.path.join(config_dir, self._config_marker), 'w').close()

class Start(object):
    """ Handles the 'sec-wall --start /foo/bar' command.
    """
    def run(self, config_dir, app_ctx):
        f, p, d = imp.find_module('config', [config_dir])
        config_mod = imp.load_module('config', f, p, d)

        names = ('http_host', 'https_host', 'http_starting_port',
                 'https_starting_port', 'http_log', 'https_log',
                 'crypto_dir', 'keyfile', 'certfile', 'ca_certs',
                 'not_authorized', 'forbidden', 'no_url_match',
                 'validation_precedence', 'client_cert_401_www_auth',
                 'syslog_host', 'syslog_port', 'syslog_facility',
                 'syslog_level', 'server_tag')

        for name in names:
            attr = getattr(config_mod, name, None)
            if not attr:
                attr = app_ctx.get_object(name)
                setattr(config_mod, name, attr)

        proxy = Proxy(config_mod)
        proxy.serve_forever()

class Stop(object):
    """ Handles the 'sec-wall --stop /foo/bar' command.
    """
    def __init__(self):
        pass