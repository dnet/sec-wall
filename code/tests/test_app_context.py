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
from hashlib import sha256
from logging.handlers import SysLogHandler
from os import path
from uuid import UUID

# nose
from nose.tools import assert_equal, assert_true, eq_

# Spring Python
from springpython.config import PythonConfig
from springpython.context import ApplicationContext

# sec-wall
from secwall.app_context import SecWallContext
from secwall.server import HTTPProxy, HTTPSProxy, _RequestHandler, _RequestApp

def test_app_context():
    assert_true(issubclass(SecWallContext, PythonConfig))
    ctx = ApplicationContext(SecWallContext())

    eq_(len(ctx.object_defs), 34)

    assert_equal(ctx.get_object('http_proxy_class'), HTTPProxy)
    assert_equal(ctx.get_object('https_proxy_class'), HTTPSProxy)
    assert_equal(ctx.get_object('wsgi_request_handler'), _RequestHandler)
    assert_equal(ctx.get_object('wsgi_request_app'), _RequestApp)
    eq_(ctx.get_object('server_type'), 'http')
    eq_(ctx.get_object('host'), '0.0.0.0')
    eq_(ctx.get_object('port'), 15100)
    eq_(ctx.get_object('log'), False)
    eq_(ctx.get_object('crypto_dir'), './crypto')
    eq_(ctx.get_object('keyfile'), path.join('./crypto', 'server-priv.pem'))
    eq_(ctx.get_object('certfile'), path.join('./crypto', 'server-cert.pem'))
    eq_(ctx.get_object('ca_certs'), path.join('./crypto', 'ca-cert.pem'))
    eq_(ctx.get_object('not_authorized'), ['401', 'Not Authorized', 'text/plain', str('You are not authorized to access this resource')])
    eq_(ctx.get_object('forbidden'), ['403', 'Forbidden', 'text/plain', str('You are not allowed to access this resource')])
    eq_(ctx.get_object('no_url_match'), ['404', 'Not Found', 'text/plain', str('Not Found')])
    eq_(ctx.get_object('internal_server_error'), ['500', 'Internal Server Error', 'text/plain', str('Internal Server Error')])
    eq_(ctx.get_object('validation_precedence'), ['ssl-cert', 'basic-auth', 'digest-auth', 'wsse-pwd', 'custom-http', 'xpath'])
    eq_(ctx.get_object('client_cert_401_www_auth'), 'Transport mode="tls-client-certificate"')
    eq_(ctx.get_object('syslog_facility'), SysLogHandler.LOG_USER)
    eq_(ctx.get_object('syslog_address'), b'/dev/log')
    eq_(ctx.get_object('log_level'), 'INFO')
    eq_(ctx.get_object('log_file_config'), None)
    eq_(ctx.get_object('server_tag'), 'sec-wall/1.0.0')
    eq_(ctx.get_object('instance_name'), 'default')
    eq_(ctx.get_object('quote_path_info'), False)
    eq_(ctx.get_object('quote_query_string'), False)
    eq_(sorted(ctx.get_object('from_backend_ignore')), ['Server'])
    eq_(ctx.get_object('add_invocation_id'), True)
    eq_(ctx.get_object('sign_invocation_id'), True)
    eq_(sha256(ctx.get_object('config_py_template')).hexdigest(), 'db97b59c2afecba50f368de5d320ca2741b2203b59639acd518d9ea869fa96d3')
    eq_(sha256(ctx.get_object('zdaemon_conf_proxy_template')).hexdigest(), '1c09f0011ffdc90d3ec533e11f7abf91f48a94542d6acdc886b2c4d6b7b6ff53')

    default_url_config = ctx.get_object('default_url_config')
    eq_(default_url_config['ssl'], True)
    eq_(default_url_config['ssl-cert'], True)

    common_name = default_url_config['ssl-cert-commonName']
    host = default_url_config['host'].replace('http://', '')

    # Will raise ValueError if values aren't UUIDs.
    UUID(common_name)
    UUID(host)

    eq_(UUID(common_name).version, 4)
    eq_(UUID(host).version, 4)

    eq_(ctx.get_object('add_default_if_not_found'), True)
