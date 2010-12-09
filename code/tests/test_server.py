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
import cStringIO, unittest, uuid

# nose
from nose.tools import assert_true, eq_

# testfixtures
from testfixtures import Replacer

# Spring Python
from springpython.context import ApplicationContext

# sec-wall
from secwall import app_context, server

app_ctx = ApplicationContext(app_context.SecWallContext())

class _DummyConfig(object):
    def __init__(self, urls):
        self.urls = urls
        self.no_url_match = app_ctx.get_object('no_url_match')
        self.client_cert_401_www_auth = app_ctx.get_object('client_cert_401_www_auth')
        self.validation_precedence = app_ctx.get_object('validation_precedence')
        self.not_authorized = app_ctx.get_object('not_authorized')
        self.forbidden = app_ctx.get_object('forbidden')
        self.no_url_match = app_ctx.get_object('no_url_match')
        self.internal_server_error = app_ctx.get_object('internal_server_error')

class _DummyCertInfo(object):
    pass

def _start_response(*ignored_args, **ignored_kwargs):
    pass

class RequestAppTestCase(unittest.TestCase):
    """ Tests related to the the secwall.server._RequestApp class, the WSGI
    application executed on each request.
    """
    def setUp(self):
        self.config = _DummyConfig([['/*', {}]])

    def test_call_match(self):
        """ Tests how the __call__ method handles a matching URL.
        """
        dummy_cert = _DummyCertInfo()

        for cert in None, dummy_cert:
            with Replacer() as r:

                _env = {'PATH_INFO': uuid.uuid4().hex}
                _url_config = self.config.urls

                def _on_request(self, start_response, env, url_config, client_cert):
                    eq_(start_response, _start_response)
                    eq_(sorted(env.items()), sorted(_env.items()))

                    url_configs = [elem[1] for elem in self.urls_compiled]
                    assert_true(url_config in url_configs, (url_config, self.urls_compiled))

                    eq_(client_cert, cert)

                r.replace('secwall.server._RequestApp._on_request', _on_request)

                req_app = server._RequestApp(self.config, app_ctx)
                req_app(_env, _start_response, cert)

    def test_call_no_match(self):
        """ Tests how the __call__ method handles a non-matching URL.
        """
        config = _DummyConfig([])

        with Replacer() as r:

            _env = {'PATH_INFO': uuid.uuid4().hex}
            _url_config = []

            def _404(self, start_response):
                eq_(start_response, _start_response)

            r.replace('secwall.server._RequestApp._404', _404)

            req_app = server._RequestApp(config, app_ctx)
            req_app(_env, _start_response)

    def test_on_request_ssl_scheme_not_https(self):
        """ A URL should be accessed through HTTPS only if config says so.
        """
        with Replacer() as r:
            def _403(self, start_response):
                eq_(start_response, _start_response)

            r.replace('secwall.server._RequestApp._403', _403)

            _url_config = {'ssl': True}
            _env = {'wsgi.url_scheme': uuid.uuid4().hex}

            req_app = server._RequestApp(self.config, app_ctx)
            req_app._on_request(_start_response, _env, _url_config, None)

    def test_on_request_client_cert_required(self):
        """ A client certificate is required if config says so.
        """
        with Replacer() as r:
            def _401(self, start_response, www_auth):
                eq_(start_response, _start_response)
                eq_(www_auth, app_ctx.get_object('client_cert_401_www_auth'))

            r.replace('secwall.server._RequestApp._401', _401)

            _url_config = {'ssl': True, 'ssl-cert': True}
            _env = {'wsgi.url_scheme': 'https'}

            req_app = server._RequestApp(self.config, app_ctx)
            req_app._on_request(_start_response, _env, _url_config, None)

    def test_on_request_handlers(self):
        """ Tests picking up a correct handler for the given auth config.
        """
        valid_validation_precedence = app_ctx.get_object('validation_precedence')

        invalid_auth_type = uuid.uuid4()
        invalid_validation_precedence = [invalid_auth_type]

        for precedence in(valid_validation_precedence, invalid_validation_precedence):
            for config_type in precedence:

                for should_succeed in False, True:

                    _host = uuid.uuid4().hex
                    _path_info = uuid.uuid4().hex
                    _realm = uuid.uuid4().hex
                    _code = uuid.uuid4().hex
                    _status = uuid.uuid4().hex
                    _response = uuid.uuid4().hex
                    _headers = {'Content-Type': uuid.uuid4().hex}

                    def _x_start_response(code_status, headers):
                        if config_type == invalid_auth_type:
                            eq_(code_status, '500 Internal Server Error')
                        else:
                            eq_(code_status, _code + ' ' + _status)
                            eq_(sorted(headers), sorted(_headers.items()))

                    with Replacer() as r:
                        def _on_ssl_cert(self, env, url_config, client_cert, data):
                            return should_succeed

                        def _on_basic_auth(*ignored_args, **ignored_kwargs):
                            return should_succeed

                        def _on_digest_auth(*ignored_args, **ignored_kwargs):
                            return should_succeed

                        def _on_wsse_pwd(*ignored_args, **ignored_kwargs):
                            return should_succeed

                        def _on_custom_http(*ignored_args, **ignored_kwargs):
                            return should_succeed

                        def _on_xpath(*ignored_args, **ignored_kwargs):
                            return should_succeed

                        def _401(self, start_response, www_auth):
                            pass

                        class _Request(object):
                            def __init__(*ignored_args, **ignored_kwargs):
                                pass

                        def _urlopen(*ignored_args, **ignored_kwargs):
                            class _DummyResponse(object):
                                def __init__(self, *ignored_args, **ignored_kwargs):
                                    self.msg = _status
                                    self.headers = _headers

                                def read(*ignored_args, **ignored_kwargs):
                                    return _response

                                def getcode(*ignored_args, **ignored_kwargs):
                                    return _code

                                def close(*ignored_args, **ignored_kwargs):
                                    pass

                            return _DummyResponse()

                        r.replace('secwall.server._RequestApp._on_ssl_cert', _on_ssl_cert)
                        r.replace('secwall.server._RequestApp._on_basic_auth', _on_basic_auth)
                        r.replace('secwall.server._RequestApp._on_digest_auth', _on_digest_auth)
                        r.replace('secwall.server._RequestApp._on_wsse_pwd', _on_wsse_pwd)
                        r.replace('secwall.server._RequestApp._on_custom_http', _on_custom_http)
                        r.replace('secwall.server._RequestApp._on_xpath', _on_xpath)
                        r.replace('secwall.server._RequestApp._401', _401)
                        r.replace('urllib2.Request', _Request)
                        r.replace('urllib2.urlopen', _urlopen)

                        try:
                            wsgi_input = cStringIO.StringIO()
                            wsgi_input.write(uuid.uuid4().hex)

                            _url_config = {'ssl': False, config_type:True, 'host':_host}

                            if config_type in('basic-auth', 'wsse-pwd'):
                                _url_config[config_type + '-realm'] = _realm

                            _env = {'wsgi.input':wsgi_input, 'PATH_INFO':_path_info}

                            req_app = server._RequestApp(self.config, app_ctx)
                            response = req_app._on_request(_x_start_response, _env, _url_config, None)

                            response_context = (should_succeed, response, _response)

                            if config_type == invalid_auth_type:
                                eq_(response, ['Internal Server Error'], response_context)
                            else:
                                if should_succeed:
                                    eq_(response, [_response], response_context)
                                else:
                                    eq_(response, None, response_context)

                        finally:
                            wsgi_input.close()

    def test_get_www_auth(self):
        """ Tests the correctness of returning a value of the WWW-Authenticate
        header.
        """
        basic_auth_realm = uuid.uuid4().hex
        wsse_pwd_realm = uuid.uuid4().hex
        url_config = {'basic-auth-realm':basic_auth_realm, 'wsse-pwd-realm':wsse_pwd_realm}

        expected = {
            'ssl-cert': self.config.client_cert_401_www_auth,
            'basic-auth': 'Basic realm="{0}"'.format(basic_auth_realm),
            'digest-auth': 'TODO',
            'wsse-pwd': 'WSSE realm="{0}", profile="UsernameToken"'.format(wsse_pwd_realm),
            'custom-http': 'custom-http',
            'xpath': 'xpath'
        }

        req_app = server._RequestApp(self.config, app_ctx)

        for config_type in app_ctx.get_object('validation_precedence'):
            value = req_app._get_www_auth(url_config, config_type)
            eq_(value, expected[config_type])

    def test_get_www_auth(self):
        """ Tests the '_response' method.
        """
        _code_status, _headers, _response = (uuid.uuid4().hex for x in range(3))

        def _start_response(code_status, headers):
            eq_(code_status, _code_status)
            eq_(headers, _headers)

        req_app = server._RequestApp(self.config, app_ctx)

        response = req_app._response(_start_response, _code_status, _headers, _response)
        eq_(response, [_response])

    def test_401(self):
        """ Tests the '_401' method.
        """
        www_auth = uuid.uuid4().hex

        _code_status, _content_type, _description = app_ctx.get_object('not_authorized')

        with Replacer() as r:

            def _response(self, start_response, code_status, headers, response):
                eq_(start_response, _start_response)
                eq_(code_status, _code_status)
                eq_(sorted(headers), [('Content-Type', _content_type), ('WWW-Authenticate', www_auth)])
                eq_(response, _description)

            r.replace('secwall.server._RequestApp._response', _response)

            req_app = server._RequestApp(self.config, app_ctx)
            req_app._401(_start_response, www_auth)

    def test_403(self):
        """ Tests the '_403' method.
        """
        _code_status, _content_type, _description = app_ctx.get_object('forbidden')

        with Replacer() as r:

            def _response(self, start_response, code_status, headers, response):
                eq_(start_response, _start_response)
                eq_(code_status, _code_status)
                eq_(sorted(headers), [('Content-Type', _content_type)])
                eq_(response, _description)

            r.replace('secwall.server._RequestApp._response', _response)

            req_app = server._RequestApp(self.config, app_ctx)
            req_app._403(_start_response)

    def test_404(self):
        """ Tests the '_404' method.
        """
        _code_status, _content_type, _description = app_ctx.get_object('no_url_match')

        with Replacer() as r:

            def _response(self, start_response, code_status, headers, response):
                eq_(start_response, _start_response)
                eq_(code_status, _code_status)
                eq_(sorted(headers), [('Content-Type', _content_type)])
                eq_(response, _description)

            r.replace('secwall.server._RequestApp._response', _response)

            req_app = server._RequestApp(self.config, app_ctx)
            req_app._404(_start_response)

    def test_500(self):
        """ Tests the '_500' method.
        """
        _code_status, _content_type, _description = app_ctx.get_object('internal_server_error')

        with Replacer() as r:

            def _response(self, start_response, code_status, headers, response):
                eq_(start_response, _start_response)
                eq_(code_status, _code_status)
                eq_(sorted(headers), [('Content-Type', _content_type)])
                eq_(response, _description)

            r.replace('secwall.server._RequestApp._response', _response)

            req_app = server._RequestApp(self.config, app_ctx)
            req_app._500(_start_response)
