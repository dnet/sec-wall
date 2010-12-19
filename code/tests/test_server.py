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
import cStringIO, logging, ssl, unittest, urllib2, uuid

# lxml
from lxml import etree

# gevent
from gevent import wsgi

# nose
from nose.tools import assert_raises, assert_true, eq_

# testfixtures
from testfixtures import Replacer

# Spring Python
from springpython.config import Object
from springpython.context import ApplicationContext

# sec-wall
from secwall import app_context, constants, core, server

client_cert = {'notAfter': 'May  8 23:59:59 2019 GMT',
 'subject': ((('serialNumber', '12345678'),),
             (('countryName', 'US'),),
             (('postalCode', '12345'),),
             (('stateOrProvinceName', 'California'),),
             (('localityName', 'Mountain View'),),
             (('organizationName', 'Foobar, Inc.'),),
             (('commonName', 'foobar-baz'),))}

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

        # Note that the funky whitespace below has been added on purpose
        # as it shouldn't make any difference for the parser.
        self.digest_auth_template = ('Digest           username          ="{0}", realm="{1}", ' \
                 'nonce="{2}", ' \
                 '   uri="{3}", ' \
                 'response   ="{4}", ' \
                 '   opaque         ="{5}"')

        self.sample_xml = b"""<?xml version="1.0" encoding="utf-8"?>
            <a xmlns:myns1="http://example.com/myns1" xmlns:myns2="http://example.com/myns2">
                <b>
                    <c>ccc
                        <d>ddd</d>
                        <foobar myattr="myvalue">baz</foobar>
                        <myns1:qux>123</myns1:qux>
                        <myns2:zxc>456</myns2:zxc>
                    </c>
                </b>
            </a>"""

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
        """ A URL should be accessed through HTTPS if the config says so.
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
        Makes sure that each of the validation handlers has a chance for validating
        the request.
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
                            return core.AuthResult(should_succeed)

                        def _on_basic_auth(*ignored_args, **ignored_kwargs):
                            return core.AuthResult(should_succeed)

                        def _on_digest_auth(*ignored_args, **ignored_kwargs):
                            return core.AuthResult(should_succeed)

                        def _on_wsse_pwd(*ignored_args, **ignored_kwargs):
                            return core.AuthResult(should_succeed)

                        def _on_custom_http(*ignored_args, **ignored_kwargs):
                            return core.AuthResult(should_succeed)

                        def _on_xpath(*ignored_args, **ignored_kwargs):
                            return core.AuthResult(should_succeed)

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

                            if config_type in('basic-auth', 'digest-auth', 'wsse-pwd'):
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

    def test_on_request_urlopen_exception(self):
        """ The _on_request method should response the response regardless
        even if it's not 200 OK.
        """
        with Replacer() as r:

            _host = uuid.uuid4().hex
            _path_info = uuid.uuid4().hex
            _username = uuid.uuid4().hex
            _password = uuid.uuid4().hex
            _realm = uuid.uuid4().hex
            _code = uuid.uuid4().hex
            _status = uuid.uuid4().hex
            _response = uuid.uuid4().hex
            _headers = {'Content-Type': uuid.uuid4().hex}

            def _x_start_response(code_status, headers):
                eq_(code_status, _code + ' ' + _status)
                eq_(sorted(headers), sorted(_headers.items()))

            def _urlopen(*ignored_args, **ignored_kwargs):
                class _DummyException(urllib2.HTTPError):
                    def __init__(self, *ignored_args, **ignored_kwargs):
                        self.msg = _status
                        self.headers = _headers

                    def read(*ignored_args, **ignored_kwargs):
                        return _response

                    def getcode(*ignored_args, **ignored_kwargs):
                        return _code

                    def close(*ignored_args, **ignored_kwargs):
                        pass

                raise _DummyException()

            r.replace('urllib2.urlopen', _urlopen)

            wsgi_input = cStringIO.StringIO()

            try:
                wsgi_input.write(uuid.uuid4().hex)

                _url_config = {'basic-auth':True, 'host':_host}
                _url_config['basic-auth-username'] = _username
                _url_config['basic-auth-password'] = _password
                _url_config['basic-auth-realm'] = _realm

                auth = 'Basic ' + (_username + ':' + _password).encode('base64')

                _env = {'wsgi.input':wsgi_input, 'PATH_INFO':_path_info,
                        'HTTP_AUTHORIZATION':auth}

                req_app = server._RequestApp(self.config, app_ctx)
                response = req_app._on_request(_x_start_response, _env, _url_config, None)
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

    def test_ssl_cert_no_cert(self):
        """ Config says a client cert is required but none is given on input.
        Such a request must be outright rejected.
        """
        _env = {}
        _url_config = {}
        _client_cert = None
        _data = None

        req_app = server._RequestApp(self.config, app_ctx)
        is_ok = req_app._on_ssl_cert(_env, _url_config, _client_cert, _data)

        eq_(bool(is_ok), False)

    def test_ssl_cert_any_cert(self):
        """ Config says the calling app must use a client certificate, but any
        certificate signed off by a known CA will do.
        """
        _env = {}
        _url_config = {}
        _client_cert = True
        _data = None

        req_app = server._RequestApp(self.config, app_ctx)
        is_ok = req_app._on_ssl_cert(_env, _url_config, _client_cert, _data)

        eq_(bool(is_ok), True)

    def test_ssl_cert_all_fields_valid(self):
        """ Config says a client cert is needed and its fields must match the
        config. Clients sends a valid certificate - all of fields required by
        config are being sent in.
        """
        _env = {}
        _url_config = {'ssl-cert-commonName':'foobar-baz',
                       'ssl-cert-serialNumber': '12345678',
                       'ssl-cert-localityName':'Mountain View'
                       }
        _data = None

        req_app = server._RequestApp(self.config, app_ctx)
        is_ok = req_app._on_ssl_cert(_env, _url_config, client_cert, _data)

        eq_(bool(is_ok), True)

    def test_ssl_cert_some_fields_invalid_value(self):
        """ Config says a client cert is needed and its fields must match the
        config. Clients sends an invalid certificate - not all of the fields
        required by config have the correct values.
        """
        _env = {}
        _url_config = {'ssl-cert-commonName':'foobar-baz',
                       'ssl-cert-serialNumber': '12345678',
                       'ssl-cert-localityName':uuid.uuid4().hex,
                       'ssl-cert-postalCode':uuid.uuid4().hex,
                       }
        _data = None

        req_app = server._RequestApp(self.config, app_ctx)
        is_ok = req_app._on_ssl_cert(_env, _url_config, client_cert, _data)

        eq_(bool(is_ok), False)

    def test_ssl_cert_some_fields_missing(self):
        """ Config says a client cert is needed and its fields must match the
        config. Clients sends an invalid certificate - some of the fields
        required by config are missing.
        """
        _env = {}
        _url_config = {'ssl-cert-commonName':'foobar-baz',
                       'ssl-cert-serialNumber': '12345678',
                       'ssl-cert-' + uuid.uuid4().hex:uuid.uuid4().hex,
                       'ssl-cert-' + uuid.uuid4().hex:uuid.uuid4().hex,
                       }
        _data = None

        req_app = server._RequestApp(self.config, app_ctx)
        is_ok = req_app._on_ssl_cert(_env, _url_config, client_cert, _data)

        eq_(bool(is_ok), False)

    def test_ssl_cert_no_subject(self):
        """ Config says a client cert is needed and its fields must match the
        config. Clients sends an invalid certificate - somehow the 'subject'
        group is missing.
        """
        _env = {}
        _url_config = {'ssl-cert-commonName':'foobar-baz',
                       'ssl-cert-serialNumber': '12345678',
                       'ssl-cert-' + uuid.uuid4().hex:uuid.uuid4().hex,
                       'ssl-cert-' + uuid.uuid4().hex:uuid.uuid4().hex,
                       }
        _data = None
        _client_cert = {'notAfter': 'May  8 23:59:59 2019 GMT'}

        req_app = server._RequestApp(self.config, app_ctx)
        is_ok = req_app._on_ssl_cert(_env, _url_config, _client_cert, _data)

        eq_(bool(is_ok), False)

    def test_on_wsse_pwd_no_data(self):
        """ Post data must be sent in when using WSSE.
        """
        _env = {}
        _url_config = {}
        _unused_client_cert = None
        _data = None

        req_app = server._RequestApp(self.config, app_ctx)
        result = req_app._on_wsse_pwd(_env, _url_config, _unused_client_cert, _data)

        eq_(False, result.status)

    def test_on_wsse_pwd_returns_validate_output(self):
        """ The '_on_wsse_pwd' method should return True if the 'self.wsse.validate'
        method returns with no exception
        """
        _env = {}
        _url_config = {}
        _unused_client_cert = None
        _data = uuid.uuid4().hex

        with Replacer() as r:
            def _fromstring(*ignored_args, **ignored_kwargs):
                pass

            def _validate(*ignored_args, **ignored_kwargs):
                return uuid.uuid4().hex

            r.replace('lxml.etree.fromstring', _fromstring)
            r.replace('secwall.wsse.WSSE.validate', _validate)

            req_app = server._RequestApp(self.config, app_ctx)
            is_ok = req_app._on_wsse_pwd(_env, _url_config, _unused_client_cert, _data)
            eq_(True, is_ok)

    def test_on_wsse_pwd_returns_false_on_security_exception(self):
        """ The '_on_wsse_pwd' method should return a boolean false AuthResult
        when a SecurityException has been caught. The AuthResult's description
        must not be empty.
        """
        _env = {}
        _url_config = {}
        _unused_client_cert = None
        _data = uuid.uuid4().hex

        with Replacer() as r:
            def _fromstring(*ignored_args, **ignored_kwargs):
                pass

            def _validate(*ignored_args, **ignored_kwargs):
                raise core.SecurityException(uuid.uuid4().hex)

            r.replace('lxml.etree.fromstring', _fromstring)
            r.replace('secwall.wsse.WSSE.validate', _validate)

            req_app = server._RequestApp(self.config, app_ctx)
            auth_result = req_app._on_wsse_pwd(_env, _url_config, _unused_client_cert, _data)
            eq_(False, auth_result.status)
            eq_(constants.AUTH_WSSE_VALIDATION_ERROR, auth_result.code)
            assert_true(auth_result.description != '')

    def test_on_basic_auth_ok(self):
        """ Everything's OK, client has to use Basic Auth and it does so
        in a correct way, by sending the correct headers.
        """
        username = uuid.uuid4().hex
        password = uuid.uuid4().hex

        auth = 'Basic ' + (username + ':' + password).encode('base64')

        _env = {'HTTP_AUTHORIZATION': auth}

        _url_config = {'basic-auth': True, 'basic-auth-username':username,
                       'basic-auth-password':password}

        req_app = server._RequestApp(self.config, app_ctx)
        is_ok = req_app._on_basic_auth(_env, _url_config)

        eq_(bool(is_ok), True)

    def test_on_basic_auth_invalid_username(self):
        """ Client sends an invalid username.
        """
        username = uuid.uuid4().hex
        password = uuid.uuid4().hex

        auth = 'Basic ' + (username + ':' + password).encode('base64')

        _env = {'HTTP_AUTHORIZATION': auth}

        _url_config = {'basic-auth': True, 'basic-auth-username':uuid.uuid4().hex,
                       'basic-auth-password':password}

        req_app = server._RequestApp(self.config, app_ctx)
        is_ok = req_app._on_basic_auth(_env, _url_config)

        eq_(bool(is_ok), False)

    def test_on_basic_auth_invalid_password(self):
        """ Client sends an invalid password.
        """
        username = uuid.uuid4().hex
        password = uuid.uuid4().hex

        auth = 'Basic ' + (username + ':' + password).encode('base64')

        _env = {'HTTP_AUTHORIZATION': auth}

        _url_config = {'basic-auth': True, 'basic-auth-username':username,
                       'basic-auth-password':uuid.uuid4().hex}

        req_app = server._RequestApp(self.config, app_ctx)
        is_ok = req_app._on_basic_auth(_env, _url_config)

        eq_(bool(is_ok), False)

    def test_on_basic_auth_no_http_authorization(self):
        """ Client doesn't send an authorization header at all.
        """
        _env = {}
        _url_config = {'basic-auth': True, 'basic-auth-username':uuid.uuid4().hex,
                       'basic-auth-password':uuid.uuid4().hex}

        req_app = server._RequestApp(self.config, app_ctx)
        is_ok = req_app._on_basic_auth(_env, _url_config)

        eq_(bool(is_ok), False)

    def test_on_basic_auth_http_authourization_invalid_prefix(self):
        """ Client sends an authorization header but it doesn't start with
        the expected prefix ('Basic ').
        """
        username = uuid.uuid4().hex
        password = uuid.uuid4().hex

        auth = uuid.uuid4().hex + (username + ':' + password).encode('base64')

        _env = {'HTTP_AUTHORIZATION': auth}

        _url_config = {'basic-auth': True, 'basic-auth-username':username,
                       'basic-auth-password':uuid.uuid4().hex}

        req_app = server._RequestApp(self.config, app_ctx)
        is_ok = req_app._on_basic_auth(_env, _url_config)

        eq_(bool(is_ok), False)

    def test_digest_auth_compute_response(self):
        """ Tests that the algorithm for computing a response works correctly,
        as defined in RFC 2069.
        """
        username = 'abc'
        realm = 'My Realm'
        password = 'def'
        uri = '/qwerty/uiop?as=df&gh=jk'
        method = 'GET'
        nonce = '8391442a5f0c48d69a5aff8847caede5'
        expected_response = '7bb69ec080c75df5b166f379d47c6528'

        response = server._RequestApp(self.config, app_ctx)._compute_digest_auth_response(
            username, realm, password, uri, method, nonce)

        eq_(expected_response, response)


    def test_digest_auth_parse_header(self):
        """ Tests that the algorithm for computing a response works correctly,
        as defined in RFC 2069.
        """
        username = 'abc'
        realm = 'My Realm'
        nonce = '8391442a5f0c48d69a5aff8847caede5'
        uri = '/qwerty/uiop?as=df&gh=jk'
        response = '7bb69ec080c75df5b166f379d47c6528'
        opaque = '69041b080f324d65829acc140e9dc5cb'

        auth = self.digest_auth_template.format(username, realm, nonce, uri, response, opaque)

        parsed = server._RequestApp(self.config, app_ctx)._parse_digest_auth(auth)

        eq_(parsed['username'], username)
        eq_(parsed['realm'], realm)
        eq_(parsed['nonce'], nonce)
        eq_(parsed['uri'], uri)
        eq_(parsed['response'], response)
        eq_(parsed['opaque'], opaque)

    def test_on_digest_auth_invalid_input(self):
        """ Digest auth handler should return False on certain conditions,
        when the header's fields don't match the expected values.
        """
        request_app = server._RequestApp(self.config, app_ctx)

        # No HTTP_AUTHORIZATION header sent at all; returns False unconditionally,
        # regardless of the URL config.

        env = {}
        url_config = {}
        auth_result = request_app._on_digest_auth(env, url_config)
        eq_(False, auth_result.status)
        eq_(constants.AUTH_DIGEST_NO_AUTH, auth_result.code)

        # The username sent in is not equal to what's in the URL config.

        env = {'PATH_INFO':uuid.uuid4().hex}
        auth = self.digest_auth_template.format(uuid.uuid4().hex, '', '', '', '', '')
        env['HTTP_AUTHORIZATION'] = auth

        url_config = {'digest-auth-username':uuid.uuid4()}
        url_config['digest-auth-password'] = uuid.uuid4()
        url_config['digest-auth-realm'] = uuid.uuid4()

        auth_result = request_app._on_digest_auth(env, url_config)
        eq_(False, auth_result.status)
        eq_(constants.AUTH_DIGEST_USERNAME_MISMATCH, auth_result.code)

        # The realm sent in is not equal to what's in the URL config.

        env = {'PATH_INFO':uuid.uuid4().hex}
        username = uuid.uuid4().hex
        auth = self.digest_auth_template.format(username, uuid.uuid4().hex, '', '', '', '')
        env['HTTP_AUTHORIZATION'] = auth

        url_config = {'digest-auth-username':username}
        url_config['digest-auth-password'] = uuid.uuid4()
        url_config['digest-auth-realm'] = uuid.uuid4()

        auth_result = request_app._on_digest_auth(env, url_config)
        eq_(False, auth_result.status)
        eq_(constants.AUTH_DIGEST_REALM_MISMATCH, auth_result.code)

        # The URI sent in in HTTP_AUTHORIZATION header is not equal to what's
        # been sent in the PATH_INFO + QUERY_STRING.

        env = {'PATH_INFO':uuid.uuid4().hex}
        username = uuid.uuid4().hex
        realm = uuid.uuid4().hex
        path_info = '/a/b/c/'
        query_string =  'q=w&e=r'

        auth = self.digest_auth_template.format(username, realm, '',
                    '{0}?{1}'.format(path_info, query_string), '', '')

        env['HTTP_AUTHORIZATION'] = auth
        env['PATH_INFO'] = path_info
        env['QUERY_STRING'] = query_string + '{0}:{1}'.format(uuid.uuid4().hex,
                                                              uuid.uuid4().hex)

        url_config = {'digest-auth-username':username}
        url_config['digest-auth-password'] = uuid.uuid4()
        url_config['digest-auth-realm'] = realm

        auth_result = request_app._on_digest_auth(env, url_config)
        eq_(False, auth_result.status)
        eq_(constants.AUTH_DIGEST_URI_MISMATCH, auth_result.code)

        # Client sends an invalid password in.

        username = 'abc'
        realm = 'My Realm'
        password = uuid.uuid4().hex
        method = 'GET'
        nonce = '8391442a5f0c48d69a5aff8847caede5'
        response = '7bb69ec080c75df5b166f379d47c6528'
        opaque = '69041b080f324d65829acc140e9dc5cb'

        path_info = '/qwerty/uiop'
        query_string =  'as=df&gh=jk'

        uri = '{0}?{1}'.format(path_info, query_string)

        env = {'PATH_INFO':'/qwerty/uiop', 'QUERY_STRING':query_string}
        auth = self.digest_auth_template.format(username, realm, nonce, uri, response, opaque)
        env['HTTP_AUTHORIZATION'] = auth
        env['REQUEST_METHOD'] = 'GET'

        url_config = {'digest-auth-username':username}
        url_config['digest-auth-password'] = password
        url_config['digest-auth-realm'] = realm

        auth_result = request_app._on_digest_auth(env, url_config)
        eq_(False, auth_result.status)
        eq_(constants.AUTH_DIGEST_RESPONSE_MISMATCH, auth_result.code)

    def test_on_digest_auth_ok(self):
        """ Client sends correct data matching the configuration, the validation
        method should return True in that case.
        """
        request_app = server._RequestApp(self.config, app_ctx)

        username = 'abc'
        password = 'def'
        realm = 'My Realm'
        method = 'GET'

        input_data = (
            # nonce, response, opaque, path_info, query_string

            ('094e8e8411eb494fa7ecb740fd6bf229', '34fbb34f2910934d88d6b9d361de68b6',
             'ae0725805fae43af85443b279dd8f0d3', '/qwerty/uiop', ''),

            ('8391442a5f0c48d69a5aff8847caede5', '7bb69ec080c75df5b166f379d47c6528',
             '69041b080f324d65829acc140e9dc5cb', '/qwerty/uiop', 'as=df&gh=jk'),
        )

        for(nonce, response, opaque, path_info, query_string) in input_data:

            if query_string:
                uri = '{0}?{1}'.format(path_info, query_string)
            else:
                uri = path_info

            env = {'PATH_INFO':'/qwerty/uiop', 'QUERY_STRING':query_string}
            auth = self.digest_auth_template.format(username, realm, nonce, uri, response, opaque)
            env['HTTP_AUTHORIZATION'] = auth
            env['REQUEST_METHOD'] = 'GET'

            url_config = {'digest-auth-username':username}
            url_config['digest-auth-password'] = password
            url_config['digest-auth-realm'] = realm

            eq_(True, request_app._on_digest_auth(env, url_config))

    def test_on_custom_http_invalid_input(self):
        """ Client sends incorrect custom authorization headers.
        """
        request_app = server._RequestApp(self.config, app_ctx)

        name1, value1 = [uuid.uuid4().hex + '-' + uuid.uuid4().hex for x in range(2)]
        name2, value2 = [uuid.uuid4().hex + '-' + uuid.uuid4().hex for x in range(2)]
        url_config = {'custom-http': True,
                      'custom-http-'+name1: value1,
                      'custom-http-'+name2: value2}

        # 1) None of the headers were sent
        env = {}
        auth_result = request_app._on_custom_http(env, url_config)
        eq_(False, auth_result.status)
        eq_(constants.AUTH_DIGEST_NO_HEADER, auth_result.code)

        # 2) All headers were sent yet their values were incorrect
        env = {'HTTP_' + name1.upper().replace('-', '_'):uuid.uuid4().hex,
               'HTTP_' + name2.upper().replace('-', '_'):uuid.uuid4().hex}

        auth_result = request_app._on_custom_http(env, url_config)
        eq_(False, auth_result.status)
        eq_(constants.AUTH_DIGEST_HEADER_MISMATCH, auth_result.code)

        # 4) One header's correct (including its value), the other has incorrect
        # name and value.
        env = {'HTTP_' + name1.upper().replace('-', '_'):value1,
               uuid.uuid4().hex:uuid.uuid4().hex}

        auth_result = request_app._on_custom_http(env, url_config)
        eq_(False, auth_result.status)
        eq_(constants.AUTH_DIGEST_NO_HEADER, auth_result.code)

        # 4) One header's correct (including its value), the other has incorrect
        # value despite its name being correct.
        env = {'HTTP_' + name1.upper().replace('-', '_'):value1,
               'HTTP_' + name2.upper().replace('-', '_'):uuid.uuid4().hex}

        auth_result = request_app._on_custom_http(env, url_config)
        eq_(False, auth_result.status)
        eq_(constants.AUTH_DIGEST_HEADER_MISMATCH, auth_result.code)

    def test_on_custom_http_exception_on_no_custom_headers_in_config(self):
        """ An Exception is being raised when the config's invalid,
        says clients should be validated against custom headers yet it doesn't
        define any custom headers. The exception must be raised regardless of
        the client input data.
        """
        request_app = server._RequestApp(self.config, app_ctx)

        url_config = {'custom-http': True}

        # We don't need to define any input data, an Exception must be always raised.
        env = {}

        assert_raises(core.SecWallException, request_app._on_custom_http, env, url_config)

    def test_on_custom_http_ok(self):
        """ All's good, a client sends data matching the configuration.
        """
        request_app = server._RequestApp(self.config, app_ctx)

        name1, value1 = ['okok-'+uuid.uuid4().hex + '-' + uuid.uuid4().hex for x in range(2)]
        name2, value2 = ['okok-'+uuid.uuid4().hex + '-' + uuid.uuid4().hex for x in range(2)]

        url_config = {'custom-http': True,
                      'custom-http-'+name1: value1,
                      'custom-http-'+name2: value2}

        env = {'HTTP_' + name1.upper().replace('-', '_'):value1,
               'HTTP_' + name2.upper().replace('-', '_'):value2,}

        eq_(True, request_app._on_custom_http(env, url_config))

    def test_on_xpath_invalid_input(self):
        """ The client sends an invalid input.
        """
        request_app = server._RequestApp(self.config, app_ctx)

        # 1) No XML input data at all, False should be returned regardless
        # of any other input data.
        env, url_config, client_cert, data = [None] * 4

        auth_result = request_app._on_xpath(env, url_config, client_cert, data)
        eq_(False, auth_result.status)
        eq_(constants.AUTH_XPATH_NO_DATA, auth_result.code)

        # 2) One of the expected expressions doesn't match even though the other
        # ones are fine.
        env, client_cert = None, None

        xpath1 = etree.XPath("/a/b/c/d/text() = 'ddd' and //foobar/text() = 'baz'")
        xpath2 = etree.XPath("//foobar/@myattr='myvalue'")

        # Using uuid4 here means the expression will never match.
        xpath3 = etree.XPath("//myns1:qux/text()='{0}'".format(uuid.uuid4().hex),
                            namespaces={'myns1':'http://example.com/myns1'})

        url_config = {
            'xpath': True,
            'xpath-1': xpath1,
            'xpath-2': xpath2,
            'xpath-3': xpath3
        }

        auth_result = request_app._on_xpath(env, url_config, client_cert, self.sample_xml)
        eq_(False, auth_result.status)
        eq_(constants.AUTH_XPATH_EXPR_MISMATCH, auth_result.code)

    def test_on_xpath_exception_on_no_expression_defined(self):
        """ An exception should be raised when no XPath expressions have been
        defined in the config even though it says validation based on XPath
        should be performed.
        """
        request_app = server._RequestApp(self.config, app_ctx)

        env, client_cert = None, None
        url_config = {'xpath': True}

        assert_raises(core.SecWallException, request_app._on_xpath, env, url_config,
                      client_cert, self.sample_xml)

    def test_on_xpath_ok(self):
        """ The client sends a valid request, containing elements that match
        the configured XPath expressions.
        """
        request_app = server._RequestApp(self.config, app_ctx)
        env, client_cert = None, None

        xpath1 = etree.XPath("/a/b/c/d/text() = 'ddd' and //foobar/text() = 'baz'")
        xpath2 = etree.XPath("//foobar/@myattr='myvalue'")
        xpath3 = etree.XPath("//myns1:qux/text()='123'", namespaces={'myns1':'http://example.com/myns1'})

        url_config = {
            'xpath': True,
            'xpath-1': xpath1,
            'xpath-2': xpath2,
            'xpath-3': xpath3
        }

        eq_(True, request_app._on_xpath(env, url_config, client_cert, self.sample_xml))

class HTTPProxyTestCase(unittest.TestCase):
    """ Tests related to the the secwall.server.HTTPProxy class, the plain
    HTTP proxy.
    """
    def test_init_parameters(self):
        """ Tests the secwall.server.HTTPProxy.__init__ method, that is passes
        the parameters correctly to the super-class.
        """
        _host = uuid.uuid4().hex
        _port = uuid.uuid4().hex
        _log = uuid.uuid4().hex
        _app_ctx = app_ctx

        class _Config(object):
            def __init__(self):
                self.host = _host
                self.port = _port
                self.log = _log
                self.urls = []

        _config = _Config()

        with Replacer() as r:

            def _init(self, listener, application, log):
                host, port = listener
                eq_(host, _host)
                eq_(port, _port)
                assert_true(isinstance(application, server._RequestApp))
                eq_(log, _log)

            r.replace('gevent.wsgi.WSGIServer.__init__', _init)
            server.HTTPProxy(_config, _app_ctx)

class HTTPSProxyTestCase(unittest.TestCase):
    """ Tests related to the the secwall.server.HTTPSProxy class, the SSL/TLS proxy.
    """
    def test_init_parameters(self):
        """ Tests the secwall.server.HTTPSProxy.__init__ method, that is passes
        the parameters correctly to the super-class.
        """
        _host = uuid.uuid4().hex
        _port = uuid.uuid4().hex
        _log = uuid.uuid4().hex
        _keyfile = uuid.uuid4().hex
        _certfile = uuid.uuid4().hex
        _ca_certs = uuid.uuid4().hex

        _app_ctx = app_ctx
        _cert_reqs = ssl.CERT_OPTIONAL

        class _Config(object):
            def __init__(self):
                self.host = _host
                self.port = _port
                self.log = _log
                self.keyfile = _keyfile
                self.certfile = _certfile
                self.ca_certs = _ca_certs
                self.urls = []

        _config = _Config()

        with Replacer() as r:

            def _init(self, listener, application, log, handler_class, keyfile,
                      certfile, ca_certs, cert_reqs):
                host, port = listener
                eq_(host, _host)
                eq_(port, _port)
                assert_true(isinstance(application, server._RequestApp))
                eq_(log, _log)
                eq_(handler_class, server._RequestHandler)
                eq_(keyfile, _keyfile)
                eq_(certfile, _certfile)
                eq_(ca_certs, _ca_certs)
                eq_(cert_reqs, _cert_reqs)

            r.replace('gevent.pywsgi.WSGIServer.__init__', _init)

            server.HTTPSProxy(_config, _app_ctx)

    def test_handle(self):
        """ The handle method should create an instance of the 'handler_class'
        and invoke the newly created instance's 'handle' method.
        """
        _host = uuid.uuid4().hex
        _port = uuid.uuid4().hex
        _log = uuid.uuid4().hex
        _keyfile = uuid.uuid4().hex
        _certfile = uuid.uuid4().hex
        _ca_certs = uuid.uuid4().hex

        _socket = uuid.uuid4().hex
        _address = uuid.uuid4().hex

        _cert_reqs = ssl.CERT_OPTIONAL

        class _Config(object):
            def __init__(self):
                self.host = _host
                self.port = _port
                self.log = _log
                self.keyfile = _keyfile
                self.certfile = _certfile
                self.ca_certs = _ca_certs
                self.urls = []

        class _RequestHandler(object):
            def __init__(self, socket, address, proxy):
                eq_(socket, _socket)
                eq_(address, _address)
                assert_true(isinstance(proxy, server.HTTPSProxy))

            def handle(self):
                pass

        class _Context(app_context.SecWallContext):
            @Object
            def wsgi_request_handler(self):
                return _RequestHandler

        _app_ctx = ApplicationContext(_Context())

        _config = _Config()

        with Replacer() as r:
            r.replace('secwall.server._RequestHandler', _RequestHandler)

            proxy = server.HTTPSProxy(_config, _app_ctx)
            proxy.handle(_socket, _address)

class HTTPRequestHandlerTestCase(unittest.TestCase):
    """ Tests related to the the secwall.server._HTTPRequestHandler class,
    a custom subclass of gevent.pywsgi.WSGIHandler which adds support for fetching
    client certificates and passing them to a WSGI application.
    """
    def test_handle_one_response_certs(self):
        """ Tests whether the overridden method returns client certificates.
        """
        for _cert in True, False:
            _data = uuid.uuid4().hex
            _env = {uuid.uuid4().hex:uuid.uuid4().hex}

            class _Socket(object):
                def __init__(self):
                    # Dynamically create the 'getpeercert' method depending on
                    # whether in this iteration the client cert should be
                    # returned or not.
                    if _cert:
                        def getpeercert():
                            return _cert
                        self.getpeercert = getpeercert

                def makefile(*ignored_args, **ignored_kwargs):
                    pass

            class _WSGIInput(object):
                def _discard(*ignored_args, **ignored_kwargs):
                    pass

            class _Server(object):
                def __init__(self, *ignored_args, **ignored_kwargs):
                    class _Log(object):
                        def write(*ignored_args, **ignored_kwargs):
                            pass
                    self.log = _Log()

            class _RequestApp(object):
                def __init__(self, config, app_ctx):
                    pass

                def __call__(self, environ, start_response, client_cert):
                    eq_(sorted(environ.items()), sorted(_env.items()))

                    expected_cert = _cert if _cert else None
                    eq_(client_cert, expected_cert)

                    start_response('200 OK', {})
                    return [_data]

            class _WFile(object):
                def __init__(self):
                    self.data = ''

                def writelines(self, data):
                    for datum in data:
                        self.data += datum

            _socket = _Socket()
            _server = _Server()
            _address = uuid.uuid4().hex
            _config = {}

            handler = server._RequestHandler(_socket, _address, _server)
            handler.application = _RequestApp(_config, app_ctx)
            handler.environ = _env
            handler.wsgi_input = _WSGIInput()
            handler.requestline = uuid.uuid4().hex
            handler.request_version = uuid.uuid4().hex
            handler.wfile = _WFile()
            handler.status = True
            handler.headers_sent = False
            handler.response_use_chunked = True

            handler.handle_one_response()

            # This will be equal to the expected value only if the
            # handler.application.__call__ above will have been succeeded.
            assert_true(handler.wfile.data.startswith(handler.request_version + ' ' + '200 OK'),
                        (handler.request_version, handler.wfile.data))

def test_loggers():
    """ Makes sure all the relevant classes define a logger object.
    """
    class _Config():
        def __init__(self):
            self.urls = []
            self.host = None
            self.port = None
            self.log = None
            self.keyfile = None
            self.certfile = None
            self.ca_certs = None

    config = _Config()

    request_app = server._RequestApp(config, app_ctx)
    http_proxy = server.HTTPProxy(config, app_ctx)
    https_proxy = server.HTTPSProxy(config, app_ctx)

    for o in request_app, http_proxy, https_proxy:
        assert_true((getattr(o, 'logger', None) is not None), o)
        assert_true(isinstance(getattr(o, 'logger'), logging.Logger), o)
