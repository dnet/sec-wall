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
import copy, cStringIO, hashlib, logging, ssl, sys, unittest, urllib, urllib2, uuid
from datetime import datetime
from logging.handlers import BufferingHandler

# lxml
from lxml import etree

# gevent
from gevent import wsgi

# PyYAML
from yaml import dump
try:
    from yaml import CDumper as Dumper
except ImportError:                      # pragma: no cover
    from yaml import Dumper              # pragma: no cover

# nose
from nose.tools import assert_false, assert_raises, assert_true, eq_

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
    def __init__(self, urls, _app_ctx=app_ctx):
        self.urls = urls
        self.no_url_match = _app_ctx.get_object('no_url_match')
        self.client_cert_401_www_auth = _app_ctx.get_object('client_cert_401_www_auth')
        self.validation_precedence = _app_ctx.get_object('validation_precedence')
        self.not_authorized = _app_ctx.get_object('not_authorized')
        self.forbidden = _app_ctx.get_object('forbidden')
        self.no_url_match = _app_ctx.get_object('no_url_match')
        self.internal_server_error = _app_ctx.get_object('internal_server_error')
        self.instance_name = _app_ctx.get_object('instance_name')
        self.INSTANCE_UNIQUE = uuid.uuid4().hex
        self.INSTANCE_SECRET = uuid.uuid4().hex
        self.quote_path_info = _app_ctx.get_object('quote_path_info')
        self.quote_query_string = _app_ctx.get_object('quote_query_string')
        self.server_tag = uuid.uuid4().hex
        self.from_backend_ignore = []
        self.add_invocation_id = True
        self.sign_invocation_id = True
        self.default_url_config = _default_url_config()
        self.add_default_if_not_found = True

class _DummyCertInfo(object):
    pass

def _start_response(*ignored_args, **ignored_kwargs):
    pass

def _dummy_invocation_context():
    ctx = core.InvocationContext()
    ctx.proc_start = datetime.now()
    ctx.auth_result = core.AuthResult()
    ctx.env = {}

    return ctx

class TestHandler(BufferingHandler):
    def __init__(self):
        BufferingHandler.__init__(self, 0)

    def shouldFlush(self):
        return False

    def emit(self, record):
        self.buffer.append(record.__dict__)

class _TestHeaders(object):
    def __init__(self, dict):
        self.dict = dict

def _default_url_config(*ignored_args, **ignored_kwargs):
    return {}
        
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
        
        path = '/' + uuid.uuid4().hex
        _config = _DummyConfig([[path, {}]])

        for cert in None, dummy_cert:
            with Replacer() as r:

                _env = {'PATH_INFO': path}
                _url_config = _config.urls

                def _on_request(self, ctx, start_response, env, url_config, client_cert, match):
                    assert_true(isinstance(ctx, core.InvocationContext))
                    eq_(start_response, _start_response)
                    eq_(sorted(env.items()), sorted(_env.items()))

                    eq_(client_cert, cert)

                r.replace('secwall.server._RequestApp._on_request', _on_request)

                req_app = server._RequestApp(_config, app_ctx)
                req_app(_env, _start_response, cert)

    def test_call_no_match(self):
        """ Tests how the __call__ method handles a non-matching URL.
        """
        config = _DummyConfig([])
        config.add_default_if_not_found = False

        with Replacer() as r:

            _env = {'PATH_INFO': uuid.uuid4().hex}

            def _404(self, ctx, start_response):
                assert_true(isinstance(ctx, core.InvocationContext))
                eq_(start_response, _start_response)

            r.replace('secwall.server._RequestApp._404', _404)

            req_app = server._RequestApp(config, app_ctx)
            req_app(_env, _start_response)

    def test_on_request_ssl_scheme_not_https(self):
        """ A URL should be accessed through HTTPS if the config says so.
        """
        with Replacer() as r:
            def _403(self, ctx, start_response):
                assert_true(isinstance(ctx, core.InvocationContext))
                eq_(start_response, _start_response)

            r.replace('secwall.server._RequestApp._403', _403)

            _url_config = {'ssl': True}
            _env = {'wsgi.url_scheme': uuid.uuid4().hex}

            req_app = server._RequestApp(self.config, app_ctx)
            req_app._on_request(_dummy_invocation_context(),
                                _start_response, _env, _url_config, None)

    def test_on_request_client_cert_required(self):
        """ A client certificate is required if config says so.
        """
        with Replacer() as r:
            def _401(self, ctx, start_response, www_auth):
                assert_true(isinstance(ctx, core.InvocationContext))
                eq_(start_response, _start_response)
                eq_(www_auth, app_ctx.get_object('client_cert_401_www_auth'))

            r.replace('secwall.server._RequestApp._401', _401)

            _url_config = {'ssl': True, 'ssl-cert': True}
            _env = {'wsgi.url_scheme': 'https'}

            req_app = server._RequestApp(self.config, app_ctx)
            req_app._on_request(_dummy_invocation_context(),
                                _start_response, _env, _url_config, None)

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

                    _host = 'http://z'
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

                            expected_headers = list(_headers.items())
                            eq_(sorted(headers), sorted(expected_headers))

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

                        def _401(self, ctx, start_response, www_auth):
                            pass

                        def _http_open(*ignored_args, **ignored_kwargs):
                            class _DummyResponse(object):
                                def __init__(self, *ignored_args, **ignored_kwargs):
                                    self.msg = _status
                                    self.headers = _headers
                                    self.code = _code

                                def info(*ignored_args, **ignored_kwargs):
                                    return _TestHeaders(_headers)

                                def readline(*ignored_args, **ignored_kwargs):
                                    return 'aaa'

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
                        r.replace('urllib2.HTTPHandler.http_open', _http_open)

                        try:
                            wsgi_input = cStringIO.StringIO()
                            wsgi_input.write(uuid.uuid4().hex)

                            _url_config = {'ssl': False, config_type:True, 'host':_host,
                                           'from-client-ignore':{}, 'to-backend-add':{}}

                            if config_type in('basic-auth', 'digest-auth', 'wsse-pwd'):
                                _url_config[config_type + '-realm'] = _realm

                            _env = {'wsgi.input':wsgi_input, 'PATH_INFO':_path_info}

                            req_app = server._RequestApp(self.config, app_ctx)
                            response = req_app._on_request(_dummy_invocation_context(),
                                                           _x_start_response, _env, _url_config, None)

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
        """ The _on_request method should return the response  even if it's not 200 OK.
        """
        with Replacer() as r:

            _host = 'http://' + uuid.uuid4().hex
            _path_info = '/' + uuid.uuid4().hex
            _username = uuid.uuid4().hex
            _password = uuid.uuid4().hex
            _realm = uuid.uuid4().hex
            _code = uuid.uuid4().hex
            _status = uuid.uuid4().hex
            _response = uuid.uuid4().hex
            _headers = {'Content-Type': uuid.uuid4().hex}

            def _x_start_response(code_status, headers):
                eq_(code_status, _code + ' ' + _status)
                expected_headers = _headers.items()
                eq_(sorted(headers), sorted(expected_headers))

            def _http_open(*ignored_args, **ignored_kwargs):
                class _DummyException(urllib2.HTTPError):
                    def __init__(self, *ignored_args, **ignored_kwargs):
                        self.msg = _status
                        self.headers = _TestHeaders(_headers)

                    def read(*ignored_args, **ignored_kwargs):
                        return _response

                    def getcode(*ignored_args, **ignored_kwargs):
                        return _code

                    def close(*ignored_args, **ignored_kwargs):
                        pass

                raise _DummyException()

            r.replace('urllib2.HTTPHandler.http_open', _http_open)

            wsgi_input = cStringIO.StringIO()

            try:
                wsgi_input.write(uuid.uuid4().hex)

                _url_config = {'basic-auth':True, 'host':_host,
                               'from-client-ignore':{}, 'to-backend-add':{}}
                _url_config['basic-auth-username'] = _username
                _url_config['basic-auth-password'] = _password
                _url_config['basic-auth-realm'] = _realm

                auth = 'Basic ' + (_username + ':' + _password).encode('base64')

                _env = {'wsgi.input':wsgi_input, 'PATH_INFO':_path_info,
                        'HTTP_AUTHORIZATION':auth}

                req_app = server._RequestApp(self.config, app_ctx)
                response = req_app._on_request(_dummy_invocation_context(),
                                               _x_start_response, _env, _url_config, None)
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
        _code, _status, _response = (uuid.uuid4().hex for x in range(3))

        _headers = {uuid.uuid4().hex: uuid.uuid4().hex}
        _headers['X-sec-wall-invocation-id-signed'] = ''
        _headers['X-sec-wall-invocation-id'] = 'None/None/None'

        def _start_response(code_status, headers):
            eq_(code_status, _code + ' ' + _status)

            eq_(sorted(headers), sorted(_headers.items()))

        req_app = server._RequestApp(self.config, app_ctx)

        response = req_app._response(_dummy_invocation_context(),
                                     _start_response, _code, _status, _headers, _response)
        eq_(response, [_response])

    def test_401(self):
        """ Tests the '_401' method.
        """
        www_auth = uuid.uuid4().hex

        _ctx  =_dummy_invocation_context()
        _code, _status, _content_type, _description = app_ctx.get_object('not_authorized')

        with Replacer() as r:

            def _response(self, ctx, start_response, code, status, headers, response):
                eq_(ctx, _ctx)
                eq_(start_response, _start_response)
                eq_(code, _code)
                eq_(status, _status)
                eq_(sorted(headers.items()), [('Content-Type', _content_type), ('WWW-Authenticate', www_auth)])
                eq_(response, _description)

            r.replace('secwall.server._RequestApp._response', _response)

            req_app = server._RequestApp(self.config, app_ctx)
            req_app._401(_ctx, _start_response, www_auth)

    def test_403(self):
        """ Tests the '_403' method.
        """
        _code, _status, _content_type, _description = app_ctx.get_object('forbidden')
        _ctx = _dummy_invocation_context()

        with Replacer() as r:

            def _response(self, ctx, start_response, code, status, headers, response):
                eq_(ctx, _ctx)
                eq_(start_response, _start_response)
                eq_(code, _code)
                eq_(status, _status)
                eq_(sorted(headers.items()), [('Content-Type', _content_type)])
                eq_(response, _description)

            r.replace('secwall.server._RequestApp._response', _response)

            req_app = server._RequestApp(self.config, app_ctx)
            req_app._403(_ctx, _start_response)

    def test_404(self):
        """ Tests the '_404' method.
        """
        _code, _status, _content_type, _description = app_ctx.get_object('no_url_match')
        _ctx = _dummy_invocation_context()

        with Replacer() as r:

            def _response(self, ctx, start_response, code, status, headers, response):
                eq_(ctx, _ctx)
                eq_(start_response, _start_response)
                eq_(code, _code)
                eq_(status, _status)
                eq_(sorted(headers.items()), [('Content-Type', _content_type)])
                eq_(response, _description)

            r.replace('secwall.server._RequestApp._response', _response)

            req_app = server._RequestApp(self.config, app_ctx)
            req_app._404(_ctx, _start_response)

    def test_500(self):
        """ Tests the '_500' method.
        """
        _code, _status, _content_type, _description = app_ctx.get_object('internal_server_error')
        _ctx = _dummy_invocation_context()

        with Replacer() as r:

            def _response(self, ctx, start_response, code, status, headers, response):
                eq_(ctx, _ctx)
                eq_(start_response, _start_response)
                eq_(code, _code)
                eq_(status, _status)
                eq_(sorted(headers.items()), [('Content-Type', _content_type)])
                eq_(response, _description)

            r.replace('secwall.server._RequestApp._response', _response)

            req_app = server._RequestApp(self.config, app_ctx)
            req_app._500(_ctx, _start_response)

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
                return uuid.uuid4().hex, uuid.uuid4().hex

            r.replace('lxml.etree.fromstring', _fromstring)
            r.replace('secwall.wsse.WSSE.validate', _validate)

            req_app = server._RequestApp(self.config, app_ctx)

            auth_result = req_app._on_wsse_pwd(_env, _url_config, _unused_client_cert, _data)
            eq_(True, auth_result.status)
            eq_('0', auth_result.code)

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

            auth_result = request_app._on_digest_auth(env, url_config)
            eq_(True, auth_result.status)
            eq_('0', auth_result.code)

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
        eq_(constants.AUTH_CUSTOM_HTTP_NO_HEADER, auth_result.code)

        # 2) All headers were sent yet their values were incorrect
        env = {'HTTP_' + name1.upper().replace('-', '_'):uuid.uuid4().hex,
               'HTTP_' + name2.upper().replace('-', '_'):uuid.uuid4().hex}

        auth_result = request_app._on_custom_http(env, url_config)
        eq_(False, auth_result.status)
        eq_(constants.AUTH_CUSTOM_HTTP_HEADER_MISMATCH, auth_result.code)

        # 4) One header's correct (including its value), the other has incorrect
        # name and value.
        env = {'HTTP_' + name1.upper().replace('-', '_'):value1,
               uuid.uuid4().hex:uuid.uuid4().hex}

        auth_result = request_app._on_custom_http(env, url_config)
        eq_(False, auth_result.status)
        eq_(constants.AUTH_CUSTOM_HTTP_NO_HEADER, auth_result.code)

        # 4) One header's correct (including its value), the other has incorrect
        # value despite its name being correct.
        env = {'HTTP_' + name1.upper().replace('-', '_'):value1,
               'HTTP_' + name2.upper().replace('-', '_'):uuid.uuid4().hex}

        auth_result = request_app._on_custom_http(env, url_config)
        eq_(False, auth_result.status)
        eq_(constants.AUTH_CUSTOM_HTTP_HEADER_MISMATCH, auth_result.code)

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

        auth_result = request_app._on_custom_http(env, url_config)
        eq_(True, auth_result.status)
        eq_('0', auth_result.code)

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

        auth_result = request_app._on_xpath(env, url_config, client_cert, self.sample_xml)
        eq_(True, auth_result.status)
        eq_('0', auth_result.code)

    def test_log_quotting(self):
        """ When told to be so in the config, the logging messages should
        be URL-quoted.
        """
        for _quote_path_info in(True, False):
            for _quote_query_string in(True, False):

                _config = copy.deepcopy(self.config)
                _config.quote_path_info = _quote_path_info
                _config.quote_query_string = _quote_query_string

                _app_ctx = ApplicationContext(app_context.SecWallContext())
                request_app = server._RequestApp(_config, _app_ctx)

                handler = TestHandler()
                request_app.logger.addHandler(handler)

                _wsgi_input = cStringIO.StringIO()
                _wsgi_input.write('')

                path_info = uuid.uuid4().hex + '!@#$%^&*()'
                query_string = uuid.uuid4().hex + '!@#$%^&*()'

                _env = {'PATH_INFO':path_info, 'QUERY_STRING':query_string,
                        'wsgi.input':_wsgi_input}

                request_app(_env, _start_response)

                log_message = handler.buffer[0]['msg']
                log_message = log_message.split(';')

                _path = log_message[4]

                if _quote_path_info and _quote_query_string:
                    expected = 'None ' + urllib.quote_plus(path_info + '?' + query_string)
                elif(not _quote_path_info) and _quote_query_string:
                    expected = 'None ' + path_info + urllib.quote_plus('?' + query_string)
                elif _quote_path_info and (not _quote_query_string):
                    expected = 'None ' + urllib.quote_plus(path_info) + '?' + query_string
                elif(not _quote_path_info) and (not _quote_query_string):
                    expected = 'None ' + path_info + '?' + query_string

                eq_(_path, expected)

    def test_response_needs_details(self):
        """ The amount of log details depends on what 'self._response' says
        should be logged.
        """
        for auth_result in(True, False):
            for log_level in(logging.ERROR, logging.DEBUG):
                _app_ctx = ApplicationContext(app_context.SecWallContext())

                _wsgi_input = cStringIO.StringIO()
                _wsgi_input.write('')

                path_info = uuid.uuid4().hex
                query_string = uuid.uuid4().hex

                _env = {'PATH_INFO':path_info, 'QUERY_STRING':query_string,
                        'wsgi.input':_wsgi_input}

                _ctx = core.InvocationContext()
                _ctx.proc_start = datetime.now()
                _ctx.auth_result = core.AuthResult(auth_result)
                _ctx.env = _env

                handler = TestHandler()

                request_app = server._RequestApp(self.config, _app_ctx)
                request_app.logger.addHandler(handler)
                request_app.log_level = log_level
                request_app._response(_ctx, _start_response, uuid.uuid4().hex,
                                      uuid.uuid4().hex, {}, uuid.uuid4().hex)

                log_message = handler.buffer[0]['msg'].split(';')
                len_log_message = len(log_message)

                # No details expected.
                if log_level == logging.ERROR and auth_result is not False:
                    expected_len = 10
                elif auth_result is True and log_level != logging.DEBUG:
                    expected_len = 10
                else:
                    expected_len = 16

                eq_(len_log_message, expected_len, (logging.getLevelName(log_level),
                                          logging.getLevelName(request_app.log_level),
                                          auth_result, len_log_message, expected_len,
                                          log_message))

    def test_from_client_ignore(self):
        """ Tests whether headers from the 'from-client-ignore' list aren't being
        passed to backend servers.
        """
        request_app = server._RequestApp(self.config, app_ctx)
        _client_cert = None
        _url_config = {'custom-http':True, 'host':'http://' + uuid.uuid4().hex}
        _url_config['to-backend-add'] = {}

        # Of two headers created, one will be added to the 'from-client-ignore'
        # list hence it's expected not to be passed to the backend server.
        k1, v1 = uuid.uuid4().hex, uuid.uuid4().hex
        k2, v2 = uuid.uuid4().hex.capitalize(), uuid.uuid4().hex
        _env = {'HTTP_' + k1: v1, 'HTTP_' + k2: v2}
        _url_config['from-client-ignore'] = [k1]

        _wsgi_input = cStringIO.StringIO()
        _wsgi_input.write('')
        _env['wsgi.input'] = _wsgi_input
        _env['PATH_INFO'] = '/' + uuid.uuid4().hex

        _ctx = core.InvocationContext()
        _ctx.proc_start = datetime.now()
        _ctx.auth_result = core.AuthResult(True)
        _ctx.env = _env
        
        _config = self.config

        def start_response(*ignored_args, **ignored_kwargs):
            pass

        def _on_custom_http(*ignored_args, **ignored_kwargs):
            return core.AuthResult(True)

        def _http_open(handler, request):
            
            expected_auth_info_signed = hashlib.sha256()
            expected_auth_info_signed.update('{0}:{1}:{2}'.format(_ctx.invocation_id, 
                                    _config.INSTANCE_SECRET,  ''))
            expected_auth_info_signed = expected_auth_info_signed.hexdigest()

            # 'k1' and 'v1' must not be passed to backend server because 'k1'
            # is on the 'from-client-ignore' list.
            eq_(sorted(request.headers.items()), [
                (k2, v2),
                ('X-sec-wall-auth-info', ''),
                ('X-sec-wall-auth-info-signed', expected_auth_info_signed),
                ('X-sec-wall-invocation-id', 'None/None/None'),
                ('X-sec-wall-invocation-id-signed', '')
            ])

            class _DummyResponse(object):
                def __init__(self, *ignored_args, **ignored_kwargs):
                    self.msg = ''
                    self.headers = ''
                    self.code = ''

                def info(*ignored_args, **ignored_kwargs):
                    return _TestHeaders({})

                def readline(*ignored_args, **ignored_kwargs):
                    return 'aaa'

                def read(*ignored_args, **ignored_kwargs):
                    return ''

                def getcode(*ignored_args, **ignored_kwargs):
                    return '200'

                def close(*ignored_args, **ignored_kwargs):
                    pass

            return _DummyResponse()

        with Replacer() as r:
            r.replace('secwall.server._RequestApp._on_custom_http', _on_custom_http)
            r.replace('urllib2.HTTPHandler.http_open', _http_open)
            request_app._on_request(_ctx, start_response, _env, _url_config, _client_cert)

    def test_to_backend_add(self):
        """ Tests whether headers from the 'to-backend-add' dictionary are being
        passed to backend servers.
        """
        request_app = server._RequestApp(self.config, app_ctx)
        _client_cert = None
        _url_config = {'custom-http':True, 'host':'http://' + uuid.uuid4().hex}
        k1, v1 = uuid.uuid4().hex.capitalize(), uuid.uuid4().hex
        _url_config['to-backend-add'] = {k1:v1}

        _env = {}
        _url_config['from-client-ignore'] = []

        _wsgi_input = cStringIO.StringIO()
        _wsgi_input.write('')
        _env['wsgi.input'] = _wsgi_input
        _env['PATH_INFO'] = '/' + uuid.uuid4().hex

        _ctx = core.InvocationContext()
        _ctx.proc_start = datetime.now()
        _ctx.auth_result = core.AuthResult(True)
        _ctx.env = _env
        
        _config = self.config

        def start_response(*ignored_args, **ignored_kwargs):
            pass

        def _on_custom_http(*ignored_args, **ignored_kwargs):
            return core.AuthResult(True)

        def _http_open(handler, request):

            expected_auth_info_signed = hashlib.sha256()
            expected_auth_info_signed.update('{0}:{1}:{2}'.format(_ctx.invocation_id, 
                                    _config.INSTANCE_SECRET,  ''))
            
            expected_auth_info_signed = expected_auth_info_signed.hexdigest()
            
            eq_(sorted(request.headers.items()), [
                (k1, v1),
                ('X-sec-wall-auth-info', ''),
                ('X-sec-wall-auth-info-signed', expected_auth_info_signed),
                ('X-sec-wall-invocation-id', 'None/None/None'),
                ('X-sec-wall-invocation-id-signed', '')
            ])

            class _DummyResponse(object):
                def __init__(self, *ignored_args, **ignored_kwargs):
                    self.msg = ''
                    self.code = ''

                def info(*ignored_args, **ignored_kwargs):
                    return _TestHeaders({})

                def readline(*ignored_args, **ignored_kwargs):
                    return 'aaa'

                def read(*ignored_args, **ignored_kwargs):
                    return ''

                def getcode(*ignored_args, **ignored_kwargs):
                    return '200'

                def close(*ignored_args, **ignored_kwargs):
                    pass

            return _DummyResponse()

        with Replacer() as r:
            r.replace('secwall.server._RequestApp._on_custom_http', _on_custom_http)
            r.replace('urllib2.HTTPHandler.http_open', _http_open)
            request_app._on_request(_ctx, start_response, _env, _url_config, _client_cert)

    def test_from_backend_ignore(self):
        """ Tests whether headers from the 'from-backend-ignore' list aren't being
        passed to clients.
        """
        request_app = server._RequestApp(self.config, app_ctx)
        _client_cert = None
        _url_config = {}
        k1, v1 = 'a' + uuid.uuid4().hex.capitalize(), uuid.uuid4().hex
        k2, v2 = 'b' + uuid.uuid4().hex.capitalize(), uuid.uuid4().hex

        _env = {}
        _url_config['to-client-add'] = {}
        _url_config['from-backend-ignore'] = [k1]

        _wsgi_input = cStringIO.StringIO()
        _wsgi_input.write('')
        _env['wsgi.input'] = _wsgi_input
        _env['PATH_INFO'] = '/' + uuid.uuid4().hex

        _ctx = core.InvocationContext()
        _ctx.proc_start = datetime.now()
        _ctx.auth_result = core.AuthResult(True)
        _ctx.env = _env
        _ctx.url_config = _url_config

        def start_response(code_status, headers):
            eq_(sorted(headers), [
                ('X-sec-wall-invocation-id', 'None/None/None'),
                ('X-sec-wall-invocation-id-signed', ''),
                (k2, v2)
            ])

        headers = {k1:v1, k2:v2}
        response = uuid.uuid4().hex

        request_app._response(_ctx, start_response, '200', 'OK', headers, response)

    def test_to_client_add(self):
        """ Tests whether headers from the 'to-client-add' dictionary are being
        passed to clients.
        """
        request_app = server._RequestApp(self.config, app_ctx)
        _client_cert = None
        _url_config = {}
        k1, v1 = 'a' + uuid.uuid4().hex.capitalize(), uuid.uuid4().hex
        k2, v2 = 'b' + uuid.uuid4().hex.capitalize(), uuid.uuid4().hex

        _env = {}
        _url_config['to-client-add'] = {k2:v2}
        _url_config['from-backend-ignore'] = []

        _wsgi_input = cStringIO.StringIO()
        _wsgi_input.write('')
        _env['wsgi.input'] = _wsgi_input
        _env['PATH_INFO'] = '/' + uuid.uuid4().hex

        _ctx = core.InvocationContext()
        _ctx.proc_start = datetime.now()
        _ctx.auth_result = core.AuthResult(True)
        _ctx.env = _env
        _ctx.url_config = _url_config

        def start_response(code_status, headers):
            eq_(sorted(headers), [
                ('X-sec-wall-invocation-id', 'None/None/None'),
                ('X-sec-wall-invocation-id-signed', ''),
                (k1, v1), (k2, v2)
            ])

        headers = {k1:v1}
        response = uuid.uuid4().hex

        request_app._response(_ctx, start_response, '200', 'OK', headers, response)

    def test_adding_server_header(self):
        """ By default, if not configured otherwise, the 'Server' header has a special
        status and is being added to the list of headers sent to a client app.
        """
        _config = copy.deepcopy(self.config)
        _config.from_backend_ignore = ['Server']

        request_app = server._RequestApp(_config, app_ctx)
        _client_cert = None

        _env = {}

        _wsgi_input = cStringIO.StringIO()
        _wsgi_input.write('')
        _env['wsgi.input'] = _wsgi_input
        _env['PATH_INFO'] = '/' + uuid.uuid4().hex

        _ctx = core.InvocationContext()
        _ctx.proc_start = datetime.now()
        _ctx.auth_result = core.AuthResult(True)
        _ctx.env = _env
        _ctx.url_config = None

        def start_response(code_status, headers):
            eq_(sorted(headers), [
                ('Server', request_app.server_tag),
                ('X-sec-wall-invocation-id', 'None/None/None'),
                ('X-sec-wall-invocation-id-signed', ''),
            ])

        response = uuid.uuid4().hex
        request_app._response(_ctx, start_response, '200', 'OK', {}, response)

    def test_add_invocation_id(self):
        """ When configured to do so, the proxy should add a 'X-sec-wall-invocation-id'
        HTTP header when invoking backend servers and returning responses to client
        applications.
        """
        for add_invocation_id in(True, False):
            for sign_invocation_id in(True, False):
                with Replacer() as r:
                    _config = copy.deepcopy(self.config)
                    _config.add_invocation_id = add_invocation_id
                    _config.sign_invocation_id = sign_invocation_id
                    _config.from_backend_ignore = ['Server']

                    request_app = server._RequestApp(_config, app_ctx)

                    _env = {}

                    _wsgi_input = cStringIO.StringIO()
                    _wsgi_input.write('')

                    _env['wsgi.input'] = _wsgi_input
                    _env['PATH_INFO'] = '/' + uuid.uuid4().hex

                    def start_response(code_status, headers):
                        headers = dict(headers)
                        eq_(headers['Content-Type'], 'text/plain')

                        if add_invocation_id:
                            eq_(len(headers['X-sec-wall-invocation-id'].split('/')), 3)
                        else:
                            assert_false(('X-sec-wall-invocation-id' in headers), headers)

                        if sign_invocation_id:
                            eq_(len(headers['X-sec-wall-invocation-id-signed']), 64)
                        else:
                            assert_false(('X-sec-wall-invocation-id-signed' in headers), headers)

                    request_app(_env, start_response)

        for add_invocation_id in(True, False):
            for sign_invocation_id in(True, False):
                with Replacer() as r:
                    _config = copy.deepcopy(self.config)
                    _config.add_invocation_id = add_invocation_id
                    _config.sign_invocation_id = sign_invocation_id
                    _config.from_backend_ignore = ['Server']

                    _url_config = {'custom-http':True, 'host':'http://' + uuid.uuid4().hex,
                                   'from-client-ignore':[], 'to-backend-add':{}}

                    request_app = server._RequestApp(_config, app_ctx)

                    _env = {}

                    instance_name = uuid.uuid4().hex
                    instance_unique = uuid.uuid4().hex
                    message_number = uuid.uuid4().hex
                    invocation_id_signed = uuid.uuid4().hex

                    _ctx = core.InvocationContext(instance_name, instance_unique, message_number)
                    _ctx.proc_start = datetime.now()
                    _ctx.auth_result = core.AuthResult(True)
                    _ctx.env = _env

                    if sign_invocation_id:
                        _ctx.invocation_id_signed = invocation_id_signed

                    _wsgi_input = cStringIO.StringIO()
                    _wsgi_input.write('')

                    _env['wsgi.input'] = _wsgi_input
                    _env['PATH_INFO'] = '/' + uuid.uuid4().hex

                    def start_response(code_status, headers):
                        pass

                    def _on_custom_http(*ignored_args, **ignored_kwargs):
                        return core.AuthResult(True)

                    def _http_open(self, req):

                        if add_invocation_id:
                            eq_(req.headers['X-sec-wall-invocation-id'],
                                '{0}/{1}/{2}'.format(instance_name, instance_unique, message_number))

                        if sign_invocation_id:
                            eq_(req.headers['X-sec-wall-invocation-id-signed'], invocation_id_signed)

                        class _DummyResponse(object):
                            def __init__(self, *ignored_args, **ignored_kwargs):
                                self.code = '200'
                                self.msg = 'OK'
                                self._headers = {}

                            def info(*ignored_args, **ignored_kwargs):
                                return _TestHeaders({})

                            def readline(*ignored_args, **ignored_kwargs):
                                return 'aaa'

                            def read(*ignored_args, **ignored_kwargs):
                                return ''

                            def getcode(*ignored_args, **ignored_kwargs):
                                return self.code

                            def close(*ignored_args, **ignored_kwargs):
                                pass

                        return _DummyResponse()

                    def start_response(code_status, headers):
                        pass

                    r.replace('urllib2.HTTPHandler.http_open', _http_open)
                    r.replace('secwall.server._RequestApp._on_custom_http', _on_custom_http)
                    request_app._on_request(_ctx, start_response, _env, _url_config, None)

    def test_add_sign_auth_info(self):
        """ Tests if adding and signing the auth info works OK.
        """
        
        class TestData(object):
            def __init__(self, fields, expected):
                self.fields = fields
                self.expected = expected

        ssl_fields = {
            'ssl-cert':True,
            'ssl-cert-commonName':'foobar-baz',
            'ssl-cert-serialNumber': '12345678',
            'ssl-cert-localityName':'Mountain View'
        }
        ssl_expected = "{ssl-cert-commonName: foobar-baz, ssl-cert-localityName: Mountain+View, ssl-cert-serialNumber: '12345678'}\n"
                
        wsse_fields = {
            'wsse-pwd':True,
            'wsse-pwd-username': b'zxc',
            'wsse-pwd-password': b'asd',
            'wsse-pwd-realm':b'zxc',
            'wsse-pwd-reject-empty-nonce-creation': True,
            'wsse-pwd-reject-stale-tokens': True,
            'wsse-pwd-reject-expiry-limit': sys.maxint,
            'wsse-pwd-nonce-freshness-time': sys.maxint,
            'wsse-pwd-password-digest': False
        }
        wsse_username = wsse_fields['wsse-pwd-username']
        wsse_expected = b"{{wsse-pwd-username: {0}}}\n".format(str(wsse_username))
        wsse_request = """<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:typ="http://example.org/math/types/">
        <soapenv:Header>
           <wsse:Security soapenv:mustUnderstand="1" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
              <wsse:UsernameToken wsu:Id="UsernameToken-6" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
                 <wsse:Username>zxc</wsse:Username>
                 <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">asd</wsse:Password>
                 <wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">iF0Cavy0XdAyZZargXtCdQ==</wsse:Nonce>
                 <wsu:Created>2011-01-16T22:19:56.722Z</wsu:Created>
              </wsse:UsernameToken>
           </wsse:Security>
        </soapenv:Header>
        <soapenv:Body>
           <typ:Add>
              <x>aaa</x>
              <y>bbb</y>
           </typ:Add>
        </soapenv:Body>
     </soapenv:Envelope>
"""
        basic_auth_fields = {
            'basic-auth':True,
            'basic-auth-realm':'zxc',
            'basic-auth-username':'foo foo',
            'basic-auth-password':'bar',
        }
        basic_auth_username = basic_auth_fields['basic-auth-username']
        basic_auth_expected = b"{{basic-auth-username: {0}}}\n".format(
            urllib.quote_plus(str(basic_auth_username)))
        
        custom_http_fields = {
            'custom-http':True,
            'custom-http-foo':'foo foo',
            'custom-http-bar':'bar',
        }
        custom_http_foo = custom_http_fields['custom-http-foo']
        custom_http_bar = custom_http_fields['custom-http-bar']
        custom_http_expected = b"{{custom-http-bar: {0}, custom-http-foo: {1}}}\n".format(
            custom_http_bar, custom_http_foo)
        
        xpath_fields = {
            'xpath':True,
            'xpath-x':etree.XPath("//x/text() = 'aaa'"),
            'xpath-y':etree.XPath("//y/text() = 'bbb'"),
        }
        xpath_x = xpath_fields['xpath-x']
        xpath_y = xpath_fields['xpath-y']
        xpath_expected = b"[{0}, {1}]\n".format(xpath_y, xpath_x)
        
        ssl_data = TestData(ssl_fields, ssl_expected)
        wsse_data = TestData(wsse_fields, wsse_expected)
        basic_auth_data = TestData(basic_auth_fields, basic_auth_expected)
        custom_http_data = TestData(custom_http_fields, custom_http_expected)
        xpath_data = TestData(xpath_fields, xpath_expected)
        
        for data in [ssl_data, wsse_data, basic_auth_data, custom_http_data, xpath_data]:
        
            with Replacer() as r:
                _env = {}
    
                _wsgi_input = cStringIO.StringIO()
                _wsgi_input.write(wsse_request)
                _wsgi_input.seek(0)
                
                _env['wsgi.input'] = _wsgi_input
                _env['PATH_INFO'] = '/' + uuid.uuid4().hex
                
                _env['HTTP_' + 'foo'.upper().replace('-', '_')] = 'foo foo'
                _env['HTTP_' + 'bar'.upper().replace('-', '_')] = 'bar'
                
                basic_auth = 'Basic ' + ('foo foo' + ':' + 'bar').encode('base64')
                _env['HTTP_AUTHORIZATION'] = basic_auth
    
                _url_config = {
                    'host':'http://' + uuid.uuid4().hex,
                    'from-client-ignore':[],
                    'to-backend-add':{}
                }
                
                _url_config.update(data.fields)
                
                instance_name, instance_unique, message_number = (uuid.uuid4().hex, uuid.uuid4().hex,
                                              uuid.uuid4().hex)
                
                _ctx = core.InvocationContext(instance_name, instance_unique, message_number)
    
                request_app = server._RequestApp(self.config, app_ctx)
                _config = self.config
    
                def _http_open(self, req):
    
                    expected_auth_info_signed = hashlib.sha256()
                    expected_auth_info_signed.update('{0}:{1}:{2}'.format(_ctx.invocation_id, 
                                            _config.INSTANCE_SECRET,  data.expected))
                    expected_auth_info_signed = expected_auth_info_signed.hexdigest()
    
                    auth_info = req.headers['X-sec-wall-auth-info']
                    auth_info_signed = req.headers['X-sec-wall-auth-info-signed']
    
                    eq_(auth_info, data.expected)
                    eq_(auth_info_signed, expected_auth_info_signed)
                    
                    class _DummyResponse(object):
                        def __init__(self, *ignored_args, **ignored_kwargs):
                            self.code = '200'
                            self.msg = 'OK'
                            self._headers = {}
    
                        def info(*ignored_args, **ignored_kwargs):
                            return _TestHeaders({})
    
                        def readline(*ignored_args, **ignored_kwargs):
                            return 'aaa'
    
                        def read(*ignored_args, **ignored_kwargs):
                            return ''
    
                        def getcode(*ignored_args, **ignored_kwargs):
                            return self.code
    
                        def close(*ignored_args, **ignored_kwargs):
                            pass
    
                    return _DummyResponse()
    
                def start_response(code_status, headers):
                    pass
    
                def _on_ssl_cert(*ignored_args, **ignored_kwargs):
                    auth_result = core.AuthResult(True)
                    auth_result.auth_info = dict((urllib.quote_plus(k), urllib.quote_plus(v)) for k, v in data.fields.iteritems() if not type(v) is bool)
                    return auth_result
    
                _ctx.proc_start = datetime.now()
                _ctx.auth_result = core.AuthResult(True)
                _ctx.env = _env
    
                r.replace('urllib2.HTTPHandler.http_open', _http_open)
                r.replace('secwall.server._RequestApp._on_ssl_cert', _on_ssl_cert)
                request_app._on_request(_ctx, start_response, _env, _url_config, None)
                
    def test_url_rewriting(self):
        """ Tests whether URL rewriting works OK.
        """
        with Replacer() as r:
            
            _host = 'http://' + uuid.uuid4().hex
            _username = uuid.uuid4().hex
            _password = uuid.uuid4().hex
            _realm = uuid.uuid4().hex
            
            pattern = '/myfoo/<foo:int>/mybar/<bar:unicode>/'
            
            _url_config = {'basic-auth':True, 'host':_host, 'from-client-ignore':[], 'to-backend-add':{}}
            _url_config['basic-auth-username'] = _username
            _url_config['basic-auth-password'] = _password
            _url_config['basic-auth-realm'] = _realm
            _url_config['rewrite'] = '/rewritten-foo/{foo}/rewritten-bar/{bar}/'
            
            config = _DummyConfig([[pattern, _url_config]])

            _path_info = '/myfoo/123/mybar/zxc/'
            _code = uuid.uuid4().hex
            _status = uuid.uuid4().hex
            _response = uuid.uuid4().hex
            _headers = {'Content-Type': uuid.uuid4().hex}
            
            def _x_start_response(code_status, headers):
                pass

            def _http_open(*args, **ignored_kwargs):
                req = args[1]
                eq_(req.get_full_url(), _host + '/rewritten-foo/123/rewritten-bar/zxc/')
                
                class _DummyResponse(object):
                    def __init__(self, *ignored_args, **ignored_kwargs):
                        self.msg = _status
                        self._headers = _headers
                        self.code = _code

                    def info(*ignored_args, **ignored_kwargs):
                        return _TestHeaders(_headers)

                    def readline(*ignored_args, **ignored_kwargs):
                        return 'aaa'

                    def read(*ignored_args, **ignored_kwargs):
                        return _response

                    def getcode(*ignored_args, **ignored_kwargs):
                        return _code

                    def close(*ignored_args, **ignored_kwargs):
                        pass

                return _DummyResponse()

            r.replace('urllib2.HTTPHandler.http_open', _http_open)

            wsgi_input = cStringIO.StringIO()

            try:
                wsgi_input.write(uuid.uuid4().hex)

                auth = 'Basic ' + (_username + ':' + _password).encode('base64')
                _env = {'HTTP_AUTHORIZATION': auth, 'PATH_INFO':_path_info,
                        'wsgi.input':wsgi_input}
                
                req_app = server._RequestApp(config, app_ctx)
                req_app(_env, _x_start_response, None)

            finally:
                wsgi_input.close()
                
    def test_wrap_only_ok(self):
        """ Tests whether SSL wrapping only, without any auth schemes, works OK.
        """
        with Replacer() as r:
            
            pattern = '/foo'
            _host = 'https://' + uuid.uuid4().hex
            _url_config = {'ssl':True, 'ssl-wrap-only':True, 'host':_host}
            
            _code = uuid.uuid4().hex
            _status = uuid.uuid4().hex
            _response = uuid.uuid4().hex
            _headers = {'Content-Type': uuid.uuid4().hex}
            
            config = _DummyConfig([[pattern, _url_config]])
            
            expected_url = _host + pattern
            
            def _x_start_response(code_status, headers):
                pass
            
            def _x_response(self, ctx, *ignored):
                eq_(ctx.auth_result.status, True)
                eq_(ctx.auth_result.code, '0')
            
            def _do_open(*args, **ignored_kwargs):
                req = args[2]
                eq_(expected_url, req.get_full_url())
                
                class _DummyResponse(object):
                    def __init__(self, *ignored_args, **ignored_kwargs):
                        self.msg = _status
                        self._headers = _headers
                        self.code = _code

                    def info(*ignored_args, **ignored_kwargs):
                        return _TestHeaders(_headers)

                    def readline(*ignored_args, **ignored_kwargs):
                        return 'aaa'

                    def read(*ignored_args, **ignored_kwargs):
                        return _response

                    def getcode(*ignored_args, **ignored_kwargs):
                        return _code

                    def close(*ignored_args, **ignored_kwargs):
                        pass

                return _DummyResponse()

            r.replace('urllib2.AbstractHTTPHandler.do_open', _do_open)
            r.replace('secwall.server._RequestApp._response', _x_response)

            wsgi_input = cStringIO.StringIO()

            try:
                wsgi_input.write(uuid.uuid4().hex)

                _path_info = '/foo'
                _env = {'PATH_INFO':_path_info, 'wsgi.input':wsgi_input,
                        'wsgi.url_scheme':'https'}
                
                req_app = server._RequestApp(config, app_ctx)
                req_app(_env, _x_start_response, None)

            finally:
                wsgi_input.close()
                
    def test_wrap_only_403_on_no_ssl(self):
        """ HTTP 403 status code should be returned when 'ssl-wrap-only' yet
        'ssl' is anything but True.
        """
        pattern = '/foo'
        _host = 'https://' + uuid.uuid4().hex
        _url_config = {'ssl-wrap-only':True, 'host':_host}
        config = _DummyConfig([[pattern, _url_config]])
        
        expected_url = _host + pattern
        
        def _x_start_response(code_status, headers):
            eq_(code_status, '403 Forbidden')

        wsgi_input = cStringIO.StringIO()

        try:
            wsgi_input.write(uuid.uuid4().hex)

            _path_info = '/foo'
            _env = {'PATH_INFO':_path_info, 'wsgi.input':wsgi_input,
                    'wsgi.url_scheme':'https'}
            
            req_app = server._RequestApp(config, app_ctx)
            req_app(_env, _x_start_response, None)

        finally:
            wsgi_input.close()

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
                self.instance_name = app_ctx.get_object('instance_name')
                self.INSTANCE_UNIQUE = uuid.uuid4().hex
                self.INSTANCE_SECRET = uuid.uuid4().hex
                self.quote_path_info = app_ctx.get_object('quote_path_info')
                self.quote_query_string = app_ctx.get_object('quote_query_string')
                self.server_tag = uuid.uuid4().hex
                self.from_backend_ignore = []
                self.add_invocation_id = True
                self.sign_invocation_id = True
                self.default_url_config = _default_url_config()
                self.add_default_if_not_found = True

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
        _instance_name = uuid.uuid4().hex
        _INSTANCE_UNIQUE = uuid.uuid4().hex
        _INSTANCE_SECRET = uuid.uuid4().hex
        _quote_path_info = uuid.uuid4().hex
        _quote_query_string = uuid.uuid4().hex

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
                self.instance_name = _instance_name
                self.INSTANCE_UNIQUE = _INSTANCE_UNIQUE
                self.INSTANCE_SECRET = _INSTANCE_SECRET
                self.quote_path_info = _quote_path_info
                self.quote_query_string = _quote_query_string
                self.server_tag = uuid.uuid4().hex
                self.from_backend_ignore = []
                self.add_invocation_id = True
                self.sign_invocation_id = True
                self.default_url_config = _default_url_config()
                self.add_default_if_not_found = True

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
                self.instance_name = app_ctx.get_object('instance_name')
                self.INSTANCE_UNIQUE = uuid.uuid4().hex
                self.INSTANCE_SECRET = uuid.uuid4().hex
                self.quote_path_info = app_ctx.get_object('quote_path_info')
                self.quote_query_string = app_ctx.get_object('quote_query_string')
                self.server_tag = uuid.uuid4().hex
                self.from_backend_ignore = []
                self.add_invocation_id = True
                self.sign_invocation_id = True
                self.default_url_config = _default_url_config()
                self.add_default_if_not_found = True

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
                
                def sendall(*ignored_args, **ignored_kwargs):
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
            
            try:
                handler.wfile = _WFile()
                check_wfile = True # Will be Trued in older gevent versions
            except AttributeError:
                handler._wfile = _WFile()
                check_wfile = False 
                
            handler.status = True
            handler.headers_sent = False
            handler.response_use_chunked = True

            handler.handle_one_response()

            if check_wfile:
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
            self.instance_name = None
            self.INSTANCE_UNIQUE = None
            self.INSTANCE_SECRET = None
            self.quote_path_info = None
            self.quote_query_string = None
            self.server_tag = uuid.uuid4().hex
            self.from_backend_ignore = []
            self.add_invocation_id = True
            self.sign_invocation_id = True
            self.default_url_config = _default_url_config()
            self.add_default_if_not_found = True
            
    config = _Config()

    request_app = server._RequestApp(config, app_ctx)
    http_proxy = server.HTTPProxy(config, app_ctx)
    https_proxy = server.HTTPSProxy(config, app_ctx)

    for o in request_app, http_proxy, https_proxy:
        assert_true((getattr(o, 'logger', None) is not None), o)
        assert_true(isinstance(getattr(o, 'logger'), logging.Logger), o)
