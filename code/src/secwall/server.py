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
import hashlib, itertools, logging, re, ssl, sys, time, traceback, urllib2, uuid
from datetime import datetime
from urllib import quote_plus

# lxml
from lxml import etree

# gevent
from gevent import pywsgi, sleep, wsgi
from gevent.hub import GreenletExit

# sec-wall
from secwall import wsse
from secwall.constants import *
from secwall.core import AuthResult, InvocationContext, SecurityException, SecWallException

class _RequestApp(object):
    """ A WSGI application executed on each request.
    """
    def __init__(self, config=None, app_ctx=None):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.config = config
        self.urls_compiled = []
        self.app_ctx = app_ctx
        self.wsse = self.app_ctx.get_object('wsse')

        self.instance_name = config.instance_name
        self.instance_unique = config.INSTANCE_UNIQUE
        self.quote_path_info = config.quote_path_info
        self.quote_query_string = config.quote_query_string

        self.msg_counter = itertools.count(1)
        self.now = datetime.now
        self.log_level = self.logger.getEffectiveLevel()

        for url_pattern, url_config in self.config.urls:
            self.urls_compiled.append((re.compile(url_pattern), url_config))

    def __call__(self, env, start_response, client_cert=None):
        """ Finds the configuration for the given URL and passes the control on
        to the main request handler. In case no config for the given URL is
        found, a 404 Not Found will be returned to the calling side.
        """
        ctx = InvocationContext(self.instance_name, self.instance_unique, self.msg_counter.next(),
                                self.now())

        path_info = env['PATH_INFO']
        if self.quote_path_info:
            path_info = quote_plus(path_info)

        query_string = env.get('QUERY_STRING')
        if query_string:
            query_string = '?' + query_string
            if self.quote_query_string:
                query_string = quote_plus(query_string)

        ctx.path_info = path_info
        ctx.query_string = query_string
        ctx.remote_address = env.get('REMOTE_ADDR')
        ctx.request_metod = env.get('REQUEST_METHOD')

        for c, url_config in self.urls_compiled:
            match = c.match(path_info)
            if match:
                return self._on_request(ctx, start_response, env, url_config, client_cert)
        else:
            # No config for that URL, we can't let the client in.
            return self._404(ctx, start_response)

    def _on_request(self, ctx, start_response, env, url_config, client_cert):
        """ Checks security, invokes the backend server, returns the response.
        """
        # Some quick SSL-related checks first.
        if url_config.get('ssl'):

            # Has the URL been accessed through SSL/TLS?
            if env.get('wsgi.url_scheme') != 'https':
                return self._403(ctx, start_response)

            # Is the client cert required?
            if url_config.get('ssl-cert') and not client_cert:
                return self._401(ctx, start_response, self._get_www_auth(url_config, 'ssl-cert'))

        data = env['wsgi.input'].read()

        ctx.env = env
        ctx.data = data

        for config_type in self.config.validation_precedence:
            if config_type in url_config:

                handler = getattr(self, '_on_' + config_type.replace('-', '_'))
                auth_result = handler(env, url_config, client_cert, data)

                ctx.auth_result = auth_result
                ctx.config_type = config_type

                if not auth_result:
                    return self._401(ctx, start_response, self._get_www_auth(url_config, config_type))
                break
        else:
            return self._500(ctx, start_response)

        req = urllib2.Request(url_config['host'] + env['PATH_INFO'], data)
        try:
            ctx.ext_start = self.now()
            resp = urllib2.urlopen(req)
        except urllib2.HTTPError, e:
            resp = e

        try:
            response = resp.read()
            resp.close()
        finally:
            ctx.ext_end = self.now()

        return self._response(ctx, start_response, str(resp.getcode()), resp.msg,
                              [('Content-Type', resp.headers['Content-Type'])],
                              response)

    def _get_www_auth(self, url_config, config_type):
        """ Returns a value of the WWW-Authenticate header to use upon a 401 error.
        """
        www_auth = {
            'ssl-cert': self.config.client_cert_401_www_auth,
            'basic-auth': 'Basic realm="{realm}"',
            'digest-auth': 'Digest realm="{realm}", nonce="{nonce}", opaque="{opaque}"',
            'wsse-pwd': 'WSSE realm="{realm}", profile="UsernameToken"',
            'custom-http': 'custom-http',
            'xpath': 'xpath'
        }
        header_value = www_auth[config_type]

        if config_type in('basic-auth', 'wsse-pwd'):
            header_value = header_value.format(realm=url_config[config_type + '-' + 'realm'])
        elif config_type == 'digest-auth':
            realm = url_config['digest-auth-realm']
            nonce = uuid.uuid4().hex
            opaque = uuid.uuid4().hex

            header_value = header_value.format(realm=realm, nonce=nonce, opaque=opaque)

        return header_value

    def _response(self, ctx, start_response, code, status, headers, response):
        """ Actually returns the response to the client.
        """
        ctx.proc_end = self.now()

        # We need details in case there was an error or we're running
        # at least on DEBUG level.
        needs_details = (ctx.auth_result == False) or (self.log_level <= logging.DEBUG)
        log_message = ctx.format_log_message(code, needs_details)

        if ctx.auth_result:
            self.logger.info(log_message)
        else:
            self.logger.error(log_message)

        start_response('{0} {1}'.format(code, status), headers)
        return [response]

    def _401(self, ctx, start_response, www_auth):
        """ 401 Not Authorized
        """
        code, status, content_type, description = self.config.not_authorized
        headers = [('Content-Type', content_type), ('WWW-Authenticate', www_auth)]

        return self._response(ctx, start_response, code, status, headers, description)

    def _403(self, ctx, start_response):
        """ 403 Forbidden
        """
        code, status, content_type, description = self.config.forbidden
        return self._response(ctx, start_response, code, status, [('Content-Type', content_type)], description)

    def _404(self, ctx, start_response):
        """ 404 Not Found
        """
        code, status, content_type, description = self.config.no_url_match
        return self._response(ctx, start_response, code, status, [('Content-Type', content_type)], description)

    def _500(self, ctx, start_response):
        """ 500 Internal Server Error
        """
        code, status, content_type, description = self.config.internal_server_error
        return self._response(ctx, start_response, code, status, [('Content-Type', content_type)], description)

    def _on_ssl_cert(self, env, url_config, client_cert, data):
        """ Validates the client SSL/TLS certificates, its very existence and
        the values of its fields (commonName, organizationName etc.)
        """
        if client_cert:
            field_prefix = 'ssl-cert-'
            config_fields = {}
            for field, value in url_config.items():
                if field.startswith(field_prefix):
                    config_fields[field.split(field_prefix)[1]] = value

            # The user just wants the connection be encrypted and the client
            # use client certificate however they're not interested in the
            # cert's fields - so as long as the CA is OK (and we know it is
            # because otherwise we wouldn't have gotten so far), we let the
            # client in.
            if not config_fields:
                ## XXX: That should be reconsidered and made consistent with
                # the rest of validation methods that would've raise an exception
                # in that case.
                return True
            else:
                subject =  client_cert.get('subject')
                if not subject:
                    return AuthResult(False, AUTH_CERT_NO_SUBJECT)

                cert_fields = dict(elem[0] for elem in subject)

                for config_field, config_value in config_fields.items():
                    cert_value = cert_fields.get(config_field)
                    if not cert_value:
                        return AuthResult(False, AUTH_CERT_NO_VALUE)
                    if cert_value != config_value:
                        return AuthResult(False, AUTH_CERT_VALUE_MISMATCH)
                else:
                    return AuthResult(True, '0')

    def _on_wsse_pwd(self, env, url_config, unused_client_cert, data):
        """ Uses WS-Security UsernameToken/Password to validate the request.
        """
        if not data:
            return AuthResult(False, AUTH_WSSE_NO_DATA)

        request = etree.fromstring(data)
        try:
            ok = self.wsse.validate(request, url_config)
        except SecurityException, e:
            return AuthResult(False, AUTH_WSSE_VALIDATION_ERROR, e.description)
        else:
            return AuthResult(True, '0')

    def _on_basic_auth(self, env, url_config, *ignored):
        """ Handles HTTP Basic Authentication.
        """
        auth = env.get('HTTP_AUTHORIZATION')
        if not auth:
            return False

        prefix = 'Basic '
        if not auth.startswith(prefix):
            return False

        _, auth = auth.split(prefix)
        auth = auth.strip().decode('base64')

        username, password = auth.split(':', 1)

        if username == url_config['basic-auth-username'] and \
           password == url_config['basic-auth-password']:
            return AuthResult(True, '0')
        else:
            return AuthResult(False, AUTH_BASIC_USERNAME_OR_PASSWORD_MISMATCH)

    def _parse_digest_auth(self, auth):
        """ Parses the client's Authorization header and transforms it into
        a dictionary.
        """
        out = {}
        auth = auth.replace('Digest ', '', 1).split(',')
        for item in auth:
            key, value = item.split('=', 1)
            key = key.strip()
            value = value[1:-1] # Strip quotation marks
            out[key] = value
        return out

    def _compute_digest_auth_response(self, expected_username, expected_realm,
                    expected_password, expected_uri, request_method, nonce):
        """ Returns the Digest Auth response as understood by RFC 2069.
        """

        # HA1
        ha1 = hashlib.md5()
        ha1.update('{0}:{1}:{2}'.format(expected_username, expected_realm, expected_password))

        # HA2
        ha2 = hashlib.md5()
        ha2.update('{0}:{1}'.format(request_method, expected_uri))

        # response
        respone = hashlib.md5()
        respone.update('{0}:{1}:{2}'.format(ha1.hexdigest(), nonce, ha2.hexdigest()))

        return respone.hexdigest()

    def _on_digest_auth(self, env, url_config, *ignored):
        """ Handles HTTP Digest Authentication.
        """
        auth = env.get('HTTP_AUTHORIZATION')
        if not auth:
            return AuthResult(False, AUTH_DIGEST_NO_AUTH)

        auth = self._parse_digest_auth(auth)

        expected_username = url_config['digest-auth-username']
        expected_password = url_config['digest-auth-password']
        expected_realm = url_config['digest-auth-realm']

        if auth['username'] != expected_username:
            return AuthResult(False, AUTH_DIGEST_USERNAME_MISMATCH)

        if auth['realm'] != expected_realm:
            return AuthResult(False, AUTH_DIGEST_REALM_MISMATCH)

        if env.get('QUERY_STRING'):
            expected_uri = '{0}?{1}'.format(env['PATH_INFO'], env['QUERY_STRING'])
        else:
            expected_uri = env['PATH_INFO']

        if auth['uri'] != expected_uri:
            return AuthResult(False, AUTH_DIGEST_URI_MISMATCH)

        expected_response = self._compute_digest_auth_response(expected_username,
                                expected_realm, expected_password, expected_uri,
                                env['REQUEST_METHOD'], auth['nonce'])

        if auth['response'] == expected_response:
            return AuthResult(True, '0')
        else:
            return AuthResult(False, AUTH_DIGEST_RESPONSE_MISMATCH)

    def _on_custom_http(self, env, url_config, *ignored):
        """ Handles the authentication based on custom HTTP headers.
        """
        prefix = 'custom-http-'
        expected_headers = [header for header in url_config if header.startswith(prefix)]

        if not expected_headers:

            # It's clearly an error. We've been requested to use custom HTTP
            # headers but none are in the config.
            raise SecWallException('No custom HTTP headers were found in the config')

        for expected_header in expected_headers:
            # This set of operations (.split, .upper, .replace) could be done once
            # when the config's read, well, it's a room for improvement.
            value = env.get('HTTP_' + expected_header.split(prefix)[1].upper().replace('-', '_'))

            if not value:
                return AuthResult(False, AUTH_DIGEST_NO_HEADER)

            if value != url_config[expected_header]:
                return AuthResult(False, AUTH_DIGEST_HEADER_MISMATCH)
        else:
            return AuthResult(True, '0')

    def _on_xpath(self, unused_env, url_config, unused_client_cert, data):
        """ Handles the authentication based on XPath expressions.
        """
        if not data:
            return AuthResult(False, AUTH_XPATH_NO_DATA)

        request = etree.fromstring(data)

        prefix = 'xpath-'
        expressions = [url_config[header] for header in url_config if header.startswith(prefix)]

        if not expressions:

            # It's clearly an error. We've been requested to use XPath yet no
            # expressions have been defined in the config.
            raise SecWallException('No XPath expressions were found in the config')

        for expr in expressions:
            if not expr(request):
                return AuthResult(False, AUTH_XPATH_EXPR_MISMATCH)
        else:
            return AuthResult(True, '0')

class _RequestHandler(pywsgi.WSGIHandler):
    """ A subclass which conveniently exposes a client SSL/TLS certificate
    to the layers above. Note that some of the lines have been given the
    '# pragma: no cover' comment, that's because they were simply copy & pasted
    from the base class and we have no tests to cover them.
    """
    def handle_one_response(self):
        self.time_start = time.time()
        self.status = None
        self.headers_sent = False

        self.result = None
        self.response_use_chunked = False
        self.response_length = 0

        try:
            try:
                cert = self.socket.getpeercert() if hasattr(self.socket, 'getpeercert') \
                     else None
                self.result = self.application(self.environ, self.start_response, cert)
                for data in self.result:
                    if data:
                        self.write(data)
                if self.status and not self.headers_sent:
                    self.write('')                               # pragma: no cover
                if self.response_use_chunked:                    # pragma: no cover
                    self.wfile.writelines('0\r\n\r\n')           # pragma: no cover
                    self.response_length += 5                    # pragma: no cover
            except GreenletExit:                                 # pragma: no cover
                raise                                            # pragma: no cover
            except Exception:                                    # pragma: no cover
                traceback.print_exc()                            # pragma: no cover
                sys.exc_clear()                                  # pragma: no cover
                try:                                             # pragma: no cover
                    args = (getattr(self, 'server', ''),         # pragma: no cover
                            getattr(self, 'requestline', ''),    # pragma: no cover
                            getattr(self, 'client_address', ''), # pragma: no cover
                            getattr(self, 'application', ''))    # pragma: no cover
                    msg = '%s: Failed to handle request:\n  request = %s from %s\n  application = %s\n\n' % args # pragma: no cover
                    sys.stderr.write(msg)                        # pragma: no cover
                except Exception:                                # pragma: no cover
                    sys.exc_clear()                              # pragma: no cover
                if not self.response_length:                     # pragma: no cover
                    self.start_response(pywsgi._INTERNAL_ERROR_STATUS, pywsgi._INTERNAL_ERROR_HEADERS) # pragma: no cover
                    self.write(pywsgi._INTERNAL_ERROR_BODY)      # pragma: no cover
        finally:                                                 # pragma: no cover
            if hasattr(self.result, 'close'):                    # pragma: no cover
                self.result.close()                              # pragma: no cover
            self.wsgi_input._discard()
            self.time_finish = time.time()
            self.log_request()

class HTTPProxy(wsgi.WSGIServer):
    """ A plain HTTP proxy.
    """
    def __init__(self, config, app_ctx):
        self.logger = logging.getLogger(self.__class__.__name__)
        wsgi_request_app = app_ctx.get_object('wsgi_request_app')

        super(HTTPProxy, self).__init__((config.host, config.port),
                wsgi_request_app(config, app_ctx), log=config.log)

class HTTPSProxy(pywsgi.WSGIServer):
    """ An SSL/TLS proxy.
    """
    def __init__(self, config, app_ctx):
        self.logger = logging.getLogger(self.__class__.__name__)
        wsgi_request_app = app_ctx.get_object('wsgi_request_app')
        wsgi_request_handler = app_ctx.get_object('wsgi_request_handler')

        super(HTTPSProxy, self).__init__((config.host, config.port),
                wsgi_request_app(config, app_ctx), log=config.log,
                handler_class=wsgi_request_handler, keyfile=config.keyfile,
                certfile=config.certfile, ca_certs=config.ca_certs,
                cert_reqs=ssl.CERT_OPTIONAL)

    def handle(self, socket, address):
        handler = self.handler_class(socket, address, self)
        handler.handle()
